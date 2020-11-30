package libp2ptls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

// ID is the protocol ID (used when negotiating with multistream)
const ID = "/tls/1.0.0"

// IDTransport is an internal interface that extends SecureTransport
// and exposes an associated Identity for the purpose of internal testing
type IDTransport interface {
	sec.SecureTransport
	Identity() *Identity

	// For testing: Override the local peer's private key
	//
	// The standard behavior expected of libp2p is for the local peer's private key,
	// which was used to derive the local peer's ID, to be used to sign the local peer's X509 certificate.
	//
	// Overriding the local X509 certificate enables testing s remote peer's ability to reject invalid certificates
	// that are presented by the local peer
	overrideLocalPeerPrivateKey(localPrivateKey *ecdsa.PrivateKey) error

	// For testing: Override the local peer's first X509 certificate
	//
	// The standard behavior expected of libp2p is for only a single certificate that is signed by the local peer's private key.
	//
	// Overriding the local X509 certificate enables testing s remote peer's ability to reject invalid certificates
	// that are presented by the local peer.
	overrideLocalX509Cert(x509Cert x509.Certificate, x509PrivateKey *ecdsa.PrivateKey) error

	// For testing: Add a second X509 certificate to the certificate chain
	//
	// The standard behavior expected of libp2p is for only a single certificate to be in the certificate chain.
	// Adding certificates to the X509 chain that are presented to a remote peer
	// enables testing a remote peer's ability to reject certificate chains with multiple certificates
	// that are presented by the local peer.
	addX509CertificateToLocalCertChain(secondX509Cert x509.Certificate, secondPrivateKey *ecdsa.PrivateKey) error
}

// StdTLSTransport secures communication sessions for a peer by using Go's standard TLS
type StdTLSTransport struct {
	identity *Identity

	localPeer peer.ID
	privKey   ci.PrivKey
}

// NewStdTLSTransport creates a standard TLS encrypted transport
func NewStdTLSTransport(key ci.PrivKey) (IDTransport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}

	identity, err := NewIdentity(key)
	if err != nil {
		return nil, err
	}

	t := &StdTLSTransport{
		localPeer: id,
		privKey:   key,
		identity:  identity,
	}

	return t, nil
}

var _ sec.SecureTransport = &StdTLSTransport{}

// SecureInbound runs the TLS handshake as a server.
func (t *StdTLSTransport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	config, keyCh := t.identity.ConfigForAny()
	cs, err := t.handshake(ctx, tls.Server(insecure, config), keyCh)
	if err != nil {
		insecure.Close()
	}
	return cs, err
}

// SecureOutbound runs the TLS handshake as a client.
// Note that SecureOutbound will not return an error if the server doesn't
// accept the certificate. This is due to the fact that in TLS 1.3, the client
// sends its certificate and the ClientFinished in the same flight, and can send
// application data immediately afterwards.
// If the handshake fails, the server will close the connection. The client will
// notice this after 1 RTT when calling Read.
func (t *StdTLSTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	config, keyCh := t.identity.ConfigForPeer(p)
	cs, err := t.handshake(ctx, tls.Client(insecure, config), keyCh)
	if err != nil {
		insecure.Close()
	}
	return cs, err
}

func (t *StdTLSTransport) handshake(
	ctx context.Context,
	tlsConn *tls.Conn,
	keyCh <-chan ci.PubKey,
) (sec.SecureConn, error) {
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		tlsConn.Close()
	default:
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Ensure that we do not return before
	// either being done or having a context
	// cancellation.
	defer wg.Wait()
	defer close(done)

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-done:
		case <-ctx.Done():
			tlsConn.Close()
		}
	}()

	if err := tlsConn.Handshake(); err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	// Should be ready by this point, don't block.
	var remotePubKey ci.PubKey
	select {
	case remotePubKey = <-keyCh:
	default:
	}
	if remotePubKey == nil {
		return nil, errors.New("go-libp2p-tls BUG: expected remote pub key to be set")
	}

	conn, err := t.setupConn(tlsConn, remotePubKey)
	if err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return conn, nil
}

func (t *StdTLSTransport) setupConn(tlsConn *tls.Conn, remotePubKey ci.PubKey) (sec.SecureConn, error) {
	remotePeerID, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}
	return &conn{
		Conn:         tlsConn,
		localPeer:    t.localPeer,
		privKey:      t.privKey,
		remotePeer:   remotePeerID,
		remotePubKey: remotePubKey,
	}, nil
}

// Identity returns the libp2p identity
func (t *StdTLSTransport) Identity() *Identity {
	return t.identity
}

// For testing validation by remote peers: Override the local peer's private key
func (t *StdTLSTransport) overrideLocalPeerPrivateKey(localPeerPrivateKey *ecdsa.PrivateKey) error {
	t.identity.config.Certificates[0].PrivateKey = localPeerPrivateKey

	return nil
}

// For testing validation by remote peers: Override the local peer's first X509 certificate
func (t *StdTLSTransport) overrideLocalX509Cert(x509Cert x509.Certificate, x509PrivateKey *ecdsa.PrivateKey) error {
	// Select the private key for the local peer's connection-certificate to the remote peer
	var certKey *ecdsa.PrivateKey
	var err error
	if x509PrivateKey != nil {
		certKey = x509PrivateKey
	} else {
		certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
	}

	// Sign the cert with the appropriate certificate key
	cert, err := signAndCreateStdTLSCert(&x509Cert, certKey)
	if err != nil {
		return err
	}

	t.Identity().config.Certificates = []tls.Certificate{*cert}

	return nil
}

// For testing validation by remote peers: Add a second X509 certificate to the certificate chain
func (t *StdTLSTransport) addX509CertificateToLocalCertChain(secondX509Cert x509.Certificate,
	secondPrivateKey *ecdsa.PrivateKey) error {

	// Check for the first certificate
	if len(t.Identity().config.Certificates) < 1 {
		return errors.New("Cannot add an X509 certificate before another certificate is already added")
	}
	if len(t.Identity().config.Certificates) > 1 {
		return errors.New("Cannot add an X509 certificate because there already are secondary certificates in the local peer's chain")
	}
	var cert1DER []byte = t.Identity().config.Certificates[0].Certificate[0]
	var cert1Key crypto.PrivateKey = t.Identity().config.Certificates[0].PrivateKey

	// Prepare the secondary certificate
	cert2DER, err := x509.CreateCertificate(rand.Reader, &secondX509Cert, &secondX509Cert, secondPrivateKey.Public(), secondPrivateKey)
	if err != nil {
		return err
	}

	var newCert tls.Certificate = tls.Certificate{
		Certificate: [][]byte{cert2DER, cert1DER},
		PrivateKey:  cert1Key,
	}

	t.Identity().config.Certificates = []tls.Certificate{newCert}

	return nil
}

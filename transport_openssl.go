// +build openssl

package libp2ptls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
	"github.com/libp2p/go-openssl"
)

// Creates an Open SSL encrypted transport
func NewOpenSSLTransport(key ci.PrivKey) (IDTransport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}

	identity, err := NewIdentity(key)
	if err != nil {
		return nil, err
	}

	t := &OpenSSLTransport{
		localPeer: id,
		privKey:   key,
		identity:  identity,
	}

	return t, nil
}

// OpenSSLTransport constructs secure communication sessions for a peer by using go-openssl.
// go-openssl uses the available Open SSL library on the operating system.
type OpenSSLTransport struct {
	identity *Identity

	localPeer peer.ID
	privKey   ci.PrivKey

	verifyCallbackError        *string
	verifyCallbackRemotePubKey *ci.PubKey

	//////
	// For debugging errors
	//////
	isTransportModeDetected bool
	isTransportModeServer   bool

	//////
	// For internal testing
	//////
	localPeerPrivateKeyOverride *ecdsa.PrivateKey

	// An override of the local peers' primary certificate in the chain that it will present to the remote peer during a TLS handshake
	primaryCertOverride *x509Tuple

	// An override of the local peer's secondary chain certificate in the chain that it will present to the remote peer during a TLS handshake
	secondaryCertOverride *x509Tuple
}

// A tuple of an unsigned certificate and a key to sign it
type x509Tuple struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// Identity returns the libp2p identity
func (t *OpenSSLTransport) Identity() *Identity {
	return t.identity
}

// For testing validation by remote peers: Override the local peer's private key
func (t *OpenSSLTransport) overrideLocalPeerPrivateKey(localPeerPrivateKey *ecdsa.PrivateKey) error {
	t.localPeerPrivateKeyOverride = localPeerPrivateKey

	return nil
}

// For testing validation by remote peers: Override the local peer's first X509 certificate
func (t *OpenSSLTransport) overrideLocalX509Cert(x509Cert x509.Certificate, x509PrivateKey *ecdsa.PrivateKey) error {
	t.primaryCertOverride = &x509Tuple{cert: &x509Cert, key: x509PrivateKey}

	return nil
}

// For testing validation by remote peers: Add a second X509 certificate to the certificate chain
func (t *OpenSSLTransport) addX509CertificateToLocalCertChain(secondX509Cert x509.Certificate, secondPrivateKey *ecdsa.PrivateKey) error {
	t.secondaryCertOverride = &x509Tuple{cert: &secondX509Cert, key: secondPrivateKey}

	return nil
}

// OpenSSL SecureInbound runs the TLS handshake as a server.
func (t *OpenSSLTransport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	if !t.isTransportModeDetected {
		// Inferring that if the first call to the IDTransport is to SecureInbound that the connection is a "server" connection
		t.isTransportModeServer = true
	}

	//////
	// Capability to detect cancellation of Go Context
	//////
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		insecure.Close()
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
			insecure.Close()
		}
	}()

	//////
	// Construct a connection context that is configured to send this peer's public key to the remote peer
	//////
	var openSSLCtx *openssl.Ctx
	var err error
	if openSSLCtx, err = t.newOpenSSLContext(""); err != nil {
		fmt.Println("An error occurred while constructing the OpenSSL context", err)
		insecure.Close()
		return nil, err
	}
	openSSLCtx.SetVerifyMode(openssl.VerifyPeer) // Essential for server: have server request a client's certificate

	//////
	// Create the connection
	// Wrap the insecure connection into an OpenSSL connection
	//////
	var openSSLConn *openssl.Conn
	if openSSLConn, err = openssl.Server(insecure, openSSLCtx); err != nil {
		fmt.Println("An error occurred while wrapping the insecure connection with OpenSSL", err)
		insecure.Close()
		return nil, err
	}

	var secureConn sec.SecureConn
	var expectedRemotePeerID peer.ID = "" // Any remote peer ID is acceptable
	if secureConn, err = t.handshake(openSSLConn, expectedRemotePeerID); err != nil {
		insecure.Close()

		// if the Go context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if t.verifyCallbackError != nil {
			return nil, errors.New(*t.verifyCallbackError)
		}
		return nil, err
	}

	return secureConn, err
}

// OpenSSL SecureOutbound
func (t *OpenSSLTransport) SecureOutbound(ctx context.Context, insecure net.Conn, expectedRemotePeerID peer.ID) (sec.SecureConn, error) {
	if !t.isTransportModeDetected {
		// Inferring that if the first call to the IDTransport is to SecureOutbound that the connection is a "client" connection
		t.isTransportModeServer = false
	}

	//////
	// Capability to detect cancellation of Go Context
	//////
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		insecure.Close()
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
			insecure.Close()
		}
	}()

	//////
	// Construct a connection context that is configured
	// - to validate the remote peer's public key
	// - to send this peer's public key to the remote peer
	//////
	var openSSLCtx *openssl.Ctx
	var err error
	if openSSLCtx, err = t.newOpenSSLContext(expectedRemotePeerID); err != nil {
		fmt.Println("An error occurred while constructing the OpenSSL context", err)
		insecure.Close()
		return nil, err
	}

	//////
	// Create the connection
	// Wrap the insecure connection into an OpenSSL connection
	//////
	var openSSLConn *openssl.Conn
	if openSSLConn, err = openssl.Client(insecure, openSSLCtx); err != nil {
		fmt.Println("An error occurred while wrapping the insecure connection with OpenSSL", err)
		insecure.Close()
		return nil, err
	}

	var secureConn sec.SecureConn
	if secureConn, err = t.handshake(openSSLConn, expectedRemotePeerID); err != nil {
		// TODO [Low]: Send a TLS alert, such as "tls: bad certificate", after go-openssl is capable

		// Hack: Close the insecure connection to trigger an error on the remote peer/listener
		if closeErr := insecure.Close(); closeErr != nil {
			// Ignore
		}

		// Handle context cancellations
		// If the Go context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err

	}
	return secureConn, err
}

// Wrap the OpenSSL connection, which already wraps a standard TLS insecure connection, with a SecureConn
func (t *OpenSSLTransport) newSecureConn(openSSLConn *openssl.Conn, remotePubKey ci.PubKey) (sec.SecureConn, error) {
	remotePeerID, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}

	return &openSSLSecureConn{
		openSSLConn:  openSSLConn,
		localPeer:    t.localPeer,
		privKey:      t.privKey,
		remotePeer:   remotePeerID,
		remotePubKey: remotePubKey,
	}, nil
}

// Create an OpenSSL context
// The context needs to be configured with
// - the local peer's signed public key embedded as an extension field of the X509 client certificate that will be sent to the remote peer during the TLS handshake
// - the local peer's private key
func (t *OpenSSLTransport) newOpenSSLContext(expectedRemotePeerID peer.ID) (*openssl.Ctx, error) {
	//////
	// Select the private key for the local peer's connection-certificate to the remote peer
	//////
	// Select the private key for the certificate
	var certKey *ecdsa.PrivateKey
	var err error
	if t.primaryCertOverride == nil || t.primaryCertOverride.key == nil {
		certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	} else {
		certKey = t.primaryCertOverride.key
	}

	//////
	// Determine which X509 certificate to use for the local peer
	//////
	var x509Template *x509.Certificate
	if t.primaryCertOverride == nil || t.primaryCertOverride.cert == nil {
		// Create the unsigned X509 certificate template
		if x509Template, err = newUnsignedX509Cert(t.privKey, certKey); err != nil {
			return nil, err
		}
	} else {
		x509Template = t.primaryCertOverride.cert
	}

	//////
	// Sign the X509 certificate template
	//////
	derBytes, err := x509.CreateCertificate(rand.Reader, x509Template, x509Template, certKey.Public(), certKey)
	if err != nil {
		return nil, err
	}

	//////
	// Create the X509 certificate object
	//////
	var localX509Cert *x509.Certificate
	localX509Cert, err = x509.ParseCertificate(derBytes)

	if err != nil {
		fmt.Println("Could not parse the local/client certificate", err)
		return nil, err
	}

	//////
	// Package the X509 certificate into an OpenSSL Context
	//////
	return t.newOpenSSLContextWithSignedX509(expectedRemotePeerID, certKey, localX509Cert)
}

// Create an OpenSSL context with the provided X509 certificate
// The context needs to be configured with
// - the local peer's signed public key embedded as an extension field of the X509 local certificate that will be sent to the remote peer during the TLS handshake
// - the local peer's private key for this connection to the remote peer
//
// The required inputs to create an libp2p transport context are
// - the remote peer's expected ID
// - the local peer's private key for the connection to the remote peer
// - the local peer's public X509 certificate containing the local peer's public key corresponding to the private key
func (t *OpenSSLTransport) newOpenSSLContextWithSignedX509(expectedRemotePeerID peer.ID, certKey *ecdsa.PrivateKey, localX509Cert *x509.Certificate) (*openssl.Ctx, error) {
	//////
	// Create an OpenSSL context
	//////
	var openSSLCtx *openssl.Ctx
	var err error
	// TODO [Medium]: Test for a potential TLS protocol downgrade attack by a remote peer to below TLS v.1.3
	if openSSLCtx, err = openssl.NewCtx(); err != nil {
		return nil, err
	}

	//////
	// Configure the OpenSSL Context with this peer's private key for this connection to the remote peer
	// IMPORTANT Essential for client
	//////
	var privateKey *ecdsa.PrivateKey
	if t.localPeerPrivateKeyOverride != nil {
		privateKey = t.localPeerPrivateKeyOverride
	} else {
		privateKey = certKey
	}
	var privateKeyBytes []byte
	if privateKeyBytes, err = x509.MarshalECPrivateKey(privateKey); err != nil {
		fmt.Println("Error with marshalling private key")
		return nil, err
	}
	opensslPrivateKey, err := openssl.LoadPrivateKeyFromDER(privateKeyBytes)
	if err != nil {
		fmt.Println("Error while setting loading private ket from DER", err)
		return nil, err
	}
	err = openSSLCtx.UsePrivateKey(opensslPrivateKey)
	if err != nil {
		fmt.Println("Error while setting OpenSSL Context Private Key")
		return nil, err
	}

	//////
	// Configure the OpenSSL Context's local certificate by adapting the X509 certificate
	//////
	if err = configureContextWithSignedX509(openSSLCtx, localX509Cert); err != nil {
		fmt.Println("Error while configuring context with X509", err)
		return nil, err
	}

	//////
	// Configure the OpenSSL Context's secondary certificate on the certificate chain
	//////
	if err = t.configureContextWithSecondaryCertificate(openSSLCtx, localX509Cert); err != nil {
		fmt.Println("Error while configuring the secondary certificate", err)
		return nil, err
	}

	//////
	// Configure the connection to receive and authenticate the remote peer's public key
	//////
	t.configureCertVerificationCallback(openSSLCtx, expectedRemotePeerID)

	// TODO [Low]: Look for any libp2p requirements about setting the next protocol
	//err = openSSLCtx.SetNextProtos([]string{"libp2p"})
	//if err != nil {
	//	return nil, err
	//}

	return openSSLCtx, nil
}

// Configure an OpenSSL Context's client certificate by adapting the signed X509 certificate
func configureContextWithSignedX509(openSSLCtx *openssl.Ctx, signedLocalX509Cert *x509.Certificate) error {
	//////
	// Configure the OpenSSL Context's client certificate by adapting the X509 certificate
	//////
	// var localStdCert tls.Certificate = tlsConfig.Certificates[0]
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: signedLocalX509Cert.Raw})
	var signedLocalCertPemString string = buf.String()

	// Mimic libp2p-tls/crypto.go/NewIdentity()
	var localPeerCert *openssl.Certificate
	var err error
	localPeerCert, err = openssl.LoadCertificateFromPEM([]byte(signedLocalCertPemString))
	err = openSSLCtx.UseCertificate(localPeerCert)
	if err != nil {
		fmt.Println("OpenSSL Outbound: Error with setting outbound certificate")
		return err
	}
	return nil
}

// Configure the context with a secondary certificate on the certificate chain.
// This is only expected to be used for internal testing.
// Any remote peer is expected to reject a certificate chain with more than a single certificate.
func (t *OpenSSLTransport) configureContextWithSecondaryCertificate(openSSLCtx *openssl.Ctx, signedPrimaryX509Cert *x509.Certificate) error {
	if t.secondaryCertOverride == nil {
		return nil
	}

	var cert2DER []byte
	var err error
	if cert2DER, err = x509.CreateCertificate(rand.Reader, t.secondaryCertOverride.cert, signedPrimaryX509Cert, t.secondaryCertOverride.key.Public(), t.secondaryCertOverride.key); err != nil {
		fmt.Println("Error with creating the secondary certificate for the local peer")
		return err
	}

	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert2DER})
	var signedLocalCertPemString string = buf.String()

	var localPeerCert *openssl.Certificate
	localPeerCert, err = openssl.LoadCertificateFromPEM([]byte(signedLocalCertPemString))
	if err = openSSLCtx.AddChainCertificate(localPeerCert); err != nil {
		fmt.Println("OpenSSL Outbound: Error with setting the outbound certificate's secondary certicate")
		return err
	}

	return nil

}

// Create a channel that will receive the remote peer's Public Key during the TLS handshake
// The remote peer's public key only needs to parsed once
// If a remote peer ID is expected, as is the case for libp2p clients that are connecting to previously identified libp2p remote peer by some other communications channel, the remote peer's public key will be evaluated.
func (t *OpenSSLTransport) configureCertVerificationCallback(openSSLCtx *openssl.Ctx, expectedRemotePeerID peer.ID) {
	//////
	// We need to check the peer ID in the VerifyPeerCertificate callback.
	//////
	// Use the openssl VerifyCallback to capture the remote peer's public key
	// This implementation is similar to Identity.ConfigForPeer()
	// except this implementation does not use a channel to convey the remote peer's public key.
	// Instead, the verifyCallbackRemotePubKey will be set if the remote peer's public key matches the expectation.
	// Not using a channel results in higher performance based on benchmark performance testing.
	var verifyCallback openssl.VerifyCallback = func(preVerified bool, store *openssl.CertificateStoreCtx) bool {
		// The first call is always false.  The second call is same result as the output/return of the first call.
		if preVerified {
			// If "pre-verified", do not verify again
			return true
		}

		var cert *openssl.Certificate = store.GetCurrentCert()

		// Use Certificate's extension value from re-derivation of the certificate from its PEM
		var remotePubKey ci.PubKey
		bytes, err := (*cert).MarshalPEM()
		if err != nil {
			fmt.Println("Remote PEM error", t.isTransportModeServer, err)
			return false

		} else {
			var block *pem.Block
			block, bytes = pem.Decode(bytes)

			var cert *x509.Certificate
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("Error re-creating certificate object", err)
				return false

			} else {
				if remotePubKey, err = PubKeyFromCertificate(cert); err != nil {
					var errorMessage string = fmt.Sprintln(err)
					t.verifyCallbackError = &errorMessage
					return false
				}
			}
		}

		// TODO [Optimization]: Possibly use the Certificate's extension value directly from the certificate's certificate
		// bytes = (*cert).GetExtensionValue(nid)

		if expectedRemotePeerID != "" && !expectedRemotePeerID.MatchesPublicKey(remotePubKey) {
			// Essential for client
			remotePeerID, err := peer.IDFromPublicKey(remotePubKey)
			if err != nil {
				remotePeerID = peer.ID(fmt.Sprintf("(not determined: %s)", err.Error()))
			}
			fmt.Errorf("peer IDs don't match: expected %s, got %s", expectedRemotePeerID, remotePeerID)
			var errorMsg string = "peer IDs don't match!"
			t.verifyCallbackError = &errorMsg
			return false
		}

		t.verifyCallbackRemotePubKey = &remotePubKey

		// Returning "true" in the client is necessary for the server to successfully handshake,
		// but it is causing the client to VerifyCallback twice.
		// Given that the handshake fails if the server is configured for VerifyClientOnce rather than VerifyPeer,
		// it suggests (needs confirmation) that two requests are being sent.
		// TODO [Optimization]: Determine whether two verification requests are going over the wire

		// OpenSSL should continue with the TLS/SSL handshake
		// per http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
		return true
	}

	openSSLCtx.SetVerifyCallback(verifyCallback)
	openSSLCtx.SetVerifyDepth(1) // Only verify the first certificate in the chain because only the first should be used by libp2p
}

func (t *OpenSSLTransport) handshake(openSSLConn *openssl.Conn, expectedRemotePeerID peer.ID) (sec.SecureConn, error) {
	// Handshake
	var err error
	if err = openSSLConn.Handshake(); err != nil {
		openSSLConn.Close()
		return nil, err
	}

	if t.verifyCallbackError != nil {
		return nil, errors.New(*t.verifyCallbackError)
	}

	// Should be ready by this point, don't block.
	var remotePubKey ci.PubKey

	if t.verifyCallbackRemotePubKey == nil {
		// TODO [Low]: Send a TLS alert, such as "tls: bad certificate", after go-openssl is capable
		if t.verifyCallbackError != nil {
			return nil, errors.New(*t.verifyCallbackError)
		} else {
			// The implication is that the verification callback was not called
			return nil, errors.New("verification failure")
		}
	}
	remotePubKey = *t.verifyCallbackRemotePubKey

	// Wrap the OpenSSL connection into an libp2p SecureConn
	var secureConn sec.SecureConn
	if secureConn, err = t.newSecureConn(openSSLConn, remotePubKey); err != nil {
		return nil, err
	}

	return secureConn, nil
}

// Implements sec.SecureConn by implementing the method of net.Conn and network.ConnSecurity
type openSSLSecureConn struct {
	openSSLConn *openssl.Conn

	localPeer    peer.ID
	privKey      ci.PrivKey
	remotePeer   peer.ID
	remotePubKey ci.PubKey
}

// network.ConnSecurity method
func (c *openSSLSecureConn) LocalPeer() peer.ID {
	return c.localPeer
}

// network.ConnSecurity method
func (c *openSSLSecureConn) LocalPrivateKey() ci.PrivKey {
	return c.privKey
}

// network.ConnSecurity method
func (c *openSSLSecureConn) RemotePeer() peer.ID {
	return c.remotePeer
}

// network.ConnSecurity method
func (c *openSSLSecureConn) RemotePublicKey() ci.PubKey {
	return c.remotePubKey
}

// net.Conn method
func (c *openSSLSecureConn) Close() error {
	return c.openSSLConn.Close()
}

// net.Conn method
func (c *openSSLSecureConn) LocalAddr() net.Addr {
	return c.openSSLConn.LocalAddr()
}

// net.Conn method
func (c *openSSLSecureConn) RemoteAddr() net.Addr {
	return c.openSSLConn.RemoteAddr()
}

// net.Conn method
func (c *openSSLSecureConn) SetDeadline(t time.Time) error {
	return c.openSSLConn.SetDeadline(t)
}

// net.Conn method
func (c *openSSLSecureConn) SetReadDeadline(t time.Time) error {
	return c.openSSLConn.SetReadDeadline(t)
}

// net.Conn method
func (c *openSSLSecureConn) SetWriteDeadline(t time.Time) error {
	return c.openSSLConn.SetWriteDeadline(t)
}

// net.Conn method
func (c *openSSLSecureConn) Read(b []byte) (n int, err error) {
	return c.openSSLConn.Read(b)
}

// net.Conn method
func (c *openSSLSecureConn) Write(b []byte) (n int, err error) {
	return c.openSSLConn.Write(b)
}

// PubKeyFromCertificate verifies a **single** certificate and extracts the remote peer's public key.
// Code adapted from crypto.go
// The usage of this single-certificate version is slightly more performant
func PubKeyFromCertificate(cert *x509.Certificate) (ci.PubKey, error) {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		// If we return an x509 error here, it will be sent on the wire.
		// Wrap the error to avoid that.
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}

	var found bool
	var keyExt pkix.Extension
	// find the libp2p key extension, skipping all unknown extensions
	for _, ext := range cert.Extensions {
		if extensionIDEqual(ext.Id, extensionID) {
			keyExt = ext
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("expected certificate to contain the key extension")
	}
	var sk signedKey
	if _, err := asn1.Unmarshal(keyExt.Value, &sk); err != nil {
		return nil, fmt.Errorf("unmarshalling signed certificate failed: %s", err)
	}
	pubKey, err := ci.UnmarshalPublicKey(sk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public key failed: %s", err)
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	valid, err := pubKey.Verify(append([]byte(certificatePrefix), certKeyPub...), sk.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %s", err)
	}
	if !valid {
		return nil, errors.New("signature invalid")
	}
	return pubKey, nil
}

package libp2ptls

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	ic "github.com/libp2p/go-libp2p-crypto"
	pb "github.com/libp2p/go-libp2p-crypto/pb"
	peer "github.com/libp2p/go-libp2p-peer"
)

const certValidityPeriod = 180 * 24 * time.Hour

// Identity is used to secure connections
type Identity struct {
	*tls.Config
}

// NewIdentity creates a new identity
func NewIdentity(
	privKey ic.PrivKey,
	verifiedPeerCallback func(net.Conn, ic.PubKey),
) (*Identity, error) {
	key, cert, err := keyToCertificate(privKey)
	if err != nil {
		return nil, err
	}
	conf := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // This is not insecure here. We will verify the cert chain ourselves.
		ClientAuth:         tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}},
	}
	// When receiving the ClientHello, create a new tls.Config.
	// This new config has a VerifyPeerCertificate set, which calls the verifiedPeerCallback
	// when we derived the remote's public key from its certificate chain.
	conf.GetConfigForClient = func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
		c := conf.Clone()
		c.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			chain := make([]*x509.Certificate, len(rawCerts))
			for i := 0; i < len(rawCerts); i++ {
				cert, err := x509.ParseCertificate(rawCerts[i])
				if err != nil {
					return err
				}
				chain[i] = cert
			}
			pubKey, err := getRemotePubKey(chain)
			if err != nil {
				return err
			}
			verifiedPeerCallback(ch.Conn, pubKey)
			return nil
		}
		return c, nil
	}
	return &Identity{conf}, nil
}

// ConfigForPeer creates a new tls.Config that verifies the peers certificate chain.
// It should be used to create a new tls.Config before dialing.
func (i *Identity) ConfigForPeer(remote peer.ID) *tls.Config {
	// We need to check the peer ID in the VerifyPeerCertificate callback.
	// The tls.Config it is also used for listening, and we might also have concurrent dials.
	// Clone it so we can check for the specific peer ID we're dialing here.
	conf := i.Config.Clone()
	// We're using InsecureSkipVerify, so the verifiedChains parameter will always be empty.
	// We need to parse the certificates ourselves from the raw certs.
	conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		chain := make([]*x509.Certificate, len(rawCerts))
		for i := 0; i < len(rawCerts); i++ {
			cert, err := x509.ParseCertificate(rawCerts[i])
			if err != nil {
				return err
			}
			chain[i] = cert
		}
		pubKey, err := getRemotePubKey(chain)
		if err != nil {
			return err
		}
		if !remote.MatchesPublicKey(pubKey) {
			return errors.New("peer IDs don't match")
		}
		return nil
	}
	return conf
}

// KeyFromChain takes a chain of x509.Certificates and returns the peer's public key.
func KeyFromChain(chain []*x509.Certificate) (ic.PubKey, error) {
	return getRemotePubKey(chain)
}

// getRemotePubKey derives the remote's public key from the certificate chain.
func getRemotePubKey(chain []*x509.Certificate) (ic.PubKey, error) {
	if len(chain) != 1 {
		return nil, errors.New("expected one certificates in the chain")
	}
	pool := x509.NewCertPool()
	pool.AddCert(chain[0])
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		// If we return an x509 error here, it will be sent on the wire.
		// Wrap the error to avoid that.
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}
	remotePubKey, err := x509.MarshalPKIXPublicKey(chain[0].PublicKey)
	if err != nil {
		return nil, err
	}
	switch chain[0].PublicKeyAlgorithm {
	case x509.RSA:
		return ic.UnmarshalRsaPublicKey(remotePubKey)
	case x509.ECDSA:
		return ic.UnmarshalECDSAPublicKey(remotePubKey)
	default:
		return nil, fmt.Errorf("unexpected public key algorithm: %d", chain[0].PublicKeyAlgorithm)
	}
}

func keyToCertificate(sk ic.PrivKey) (crypto.PrivateKey, *x509.Certificate, error) {
	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(certValidityPeriod),
	}

	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	raw, err := sk.Raw()
	if err != nil {
		return nil, nil, err
	}
	switch sk.Type() {
	case pb.KeyType_RSA:
		k, err := x509.ParsePKCS1PrivateKey(raw)
		if err != nil {
			return nil, nil, err
		}
		publicKey = &k.PublicKey
		privateKey = k
	case pb.KeyType_ECDSA:
		k, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			return nil, nil, err
		}
		publicKey = &k.PublicKey
		privateKey = k
	// TODO: add support for Ed25519
	default:
		return nil, nil, errors.New("unsupported key type for TLS")
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, cert, nil
}

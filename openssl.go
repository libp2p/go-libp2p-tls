// +build openssl

package libp2ptls

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-openssl"
)

// libp2pNID is the NID for the libp2p-tls oid.
var libp2pNID openssl.NID = openssl.CreateObjectIdentifier(getExtensionString(extensionID),
	"libp2p-tls",
	"Object Identifier for libp2p-tls")

// openSSLIdentity is used to
type openSSLIdentity struct {
	certificate *openssl.Certificate
	privateKey  openssl.PrivateKey
}

// newOpenSSLIdentity create openSSLIdentity.
func newOpenSSLIdentity(sk ic.PrivKey) (*openSSLIdentity, error) {
	cert, privKey, err := createOpenSSLCertificate(sk)
	if err != nil {
		return nil, err
	}
	return &openSSLIdentity{
		certificate: cert,
		privateKey:  privKey,
	}, nil
}

// CreateServerConn creates server connection to do the tls handshake.
func (o *openSSLIdentity) CreateServerConn(insecure net.Conn) (handshakeConn,
	<-chan ic.PubKey, error) {
	opensslCtx, keyCh, err := o.createOpenSSLCtx("")
	if err := opensslCtx.UsePrivateKey(o.privateKey); err != nil {
		return nil, nil, err
	}
	conn, err := openssl.Server(insecure, opensslCtx)
	if err != nil {
		return nil, nil, err
	}
	return conn, keyCh, nil
}

// CreateClientConn creates client connection to do the tls handshake.
func (o *openSSLIdentity) CreateClientConn(insecure net.Conn, remote peer.ID) (handshakeConn,
	<-chan ic.PubKey, error) {
	opensslCtx, keyCh, err := o.createOpenSSLCtx(remote)

	conn, err := openssl.Client(insecure, opensslCtx)
	if err != nil {
		return nil, nil, err
	}
	return conn, keyCh, nil
}

func (o *openSSLIdentity) createOpenSSLCtx(remote peer.ID) (*openssl.Ctx,
	<-chan ic.PubKey, error) {
	keyCh := make(chan ic.PubKey, 4)
	opensslCtx, err := openssl.NewCtx()
	if err != nil {
		return nil, nil, err
	}

	// Set minimum version to TLS 1.3
	if !opensslCtx.SetMinProtoVersion(openssl.TLS1_3_VERSION) {
		return nil, nil, errors.New("OpenSSL doesn't support TLS 1.3")
	}

	// Add the certificate.
	if err := opensslCtx.UseCertificate(o.certificate); err != nil {
		return nil, nil, err
	}

	// Enable two way tls.
	opensslCtx.SetVerifyMode(openssl.VerifyPeer | openssl.VerifyFailIfNoPeerCert)

	opensslCtx.SetVerifyCallback(func(preverify_ok bool,
		store *openssl.CertificateStoreCtx) bool {
		if !preverify_ok {
			return false // verifying the cert chain failed on this certificate
		}
		cert := store.GetCurrentCert()
		if cert == nil {
			fmt.Println("error: nil certificate in verify callback")
			return false
		}
		pubKey, err := pubKeyFromOpenSSLCertificate(cert)
		if err != nil {
			return false
		}
		err = validateRemote(pubKey, remote)
		if err != nil {
			return false
		}
		keyCh <- pubKey
		return true
	})

	if err = opensslCtx.SetNextProtos([]string{alpn}); err != nil {
		return nil, nil, err
	}

	if err := opensslCtx.UsePrivateKey(o.privateKey); err != nil {
		return nil, nil, err
	}
	return opensslCtx, keyCh, nil
}

// pubKeyFromOpenSSLCertificate extracts the public key from the custom extension.
func pubKeyFromOpenSSLCertificate(cert *openssl.Certificate) (ic.PubKey, error) {
	extValue := cert.GetExtensionValue(libp2pNID)
	if len(extValue) == 0 {
		return nil, errors.New("unable to find extension value")
	}

	pubKey, err := cert.PublicKey()
	if err != nil {
		return nil, err
	}
	certKeyPub, err := pubKey.MarshalPKIXPublicKeyDER()
	if err != nil {
		return nil, err
	}
	return unmarshalExtensionPublicKey(extValue, certKeyPub)
}

// createOpenSSLCertificate creates openssl certificate and returns the certificate and it's
// private key.
func createOpenSSLCertificate(sk ic.PrivKey) (*openssl.Certificate, openssl.PrivateKey, error) {
	config, err := newCertificateConfig(sk)
	if err != nil {
		return nil, nil, err
	}
	info := &openssl.CertificateInfo{
		Issued:       time.Since(time.Time{}),
		Expires:      time.Since(time.Now().Add(certValidityPeriod)),
		Serial:       config.serialNumber,
		Country:      "US",
		CommonName:   "libp2p",
		Organization: "libp2p",
	}

	// Create the public key in pem format.
	encodedPublicKey, err := x509.MarshalPKIXPublicKey(config.certKey.Public())
	if err != nil {
		return nil, nil, err
	}

	pemPublicKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedPublicKey})
	pubKey, err := openssl.LoadPublicKeyFromPEM(pemPublicKey)
	if err != nil {
		return nil, nil, err
	}

	// Create a certificate with the given public key,
	certificate, err := openssl.NewCertificate(info, pubKey)
	if err != nil {
		return nil, nil, err
	}

	// Add the custom extension.
	config.extensionValue = append(config.extensionValue, 0)
	fmt.Println(len(config.extensionValue))
	err = certificate.AddCustomExtension(openssl.NID(libp2pNID), config.extensionValue)
	if err != nil {
		return nil, nil, err
	}
	encodedPrivateKey, err := x509.MarshalPKCS8PrivateKey(config.certKey)
	if err != nil {
		return nil, nil, err
	}
	pemPrivateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivateKey})
	privKey, err := openssl.LoadPrivateKeyFromPEM(pemPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// Self sign the certificate.
	if err = certificate.Sign(privKey, openssl.EVP_SHA512); err != nil {
		return nil, nil, err
	}
	return certificate, privKey, nil
}

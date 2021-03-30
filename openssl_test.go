// +build openssl

package libp2ptls

import (
	/*	"context"
		"crypto"
		"crypto/ecdsa"
		"crypto/elliptic"
		"crypto/rand"
		"crypto/rsa"
		"crypto/tls"
		"crypto/x509"
		"crypto/x509/pkix"
		"encoding/asn1"
		"fmt"
		"math/big"
		"time" */
	"net"

	//"github.com/onsi/gomega/gbytes"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	/*	. "github.com/onsi/ginkgo"
		. "github.com/onsi/gomega" */)

func InvalidCertificateTests(serverKey *ci.PrivKey, clientKey *ci.PrivKey,
	serverID *peer.ID, clientID *peer.ID, connect func() (net.Conn, net.Conn)) {
	return // skip tests for now
	// TODO reimplement test cases
	/*invalidateCertChain := func(identity *Identity) {
		switch identity.config.Certificates[0].PrivateKey.(type) {
		case *rsa.PrivateKey:
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).ToNot(HaveOccurred())
			identity.config.Certificates[0].PrivateKey = key
		case *ecdsa.PrivateKey:
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).ToNot(HaveOccurred())
			identity.config.Certificates[0].PrivateKey = key
		default:
			Fail("unexpected private key type")
		}
	}

	twoCerts := func(identity *Identity) {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
		key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		cert1DER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key1.Public(), key1)
		Expect(err).ToNot(HaveOccurred())
		cert1, err := x509.ParseCertificate(cert1DER)
		Expect(err).ToNot(HaveOccurred())
		cert2DER, err := x509.CreateCertificate(rand.Reader, tmpl, cert1, key2.Public(), key2)
		Expect(err).ToNot(HaveOccurred())
		identity.config.Certificates = []tls.Certificate{{
			Certificate: [][]byte{cert2DER, cert1DER},
			PrivateKey:  key2,
		}}
	}

	getCertWithKey := func(key crypto.Signer, tmpl *x509.Certificate) tls.Certificate {
		cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		Expect(err).ToNot(HaveOccurred())
		return tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  key,
		}
	}

	getCert := func(tmpl *x509.Certificate) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		return getCertWithKey(key, tmpl)
	}

	expiredCert := func(identity *Identity) {
		cert := getCert(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(-time.Minute),
		})
		identity.config.Certificates = []tls.Certificate{cert}
	}

	noKeyExtension := func(identity *Identity) {
		cert := getCert(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		})
		identity.config.Certificates = []tls.Certificate{cert}
	}

	unparseableKeyExtension := func(identity *Identity) {
		cert := getCert(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{
				{Id: extensionID, Value: []byte("foobar")},
			},
		})
		identity.config.Certificates = []tls.Certificate{cert}
	}

	unparseableKey := func(identity *Identity) {
		data, err := asn1.Marshal(signedKey{PubKey: []byte("foobar")})
		Expect(err).ToNot(HaveOccurred())
		cert := getCert(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{
				{Id: extensionID, Value: data},
			},
		})
		identity.config.Certificates = []tls.Certificate{cert}
	}

	tooShortSignature := func(identity *Identity) {
		key, _, err := ci.GenerateSecp256k1Key(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		keyBytes, err := key.GetPublic().Bytes()
		Expect(err).ToNot(HaveOccurred())
		data, err := asn1.Marshal(signedKey{
			PubKey:    keyBytes,
			Signature: []byte("foobar"),
		})
		Expect(err).ToNot(HaveOccurred())
		cert := getCert(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{
				{Id: extensionID, Value: data},
			},
		})
		identity.config.Certificates = []tls.Certificate{cert}
	}

	invalidSignature := func(identity *Identity) {
		key, _, err := ci.GenerateSecp256k1Key(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		keyBytes, err := key.GetPublic().Bytes()
		Expect(err).ToNot(HaveOccurred())
		signature, err := key.Sign([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		data, err := asn1.Marshal(signedKey{
			PubKey:    keyBytes,
			Signature: signature,
		})
		Expect(err).ToNot(HaveOccurred())
		cert := getCert(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{
				{Id: extensionID, Value: data},
			},
		})
		identity.config.Certificates = []tls.Certificate{cert}
	}
	// +build
	transforms := []transform{
		{
			name:  "private key used in the TLS handshake doesn't match the public key in the cert",
			apply: invalidateCertChain,
			remoteErr: Or(
				Equal("tls: invalid signature by the client certificate: ECDSA verification failure"),
				Equal("tls: invalid signature by the server certificate: ECDSA verification failure"),
			),
		},
		{
			name:      "certificate chain contains 2 certs",
			apply:     twoCerts,
			remoteErr: Equal("expected one certificates in the chain"),
		},
		{
			name:      "cert is expired",
			apply:     expiredCert,
			remoteErr: ContainSubstring("certificate has expired or is not yet valid"),
		},
		{
			name:      "cert doesn't have the key extension",
			apply:     noKeyExtension,
			remoteErr: Equal("expected certificate to contain the key extension"),
		},
		{
			name:      "key extension not parseable",
			apply:     unparseableKeyExtension,
			remoteErr: ContainSubstring("asn1"),
		},
		{
			name:      "key protobuf not parseable",
			apply:     unparseableKey,
			remoteErr: ContainSubstring("unmarshalling public key failed: proto:"),
		},
		{
			name:      "signature is malformed",
			apply:     tooShortSignature,
			remoteErr: ContainSubstring("signature verification failed:"),
		},
		{
			name:      "signature is invalid",
			apply:     invalidSignature,
			remoteErr: Equal("signature invalid"),
		},
	}

	for i := range transforms {
		t := transforms[i]

		It(fmt.Sprintf("fails if the client presents an invalid cert: %s", t.name), func() {
			serverTransport, err := New(serverKey)
			Expect(err).ToNot(HaveOccurred())
			i, err := NewIdentity(clientKey)
			Expect(err).ToNot(HaveOccurred())
			clientTransport := &Transport{
				identity: i,
			}
			Expect(err).ToNot(HaveOccurred())
			t.apply(i)

			clientInsecureConn, serverInsecureConn := connect()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(t.remoteErr)
				close(done)
			}()

			conn, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
			Expect(err).ToNot(HaveOccurred())
			_, err = gbytes.TimeoutReader(conn, time.Second).Read([]byte{0})
			Expect(err).To(Or(
				// if the certificate's public key doesn't match the private key used for signing
				MatchError("remote error: tls: error decrypting message"),
				// all other errors
				MatchError("remote error: tls: bad certificate"),
			))
			Eventually(done).Should(BeClosed())
		})

		It(fmt.Sprintf("fails if the server presents an invalid cert: %s", t.name), func() {
			i, err := NewIdentity(serverKey)
			Expect(err).ToNot(HaveOccurred())
			serverTransport := &Transport{
				identity: i,
			}
			Expect(err).ToNot(HaveOccurred())
			t.apply(i)
			clientTransport, err := New(clientKey)
			Expect(err).ToNot(HaveOccurred())

			clientInsecureConn, serverInsecureConn := connect()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("remote error: tls:"))
				close(done)
			}()

			_, err = clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(t.remoteErr)
			Eventually(done).Should(BeClosed())
		})
	} */
}

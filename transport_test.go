package libp2ptls

import (
	"context"
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
	mrand "math/rand"
	"net"
	"reflect"
	"time"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/types"
)

type transform struct {
	name      string
	apply     func(*Identity)
	remoteErr types.GomegaMatcher // the error that the side validating the chain gets
}

var _ = Describe("Transport", func() {
	var (
		serverKey, clientKey ci.PrivKey
		serverID, clientID   peer.ID
	)

	createPeer := func() (peer.ID, ci.PrivKey) {
		var priv ci.PrivKey
		var err error
		switch mrand.Int() % 4 {
		case 0:
			fmt.Fprintf(GinkgoWriter, " using an ECDSA key: ")
			priv, _, err = ci.GenerateECDSAKeyPair(rand.Reader)
		case 1:
			fmt.Fprintf(GinkgoWriter, " using an RSA key: ")
			priv, _, err = ci.GenerateRSAKeyPair(2048, rand.Reader)
		case 2:
			fmt.Fprintf(GinkgoWriter, " using an Ed25519 key: ")
			priv, _, err = ci.GenerateEd25519Key(rand.Reader)
		case 3:
			fmt.Fprintf(GinkgoWriter, " using an secp256k1 key: ")
			priv, _, err = ci.GenerateSecp256k1Key(rand.Reader)
		}
		Expect(err).ToNot(HaveOccurred())
		id, err := peer.IDFromPrivateKey(priv)
		Expect(err).ToNot(HaveOccurred())
		fmt.Fprintln(GinkgoWriter, id.Pretty())
		return id, priv
	}

	connect := func() (net.Conn, net.Conn) {
		ln, err := net.Listen("tcp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		serverConnChan := make(chan net.Conn)
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept()
			Expect(err).ToNot(HaveOccurred())
			serverConnChan <- conn
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		Expect(err).ToNot(HaveOccurred())
		return conn, <-serverConnChan
	}

	BeforeEach(func() {
		fmt.Fprintf(GinkgoWriter, "Initializing a server")
		serverID, serverKey = createPeer()
		fmt.Fprintf(GinkgoWriter, "Initializing a client")
		clientID, clientKey = createPeer()
	})

	Context("successful handshakes", func() {
		for _, critical := range []bool{true, false} {
			crit := critical

			It(fmt.Sprintf("handshakes, extension critical: %t", crit), func() {
				extensionCritical = crit
				defer func() { extensionCritical = false }()
				clientTransport, err := New(clientKey)
				Expect(err).ToNot(HaveOccurred())
				serverTransport, err := New(serverKey)
				Expect(err).ToNot(HaveOccurred())

				clientInsecureConn, serverInsecureConn := connect()

				serverConnChan := make(chan sec.SecureConn)
				go func() {
					defer GinkgoRecover()
					serverConn, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn, "")
					Expect(err).ToNot(HaveOccurred())
					serverConnChan <- serverConn
				}()
				clientConn, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
				Expect(err).ToNot(HaveOccurred())
				var serverConn sec.SecureConn
				Eventually(serverConnChan).Should(Receive(&serverConn))
				defer clientConn.Close()
				defer serverConn.Close()
				Expect(clientConn.LocalPeer()).To(Equal(clientID))
				Expect(serverConn.LocalPeer()).To(Equal(serverID))
				Expect(clientConn.LocalPrivateKey()).To(Equal(clientKey))
				Expect(serverConn.LocalPrivateKey()).To(Equal(serverKey))
				Expect(clientConn.RemotePeer()).To(Equal(serverID))
				Expect(serverConn.RemotePeer()).To(Equal(clientID))
				Expect(ci.KeyEqual(clientConn.RemotePublicKey(), serverKey.GetPublic())).To(BeTrue())
				Expect(ci.KeyEqual(serverConn.RemotePublicKey(), clientKey.GetPublic())).To(BeTrue())
				// exchange some data
				_, err = serverConn.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				b := make([]byte, 6)
				_, err = clientConn.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(b)).To(Equal("foobar"))
			})
		}
	})

	It("fails when the context of the outgoing connection is canceled", func() {
		clientTransport, err := New(clientKey)
		Expect(err).ToNot(HaveOccurred())
		serverTransport, err := New(serverKey)
		Expect(err).ToNot(HaveOccurred())

		clientInsecureConn, serverInsecureConn := connect()

		go func() {
			defer GinkgoRecover()
			_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn, "")
			Expect(err).To(HaveOccurred())
		}()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = clientTransport.SecureOutbound(ctx, clientInsecureConn, serverID)
		Expect(err).To(MatchError(context.Canceled))
	})

	It("fails when the context of the incoming connection is canceled", func() {
		clientTransport, err := New(clientKey)
		Expect(err).ToNot(HaveOccurred())
		serverTransport, err := New(serverKey)
		Expect(err).ToNot(HaveOccurred())

		clientInsecureConn, serverInsecureConn := connect()

		go func() {
			defer GinkgoRecover()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := serverTransport.SecureInbound(ctx, serverInsecureConn, "")
			Expect(err).To(MatchError(context.Canceled))
		}()
		_, err = clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
		Expect(err).To(HaveOccurred())
	})

	Context("peer ID checks", func() {
		It("succeeds when the server checks the client's ID", func() {
			serverTransport, err := New(serverKey)
			Expect(err).ToNot(HaveOccurred())
			clientTransport, err := New(clientKey)
			Expect(err).ToNot(HaveOccurred())

			clientInsecureConn, serverInsecureConn := connect()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn, clientID)
				Expect(err).ToNot(HaveOccurred())
				Expect(conn.RemotePeer()).To(Equal(clientID))
				b := make([]byte, 6)
				_, err = conn.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(b)).To(Equal("foobar"))
			}()
			conn, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close()
			_, err = conn.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.RemotePeer()).To(Equal(serverID))
			Eventually(done).Should(BeClosed())
		})

		It("fails if the peer ID doesn't match, for outgoing connections", func() {
			fmt.Fprintf(GinkgoWriter, "Creating another peer")
			thirdPartyID, _ := createPeer()

			serverTransport, err := New(serverKey)
			Expect(err).ToNot(HaveOccurred())
			clientTransport, err := New(clientKey)
			Expect(err).ToNot(HaveOccurred())

			clientInsecureConn, serverInsecureConn := connect()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn, "")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("tls: bad certificate"))
			}()
			// dial, but expect the wrong peer ID
			_, err = clientTransport.SecureOutbound(context.Background(), clientInsecureConn, thirdPartyID)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("peer IDs don't match"))
			Eventually(done).Should(BeClosed())
		})

		It("fails if the peer ID doesn't match, for incoming connections", func() {
			fmt.Fprintf(GinkgoWriter, "Creating another peer")
			thirdPartyID, _ := createPeer()

			serverTransport, err := New(serverKey)
			Expect(err).ToNot(HaveOccurred())
			clientTransport, err := New(clientKey)
			Expect(err).ToNot(HaveOccurred())

			clientInsecureConn, serverInsecureConn := connect()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
				Expect(err).ToNot(HaveOccurred())
				_, err = conn.Read([]byte{0})
				Expect(err.Error()).To(ContainSubstring("tls: bad certificate"))
			}()
			// accept connection, but expect the wrong peer ID
			_, err = serverTransport.SecureInbound(context.Background(), serverInsecureConn, thirdPartyID)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("peer IDs don't match"))
			Eventually(done).Should(BeClosed())
		})
	})

	It("handles simultaneous open", func() {
		// Avoid confusion regarding the naming.
		p1, p1Key := serverID, serverKey
		p2, p2Key := clientID, clientKey

		// We use a normal dial / listen to establish the TCP connection,
		// but we then start two clients.
		c1raw, c2raw := connect()

		c1Transport, err := New(p1Key)
		Expect(err).ToNot(HaveOccurred())
		c2Transport, err := New(p2Key)
		Expect(err).ToNot(HaveOccurred())

		c1ConnChan := make(chan sec.SecureConn, 1)
		go func() {
			defer GinkgoRecover()
			conn, err := c1Transport.SecureOutbound(context.Background(), c1raw, p2)
			Expect(err).ToNot(HaveOccurred())
			c1ConnChan <- conn
		}()

		c2, err := c2Transport.SecureOutbound(context.Background(), c2raw, p1)
		Expect(err).ToNot(HaveOccurred())
		defer c2.Close()
		var c1 sec.SecureConn
		Eventually(c1ConnChan).Should(Receive(&c1))
		defer c1.Close()

		// check that the peers are in the correct roles
		isClient := func(c sec.SecureConn) bool {
			// the isClient field of the tls.Conn will tell us who is client and server
			return reflect.ValueOf(c.(*conn).Conn).Elem().FieldByName("isClient").Bool()
		}
		switch comparePeerIDs(p1, p2) {
		case -1:
			// H(p1) < H(p2) => p1 acts as a client, p2 as a server
			Expect(isClient(c1)).To(BeTrue())
			Expect(isClient(c2)).To(BeFalse())
		case 1:
			// H(p1) > H(p2) => p1 acts as a server, p2 as a client
			Expect(isClient(c1)).To(BeFalse())
			Expect(isClient(c2)).To(BeTrue())
		default:
			Fail("unexpected peer comparison result")
		}

		// exchange some data
		_, err = c1.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		b := make([]byte, 6)
		_, err = c2.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(b)).To(Equal("foobar"))
	})

	Context("invalid certificates", func() {
		invalidateCertChain := func(identity *Identity) {
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
			cert2DER, err := x509.CreateCertificate(rand.Reader, tmpl, cert1, key2.Public(), key1)
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
				ExtraExtensions: []pkix.Extension{
					{Id: extensionID, Value: []byte("foobar")},
				},
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
			keyBytes, err := ci.MarshalPublicKey(key.GetPublic())
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
			keyBytes, err := ci.MarshalPublicKey(key.GetPublic())
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
				clientTransport, err := New(clientKey)
				Expect(err).ToNot(HaveOccurred())
				t.apply(clientTransport.identity)

				clientInsecureConn, serverInsecureConn := connect()

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn, "")
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
				serverTransport, err := New(serverKey)
				Expect(err).ToNot(HaveOccurred())
				t.apply(serverTransport.identity)
				clientTransport, err := New(clientKey)
				Expect(err).ToNot(HaveOccurred())

				clientInsecureConn, serverInsecureConn := connect()

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn, "")
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("remote error: tls:"))
					close(done)
				}()

				_, err = clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(t.remoteErr)
				Eventually(done).Should(BeClosed())
			})
		}
	})
})

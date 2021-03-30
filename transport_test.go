package libp2ptls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/types"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

//////
// Definition of types and helper functions for the tests
//////

// Credentials for a libp2p peer
type credentials struct {
	ID  peer.ID
	key ci.PrivKey
}

// Type of private key
type privateKeyType int

// Enumerated types of private keys
const (
	ecdsaKeyType privateKeyType = iota
	rsaKeyType
	ed25519KeyType
	secp256k1KeyType
)

// Create peer credentials for a specific key type
func createPeerWithKeyType(keyType privateKeyType) credentials {
	var priv ci.PrivKey
	var err error
	switch keyType {
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
	return credentials{ID: id, key: priv}
}

// Create peer credentials with a random key type
func createPeer() credentials {
	var randomInt privateKeyType = privateKeyType(mrand.Int() % 4)

	return createPeerWithKeyType(randomInt)
}

// Create an insecure connection between a server and a client
func connect() (net.Conn, net.Conn) {
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

//////
// Definition of standard tests
//////
func testHandshake(serverCredentials credentials, serverTransport IDTransport, clientCredentials credentials, clientTransport IDTransport) {
	clientInsecureConn, serverInsecureConn := connect()

	serverConnChan := make(chan sec.SecureConn)
	go func() {
		defer GinkgoRecover()
		serverConn, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
		Expect(err).ToNot(HaveOccurred())
		serverConnChan <- serverConn
	}()
	clientConn, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverCredentials.ID)
	Expect(err).ToNot(HaveOccurred())
	var serverConn sec.SecureConn
	Eventually(serverConnChan).Should(Receive(&serverConn))
	defer clientConn.Close()
	defer serverConn.Close()
	Expect(clientConn.LocalPeer()).To(Equal(clientCredentials.ID))
	Expect(serverConn.LocalPeer()).To(Equal(serverCredentials.ID))
	Expect(clientConn.LocalPrivateKey()).To(Equal(clientCredentials.key))
	Expect(serverConn.LocalPrivateKey()).To(Equal(serverCredentials.key))
	Expect(clientConn.RemotePeer()).To(Equal(serverCredentials.ID))
	Expect(serverConn.RemotePeer()).To(Equal(clientCredentials.ID))
	Expect(clientConn.RemotePublicKey()).To(Equal(serverCredentials.key.GetPublic()))
	Expect(serverConn.RemotePublicKey()).To(Equal(clientCredentials.key.GetPublic()))
	// exchange some data
	_, err = serverConn.Write([]byte("foobar"))
	Expect(err).ToNot(HaveOccurred())
	b := make([]byte, 6)
	_, err = clientConn.Read(b)
	Expect(err).ToNot(HaveOccurred())
	Expect(string(b)).To(Equal("foobar"))
}

func testOutboundContextCancel(serverCredentials credentials, serverTransport IDTransport, clientCredentials credentials, clientTransport IDTransport) {
	clientInsecureConn, serverInsecureConn := connect()

	go func() {
		defer GinkgoRecover()
		_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
		Expect(err).To(HaveOccurred())
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := clientTransport.SecureOutbound(ctx, clientInsecureConn, serverCredentials.ID)
	Expect(err).To(MatchError(context.Canceled))
}

func testInboundContextCancel(serverCredentials credentials, serverTransport IDTransport, clientCredentials credentials, clientTransport IDTransport) {
	clientInsecureConn, serverInsecureConn := connect()

	go func() {
		defer GinkgoRecover()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := serverTransport.SecureInbound(ctx, serverInsecureConn)
		Expect(err).To(MatchError(context.Canceled))
	}()
	_, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverCredentials.ID)
	Expect(err).To(HaveOccurred())
}

func testMismatchingPeerID(serverTransport IDTransport, clientTransport IDTransport, expectedServerError string) {
	fmt.Fprintf(GinkgoWriter, "Creating another peer")
	thirdParty := createPeer()

	clientInsecureConn, serverInsecureConn := connect()

	done := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(expectedServerError))
		close(done)
	}()
	// dial, but expect the wrong peer ID
	_, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, thirdParty.ID)
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("peer IDs don't match"))
	Eventually(done).Should(BeClosed())
}

//////
// Definition of invalid certificate tests
//////
func invalidateCertChain(localPrivKey ci.PrivKey, idTransport *IDTransport) {
	// TODO [Low]: ?Handle *rsa.PrivateKey for identity.config.Certificates[0].PrivateKey.(type)?
	// Create an alternate private key for signing the certificate that is sent to the remote peer
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())
	err = (*idTransport).overrideLocalPeerPrivateKey(key)
	Expect(err).ToNot(HaveOccurred())
}

func twoCerts(localPrivKey ci.PrivKey, idTransport *IDTransport) {
	var err error
	keyLeaf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	data, err := signCertKey(localPrivKey, keyLeaf)
	tmplLeaf := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: data},
		},
	}

	err = (*idTransport).overrideLocalX509Cert(*tmplLeaf, keyLeaf)
	Expect(err).ToNot(HaveOccurred())

	// Prepare the parent certificate in the certificate chain
	tmplParent := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	keyParent, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	err = (*idTransport).addX509CertificateToLocalCertChain(*tmplParent, keyParent)
	Expect(err).ToNot(HaveOccurred())
}

func expiredCert(localPrivKey ci.PrivKey, idTransport *IDTransport) {
	err := (*idTransport).overrideLocalX509Cert(x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(-time.Minute),
	}, nil)
	Expect(err).ToNot(HaveOccurred())
}

func noKeyExtension(localPrivKey ci.PrivKey, idTransport *IDTransport) {
	err := (*idTransport).overrideLocalX509Cert(x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, nil)
	Expect(err).ToNot(HaveOccurred())
}

func unparseableKeyExtension(localPrivKey ci.PrivKey, idTransport *IDTransport) {
	err := (*idTransport).overrideLocalX509Cert(x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: []byte("foobar")},
		},
	}, nil)
	Expect(err).ToNot(HaveOccurred())
}

func unparseableKey(localPrivKey ci.PrivKey, idTransport *IDTransport) {
	data, err := asn1.Marshal(signedKey{PubKey: []byte("foobar")})
	Expect(err).ToNot(HaveOccurred())
	err = (*idTransport).overrideLocalX509Cert(x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: data},
		},
	}, nil)
	Expect(err).ToNot(HaveOccurred())
}

func tooShortSignature(localPrivKey ci.PrivKey, idTransport *IDTransport) {
	key, _, err := ci.GenerateSecp256k1Key(rand.Reader)
	Expect(err).ToNot(HaveOccurred())
	keyBytes, err := key.GetPublic().Bytes()
	Expect(err).ToNot(HaveOccurred())
	data, err := asn1.Marshal(signedKey{
		PubKey:    keyBytes,
		Signature: []byte("foobar"),
	})
	Expect(err).ToNot(HaveOccurred())
	err = (*idTransport).overrideLocalX509Cert(x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: data},
		},
	}, nil)
	Expect(err).ToNot(HaveOccurred())
}

func invalidSignature(localPrivKey ci.PrivKey, idTransport *IDTransport) {
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
	err = (*idTransport).overrideLocalX509Cert(x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: data},
		},
	}, nil)
	Expect(err).ToNot(HaveOccurred())
}

// Define functions that will transform an IDTransport to generate invalid certificates by the local peer,
// and the error that is to be expected by detected by the remote peer
type transform struct {
	name      string
	apply     func(ci.PrivKey, *IDTransport)
	remoteErr types.GomegaMatcher // the error that the side validating the chain gets
}

var transforms = []transform{
	{
		name:  "private key used in the TLS handshake doesn't match the public key in the cert",
		apply: invalidateCertChain,
		remoteErr: Or(
			Equal("tls: invalid signature by the client certificate: ECDSA verification failure"),
			Equal("tls: invalid signature by the server certificate: ECDSA verification failure"),
		),
	},
	{
		name:  "certificate chain contains 2 certs",
		apply: twoCerts,
		remoteErr: Or(
			Equal("expected one certificates in the chain"),
		),
	},
	{
		name:  "cert is expired",
		apply: expiredCert,
		remoteErr: Or(
			ContainSubstring("certificate has expired or is not yet valid"),
		),
	},
	{
		name:      "cert doesn't have the key extension",
		apply:     noKeyExtension,
		remoteErr: ContainSubstring("expected certificate to contain the key extension"),
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
		remoteErr: ContainSubstring("signature invalid"),
	},
}

/// Define helper function for creating invalid certificate tests by a transport client
type transportConstructor func(key ci.PrivKey) (IDTransport, error)

func createInvalidCertByClientTest(categoryLabel string,
	clientTransportTransform transform,
	localErrOnClient types.GomegaMatcher,
	serverPeerConstructor func() credentials,
	serverTransportConstructor transportConstructor,
	clientPeerConstructor func() credentials,
	clientTransportConstructor transportConstructor) {
	//////
	// Test an invalid certificate presented by a client
	//////
	It(fmt.Sprintf(categoryLabel, clientTransportTransform.name), func() {
		// Create peers with a specific key type
		serverCreds := serverPeerConstructor()
		clientCreds := clientPeerConstructor()

		// Create the security transports
		serverTransport, err := serverTransportConstructor(serverCreds.key)
		Expect(err).ToNot(HaveOccurred())
		clientTransport, err := clientTransportConstructor(clientCreds.key)
		Expect(err).ToNot(HaveOccurred())
		clientTransportTransform.apply(clientCreds.key, &clientTransport)

		// Create the insecure connections
		clientInsecureConn, serverInsecureConn := connect()

		// Check errors on the server
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(clientTransportTransform.remoteErr)
			close(done)
		}()

		// Check errors on the client
		conn, err := clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverCreds.ID)
		Expect(err).ToNot(HaveOccurred())
		_, err = gbytes.TimeoutReader(conn, time.Second).Read([]byte{0})
		Expect(err.Error()).To(localErrOnClient)
		Eventually(done).Should(BeClosed())
	})
} // createInvalidCertByClientTest

/// Define helper function for constructing invalid certificate tests by a transport client
func createInvalidCertByServerTest(categoryLabel string,
	serverTransportTransform transform,
	localErrOnServer types.GomegaMatcher,
	serverPeerConstructor func() credentials,
	serverTransportConstructor transportConstructor,
	clientPeerConstructor func() credentials,
	clientTransportConstructor transportConstructor) {
	//////
	// Test an invalid certificate presented by a client
	//////
	It(fmt.Sprintf(categoryLabel, serverTransportTransform.name), func() {
		// Create peers with a specific key type
		serverCreds := serverPeerConstructor()
		clientCreds := clientPeerConstructor()

		// Create the security transports
		serverTransport, err := serverTransportConstructor(serverCreds.key)
		Expect(err).ToNot(HaveOccurred())
		serverTransportTransform.apply(serverCreds.key, &serverTransport)
		clientTransport, err := clientTransportConstructor(clientCreds.key)
		Expect(err).ToNot(HaveOccurred())

		// Create the insecure connections
		clientInsecureConn, serverInsecureConn := connect()

		// Check errors on the server
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(localErrOnServer)
			close(done)
		}()

		// Check errors on the client
		_, err = clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverCreds.ID)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(serverTransportTransform.remoteErr)
		Eventually(done).Should(BeClosed())
	})
} // createInvalidCertByServerTest

//////
// Assemble the test definitions
//////
var _ = Describe("Transport", func() {
	var (
		serverCredentials credentials
		clientCredentials credentials
	)

	// Run before each test
	BeforeEach(func() {
		fmt.Fprintf(GinkgoWriter, "Initializing a server")
		serverCredentials = createPeer()
		fmt.Fprintf(GinkgoWriter, "Initializing a client")
		clientCredentials = createPeer()
	})

	//////
	// Test a handshake between two peers
	//////
	It("handshakes - StdTLSServer-StdTLSClient", func() {
		clientTransport, err := NewStdTLSTransport(clientCredentials.key)
		Expect(err).ToNot(HaveOccurred())
		serverTransport, err := NewStdTLSTransport(serverCredentials.key)
		Expect(err).ToNot(HaveOccurred())

		testHandshake(serverCredentials, serverTransport, clientCredentials, clientTransport)
	})

	//////
	// Test whether a client/outbound detects a context cancellation by client
	//////
	It("fails when the context of the outgoing connection is canceled - StdTLSServer-StdTLSClient", func() {
		clientTransport, err := NewStdTLSTransport(clientCredentials.key)
		Expect(err).ToNot(HaveOccurred())
		serverTransport, err := NewStdTLSTransport(serverCredentials.key)
		Expect(err).ToNot(HaveOccurred())

		testOutboundContextCancel(serverCredentials, serverTransport, clientCredentials, clientTransport)
	})

	//////
	// Test whether a server/inbound detects a context cancellation by server
	//////
	It("fails when the context of the incoming connection is canceled - StdTLSServer-StdTLSClient", func() {
		clientTransport, err := NewStdTLSTransport(clientCredentials.key)
		Expect(err).ToNot(HaveOccurred())
		serverTransport, err := NewStdTLSTransport(serverCredentials.key)
		Expect(err).ToNot(HaveOccurred())

		testInboundContextCancel(serverCredentials, serverTransport, clientCredentials, clientTransport)
	})

	//////
	// Test whether a client detects an incorrect peer ID
	//////
	It("fails if the peer ID doesn't match - StdTLSServer-StdTLSClient", func() {
		serverTransport, err := NewStdTLSTransport(serverCredentials.key)
		Expect(err).ToNot(HaveOccurred())
		clientTransport, err := NewStdTLSTransport(clientCredentials.key)
		Expect(err).ToNot(HaveOccurred())

		// "tls: bad certificate"
		var expectedServerErrorMessage string = "bad certificate"
		testMismatchingPeerID(serverTransport, clientTransport, expectedServerErrorMessage)
	})

	//////
	// Test invalid certificates
	//////
	Context("invalid certificates", func() {
		var localErrOnClient types.GomegaMatcher
		var localErrOnServer types.GomegaMatcher

		//////
		// Test invalid certificates between StdTLSServer-StdTLSClient
		//////
		// The error observed by a client that generates the invalid certificate
		localErrOnClient = Or(
			// if the certificate's public key doesn't match the private key used for signing
			Equal("remote error: tls: error decrypting message"),
			// all other errors
			Equal("remote error: tls: bad certificate"),
		)

		// The error observed by a server that generates the invalid certificate
		localErrOnServer = ContainSubstring("remote error: tls:")

		for i := range transforms {
			t := transforms[i]

			//////
			// Test an invalid certificate presented by a client
			//////
			createInvalidCertByClientTest("fails if the client presents an invalid cert - StdTLSServer-StdTLSClient: %s",
				t,
				localErrOnClient,
				func() credentials { return createPeer() },
				NewStdTLSTransport,
				func() credentials { return createPeer() },
				NewStdTLSTransport)

			//////
			// Test an invalid certificate presented by a server
			//////
			createInvalidCertByServerTest("fails if the server presents an invalid cert - StdTLSServer-StdTLSClient: %s",
				t,
				localErrOnServer,
				func() credentials { return createPeer() },
				NewStdTLSTransport,
				func() credentials { return createPeer() },
				NewStdTLSTransport)
		}

	})
})

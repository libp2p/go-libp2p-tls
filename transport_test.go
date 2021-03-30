package libp2ptls

import (
	"context"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"net"

	"github.com/onsi/gomega/types"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

	It("handshakes", func() {
		clientTransport, err := New(clientKey)
		Expect(err).ToNot(HaveOccurred())
		serverTransport, err := New(serverKey)
		Expect(err).ToNot(HaveOccurred())

		clientInsecureConn, serverInsecureConn := connect()

		serverConnChan := make(chan sec.SecureConn)
		go func() {
			defer GinkgoRecover()
			serverConn, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
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
		Expect(clientConn.RemotePublicKey()).To(Equal(serverKey.GetPublic()))
		Expect(serverConn.RemotePublicKey()).To(Equal(clientKey.GetPublic()))
		// exchange some data
		_, err = serverConn.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		b := make([]byte, 6)
		_, err = clientConn.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(b)).To(Equal("foobar"))
	})

	It("fails when the context of the outgoing connection is canceled", func() {
		clientTransport, err := New(clientKey)
		Expect(err).ToNot(HaveOccurred())
		serverTransport, err := New(serverKey)
		Expect(err).ToNot(HaveOccurred())

		clientInsecureConn, serverInsecureConn := connect()

		go func() {
			defer GinkgoRecover()
			_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
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
			_, err := serverTransport.SecureInbound(ctx, serverInsecureConn)
			Expect(err).To(MatchError(context.Canceled))
		}()
		_, err = clientTransport.SecureOutbound(context.Background(), clientInsecureConn, serverID)
		Expect(err).To(HaveOccurred())
	})

	It("fails if the peer ID doesn't match", func() {
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
			_, err := serverTransport.SecureInbound(context.Background(), serverInsecureConn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("tls: bad certificate"))
			close(done)
		}()
		// dial, but expect the wrong peer ID
		_, err = clientTransport.SecureOutbound(context.Background(), clientInsecureConn, thirdPartyID)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(SatisfyAny(ContainSubstring("peer IDs don't match"),
			ContainSubstring("SSL errors: SSL routines:tls_process_server_certificate:certificate verify failed")))
		Eventually(done).Should(BeClosed())
	})

	Context("invalid certificates", func() {
		InvalidCertificateTests(&serverKey, &clientKey, &serverID, &clientID, connect)
	})
})

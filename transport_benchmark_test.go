package libp2ptls

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

//////
// Handshake throughput
//////

func BenchmarkHandshake_StdTLSServer_StdTLSClient(b *testing.B) {
	var serverTT transportConstructor = NewStdTLSTransport
	var clientTT transportConstructor = NewStdTLSTransport
	benchmarkHandshake(b, serverTT, clientTT)
}

// The generic function to benchmark the security transport handshake
func benchmarkHandshake(b *testing.B, serverTT transportConstructor, clientTT transportConstructor) {
	// Create a StdTLS peer listener
	var remotePeerID *peer.ID
	var tp IDTransport
	var ln net.Listener
	var err error
	if remotePeerID, tp, ln, err = newPeerServer(serverTT); err != nil {
		b.Error("Unable to create a peer listener")
		b.FailNow()
	}

	// Create a single-connection server that is controllable (can close the single connection) by the test
	var shutdown = false
	defer func() {
		ln.Close()
	}()
	go func() {
		for {
			if shutdown {
				break
			}

			insecureConn, err := ln.Accept()
			if err != nil {
				continue
			}

			// Secure the libp2p connection
			go func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				_, err := tp.SecureInbound(ctx, insecureConn)
				if err != nil {
					fmt.Println("libp2p Server experienced an accept error")
					//continue
				}

				// Do nothing with the secureConn.  Expect the client to close the connection
				// Synchronously wait for test to trigger closing the connection
				//<- closeInsecureConnChan

				// Close the secure connection
				//secureConn.Close()
			}()
		}
	}()

	// Prepare a loop for the handshake benchmark
	var serverTransportProtocol string = ln.Addr().Network() // e.g."tcp"
	var serverEndpoint string = ln.Addr().String()           // e.g. "127.0.0.1:5533"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Construct an insecure connection to the server
		var tp IDTransport
		var err error
		_, tp, err = newPeerClientComponents(clientTT)

		insecureConn, err := net.Dial(serverTransportProtocol, serverEndpoint)
		if err != nil {
			b.Error("Error dialing\n", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Benchmark the handshake
		b.StartTimer()
		secureConn, err := tp.SecureOutbound(ctx, insecureConn, *remotePeerID)
		if err != nil {
			b.Error("Error with securing client handshake", err)
			// return err
		}
		b.StopTimer()

		// Trigger the server to close the single connection
		secureConn.Close()
	}

	// Shutdown server
	shutdown = true
	ln.Close()
}

//////
// Connection latency (ping benchmarks)
//////

func BenchmarkLatency_StdTLSServer_StdTLSClient(b *testing.B) {
	var serverTT transportConstructor = NewStdTLSTransport
	var clientTT transportConstructor = NewStdTLSTransport
	benchmarkPingLatency(b, serverTT, clientTT)
}

// The generic function to benchmark the latency of an existing secure connection
func benchmarkPingLatency(b *testing.B, serverTC transportConstructor, clientTC transportConstructor) {
	// Start a server
	var wg sync.WaitGroup
	wg.Add(1)
	const withHeartbeatListener bool = true
	var s *server
	var err error
	if s, err = startBenchmarkServer(serverTC, withHeartbeatListener, &wg); err != nil {
		fmt.Println("Unable to start server for benchmarking", err)
		return
	}
	wg.Wait() // Wait for server to be ready

	// Start a client
	var c *client
	var cancel context.CancelFunc
	if c, cancel, err = startClient(clientTC, s.peerID, s.ln.Addr()); err != nil {
		// Skip
		fmt.Println("Unable to start client")
		cancel()
		b.FailNow()
		return
	}
	defer cancel()

	// Perform benchmark
	var clientHeartbeatRequests int
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientHeartbeatRequests++
		if err = c.checkHeartbeat(); err != nil {
			fmt.Println("Client hearbeat check request rejected", err)
			b.FailNow()
			return
		}
	}
	b.StopTimer()

	// Clean up
	wg.Add(1)
	s.stopServer(&wg)
	c.stopClient()
	wg.Wait() // Wait for server to stop before checking the heartbeats

	// Check the heartbeats
	if clientHeartbeatRequests != s.nbrHeartbeatReplies {
		b.Fail()
	}

}

//////
// Connection throughput
//////

func BenchmarkConnections_StdTLSServer_StdTLSClient(b *testing.B) {
	var serverTT transportConstructor = NewStdTLSTransport
	var clientTT transportConstructor = NewStdTLSTransport
	benchmarkConnections(b, serverTT, clientTT)
}

// The generic function to benchmark the establishment of a secure connection
func benchmarkConnections(b *testing.B, serverTC transportConstructor, clientTC transportConstructor) {
	// Start a server
	var wg sync.WaitGroup
	wg.Add(1)
	const withHeartbeatListener bool = false
	var s *server
	var err error
	if s, err = startBenchmarkServer(serverTC, withHeartbeatListener, &wg); err != nil {
		fmt.Println("Unable to start server for benchmarking", err)
		return
	}
	wg.Wait() // Wait for server to be ready

	var serverPeerID peer.ID = s.peerID
	var serverAddr net.Addr = s.ln.Addr()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Provision a client
		var c *client
		var cancel context.CancelFunc
		if c, cancel, err = startClient(clientTC, serverPeerID, serverAddr); err != nil {
			// Skip
			cancel()
			b.FailNow()
			fmt.Println("Unable to start client", i)
		}
		c.stopClient()
		cancel()
	}
	b.StopTimer()

	// Clean up
	wg.Add(1)
	s.stopServer(&wg)
	wg.Wait() // Wait for server to stop
}

//////
// Helper: A client for benchmark tests
//////

func newClient(secureConnection sec.SecureConn) *client {
	var c = client{secureConn: secureConnection}
	var r io.Reader = bufio.NewReader(secureConnection)
	c.scanr = bufio.NewScanner(r)

	return &c
}

func newPeerClientComponents(constructor transportConstructor) (*peer.ID, IDTransport, error) {
	keyType := "ecdsa"

	priv, err := generateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	var tp IDTransport
	if tp, err = constructor(priv); err != nil {
		return nil, nil, err
	}

	return &id, tp, err
}

// client is adapted from cmd/tlsdiag/client.go
type client struct {
	secureConn sec.SecureConn
	scanr      *bufio.Scanner
}

func (c *client) checkHeartbeat() error {
	var err error
	if _, err = c.secureConn.Write([]byte("PING\n")); err != nil {
		fmt.Println("Client: failure to send heartbeat check")
		return err
	}

	scanned := c.scanr.Scan()

	if !scanned {
		return errors.New("Client: Did not receive a heartbeat failure")
	}

	return nil
}

func (c *client) stopClient() error {
	return c.secureConn.Close()
}

func startClient(tc transportConstructor, remotePeerID peer.ID, remoteAddr net.Addr) (*client, context.CancelFunc, error) {
	var tp IDTransport
	var err error
	if _, tp, err = newPeerClientComponents(tc); err != nil {
		return nil, nil, err
	}

	conn, err := net.Dial(remoteAddr.Network(), remoteAddr.String())
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	sconn, err := tp.SecureOutbound(ctx, conn, remotePeerID)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	return newClient(sconn), cancel, nil
}

//////
// Helper: A server for benchmark tests
//////

func startBenchmarkServer(tc transportConstructor, withHeartbeatListener bool, startWG *sync.WaitGroup) (*server, error) {
	var s = server{shutdown: false}
	var err error
	if err = s.startServer(tc, withHeartbeatListener, startWG); err != nil {
		return nil, err
	}

	return &s, nil
}

// A server for benchmark tests
type server struct {
	peerID              peer.ID
	shutdown            bool
	ln                  net.Listener
	nbrHeartbeatReplies int
	stoppedWG           *sync.WaitGroup
}

// Create the related parts of a libp2p peer that will listen
// tp The particular transport type
func newPeerServer(constructor transportConstructor) (*peer.ID, IDTransport, net.Listener, error) {
	port := 0 // Any available port
	keyType := "ecdsa"

	priv, err := generateKey(keyType)
	if err != nil {
		return nil, nil, nil, err
	}

	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, nil, nil, err
	}

	var tp IDTransport
	if tp, err = constructor(priv); err != nil {
		return nil, nil, nil, err
	}

	var ln net.Listener
	ln, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", port))

	return &id, tp, ln, err
}

// This is a variation of the cmd/tlsdiag/server.go
func (s *server) startServer(tc transportConstructor, withHeartbeatListener bool, startWG *sync.WaitGroup) error {
	var id *peer.ID
	var tp IDTransport
	var err error
	if id, tp, s.ln, err = newPeerServer(tc); err != nil {
		return err
	}

	go func() {
		defer s.ln.Close()
		startWG.Done()

		for {
			if s.shutdown {
				break
			}

			insecureConn, err := s.ln.Accept()
			if err != nil {
				// fmt.Println("Server experienced an accept error")
				continue
			}
			// fmt.Printf("Accepted raw connection from %s\n", conn.RemoteAddr())
			go func() {
				var secureConn sec.SecureConn
				if secureConn, err = handleConn(tp, insecureConn); err != nil {
					fmt.Printf("Error handling connection from %s: %s\n", insecureConn.RemoteAddr(), err)
					return
				}

				if withHeartbeatListener {
					s.listenForHeartbeatChecks(secureConn)
				}
			}()
		}

		if !withHeartbeatListener && s.stoppedWG != nil {
			s.stoppedWG.Done()
		}
	}()

	s.peerID = *id
	return nil

}

// Check and respond to heartbeat queries
func (s *server) listenForHeartbeatChecks(secureConn sec.SecureConn) {
	var err error

	// Listen for hearbeat checks in a crude, churning, infinite loop
	var r = bufio.NewReader(secureConn)
	var scanr = bufio.NewScanner(r)
	var pongbytes = []byte("PONG\n")
	for {
		if s.shutdown {
			break
		}

		scanned := scanr.Scan()

		if !scanned {
			continue
		}

		if scanr.Text() != "PING" {
			fmt.Println("Server: received an unrecognized heartbeat check")
			continue
		}

		if _, err = secureConn.Write(pongbytes); err != nil {
			fmt.Println("Server: error writing pong", err)
			continue
		}
		s.nbrHeartbeatReplies++
	}

	if s.stoppedWG != nil {
		s.stoppedWG.Done()
	}
}

func (s *server) stopServer(stoppedWaitGroup *sync.WaitGroup) {
	s.stoppedWG = stoppedWaitGroup
	s.shutdown = true
	s.ln.Close()
}

func handleConn(tp IDTransport, insecureConn net.Conn) (sec.SecureConn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secureConn, err := tp.SecureInbound(ctx, insecureConn)
	if err != nil {
		return nil, err
	}

	return secureConn, nil
}

// Copied from cmd/tlsdiag/key.go
func generateKey(keyType string) (priv ic.PrivKey, err error) {
	switch keyType {
	case "rsa":
		priv, _, err = ic.GenerateRSAKeyPair(2048, rand.Reader)
	case "ecdsa":
		priv, _, err = ic.GenerateECDSAKeyPair(rand.Reader)
	case "ed25519":
		priv, _, err = ic.GenerateEd25519Key(rand.Reader)
	case "secp256k1":
		priv, _, err = ic.GenerateSecp256k1Key(rand.Reader)
	default:
		return nil, fmt.Errorf("unknown key type: %s", keyType)
	}
	return
}

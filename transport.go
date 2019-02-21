package libp2ptls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"

	cs "github.com/libp2p/go-conn-security"
	ci "github.com/libp2p/go-libp2p-crypto"
	ic "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
)

// TLS 1.3 is opt-in in Go 1.12
// Activate it by setting the tls13 GODEBUG flag.
func init() {
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
}

// ID is the protocol ID (used when negotiating with multistream)
const ID = "/tls/1.0.0"

// Transport constructs secure communication sessions for a peer.
type Transport struct {
	identity *Identity

	localPeer peer.ID
	privKey   ci.PrivKey

	activeMutex sync.Mutex
	active      map[net.Conn]ic.PubKey
}

// New creates a TLS encrypted transport
func New(key ci.PrivKey) (*Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		localPeer: id,
		privKey:   key,
		active:    make(map[net.Conn]ic.PubKey),
	}

	identity, err := NewIdentity(key, func(conn net.Conn, pubKey ic.PubKey) {
		t.activeMutex.Lock()
		t.active[conn] = pubKey
		t.activeMutex.Unlock()
	})
	if err != nil {
		return nil, err
	}
	t.identity = identity
	return t, nil
}

var _ cs.Transport = &Transport{}

// SecureInbound runs the TLS handshake as a server.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (cs.Conn, error) {
	defer func() {
		t.activeMutex.Lock()
		// only contains this connection if we successfully derived the client's key
		delete(t.active, insecure)
		t.activeMutex.Unlock()
	}()

	serv := tls.Server(insecure, t.identity.Config)
	return t.handshake(ctx, insecure, serv)
}

// SecureOutbound runs the TLS handshake as a client.
// Note that SecureOutbound will not return an error if the server doesn't
// accept the certificate. This is due to the fact that in TLS 1.3, the client
// sends its certificate and the ClientFinished in the same flight, and can send
// application data immediately afterwards.
// If the handshake fails, the server will close the connection. The client will
// notice this after 1 RTT when calling Read.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (cs.Conn, error) {
	verifiedCallback := func(pubKey ic.PubKey) {
		t.activeMutex.Lock()
		t.active[insecure] = pubKey
		t.activeMutex.Unlock()
	}
	cl := tls.Client(insecure, t.identity.ConfigForPeer(p, verifiedCallback))
	return t.handshake(ctx, insecure, cl)
}

func (t *Transport) handshake(
	ctx context.Context,
	insecure net.Conn,
	tlsConn *tls.Conn,
) (cs.Conn, error) {
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		tlsConn.Close()
	default:
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
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
	conn, err := t.setupConn(insecure, tlsConn)
	if err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return conn, nil
}

func (t *Transport) setupConn(insecure net.Conn, tlsConn *tls.Conn) (cs.Conn, error) {
	t.activeMutex.Lock()
	remotePubKey := t.active[insecure]
	t.activeMutex.Unlock()

	if remotePubKey == nil {
		return nil, errors.New("go-libp2p-tls BUG: expected remote pub key to be set")
	}

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

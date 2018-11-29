package libp2ptls

import (
	"context"
	"crypto/tls"
	"net"

	cs "github.com/libp2p/go-conn-security"
	ci "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
)

// ID is the protocol ID (used when negotiating with multistream)
const ID = "/tls/1.0.0"

// Transport constructs secure communication sessions for a peer.
type Transport struct {
	identity *Identity

	localPeer peer.ID
	privKey   ci.PrivKey
}

// New creates a TLS encrypted transport
func New(key ci.PrivKey) (*Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	identity, err := NewIdentity(key)
	if err != nil {
		return nil, err
	}
	return &Transport{
		identity:  identity,
		localPeer: id,
		privKey:   key,
	}, nil
}

var _ cs.Transport = &Transport{}

// SecureInbound runs the TLS handshake as a server.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (cs.Conn, error) {
	serv := tls.Server(insecure, t.identity.Config)
	return t.handshake(ctx, insecure, serv)
}

// SecureOutbound runs the TLS handshake as a client.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (cs.Conn, error) {
	cl := tls.Client(insecure, t.identity.ConfigForPeer(p))
	return t.handshake(ctx, insecure, cl)
}

func (t *Transport) handshake(
	ctx context.Context,
	// in Go 1.10, we need to close the underlying net.Conn
	// in Go 1.11 this was fixed, and tls.Conn.Close() works as well
	insecure net.Conn,
	tlsConn *tls.Conn,
) (cs.Conn, error) {
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			insecure.Close()
		}
	}()

	if err := tlsConn.Handshake(); err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	conn, err := t.setupConn(tlsConn)
	if err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return conn, nil
}

func (t *Transport) setupConn(tlsConn *tls.Conn) (cs.Conn, error) {
	remotePubKey, err := KeyFromChain(tlsConn.ConnectionState().PeerCertificates)
	if err != nil {
		return nil, err
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

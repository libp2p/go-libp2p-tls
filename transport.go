package libp2ptls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	ps "github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-core/sec"
)

// ID is the protocol ID (used when negotiating with multistream)
const ID = "/tls/1.0.0"

// Transport constructs secure communication sessions for a peer.
type Transport struct {
	identity  *Identity
	peerstore ps.Peerstore

	localPeer peer.ID
	privKey   ci.PrivKey
}

// New creates a TLS encrypted transport
func New(key ci.PrivKey, peerstore ps.Peerstore) (*Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		localPeer: id,
		peerstore: peerstore,
		privKey:   key,
	}

	identity, err := NewIdentity(key)
	if err != nil {
		return nil, err
	}
	t.identity = identity
	return t, nil
}

var _ sec.SecureTransport = &Transport{}

// SecureInbound runs the TLS handshake as a server.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	config, keyCh := t.identity.ConfigForAny()
	cs, err := t.handshake(ctx, tls.Server(insecure, config), keyCh, nil)
	if err != nil {
		insecure.Close()
	}
	return cs, err
}

// SecureOutbound runs the TLS handshake as a client.
// Note that SecureOutbound will not return an error if the server doesn't
// accept the certificate. This is due to the fact that in TLS 1.3, the client
// sends its certificate and the ClientFinished in the same flight, and can send
// application data immediately afterwards.
// If the handshake fails, the server will close the connection. The client will
// notice this after 1 RTT when calling Read.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	config, keyCh := t.identity.ConfigForPeer(p)

	var sessionCache *clientSessionCache
	if csc, err := t.peerstore.Get(p, peerStoreKey); err != nil {
		if err != ps.ErrNotFound {
			panic(fmt.Sprintf("Failed to get session cache from peer store: %s", err))
		}
		sessionCache = newClientSessionCache()
		t.peerstore.Put(p, peerStoreKey, sessionCache)
	} else {
		sessionCache = csc.(*clientSessionCache)
	}
	config.ClientSessionCache = sessionCache

	cs, err := t.handshake(ctx, tls.Client(insecure, config), keyCh, sessionCache)
	if err != nil {
		insecure.Close()
	} else {
		if peerID, err := peer.IDFromPublicKey(cs.RemotePublicKey()); err != nil || peerID != p {
			// Should never happen, but make sure that the public key actually matches the peer ID.
			// Especially important for resumed connection.
			return nil, errors.New("libp2p-tls BUG: peer ID doesn't match public key")
		}
	}
	return cs, err
}

func (t *Transport) handshake(
	ctx context.Context,
	tlsConn *tls.Conn,
	keyCh <-chan ci.PubKey,
	sessionCache *clientSessionCache,
) (sec.SecureConn, error) {
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		tlsConn.Close()
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

	// Should be ready by this point, don't block.
	var remotePubKey ci.PubKey
	select {
	case remotePubKey = <-keyCh:
		// In the case of a normal (non-resumed) handshake, the server will send its certificate,
		// and we extract its public key from it.
	default:
		// In the case of a resumed handshake, the server doesn't send any certificate.
		// We already know its public key from the last connection.
	}
	if remotePubKey == nil {
		if !tlsConn.ConnectionState().DidResume || sessionCache == nil {
			return nil, errors.New("go-libp2p-tls BUG: expected remote pub key to be set")
		}
		remotePubKey = sessionCache.GetPubKey()
	} else if sessionCache != nil {
		sessionCache.SetPubKey(remotePubKey)
	}

	conn, err := t.setupConn(tlsConn, remotePubKey)
	if err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return conn, nil
}

func (t *Transport) setupConn(tlsConn *tls.Conn, remotePubKey ci.PubKey) (sec.SecureConn, error) {
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

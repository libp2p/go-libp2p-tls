package libp2ptls

import (
	"crypto/tls"

	cs "github.com/libp2p/go-conn-security"
	ic "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
)

type conn struct {
	*tls.Conn

	localPeer peer.ID
	privKey   ic.PrivKey

	remotePeer   peer.ID
	remotePubKey ic.PubKey
}

var _ cs.Conn = &conn{}

func (c *conn) LocalPeer() peer.ID {
	return c.localPeer
}

func (c *conn) LocalPrivateKey() ic.PrivKey {
	return c.privKey
}

func (c *conn) RemotePeer() peer.ID {
	return c.remotePeer
}

func (c *conn) RemotePublicKey() ic.PubKey {
	return c.remotePubKey
}

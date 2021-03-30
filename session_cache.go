package libp2ptls

import (
	"crypto/tls"

	ci "github.com/libp2p/go-libp2p-core/crypto"
)

const cacheSize = 3

type clientSessionCache struct {
	cache []*tls.ClientSessionState

	// When using session resumption, the server won't send its certificate chain.
	// We therefore need to save its public key when storing a session ticket,
	// so we can return it on conn.RemotePublicKey().
	pubKey ci.PubKey
}

var _ tls.ClientSessionCache = &clientSessionCache{}

func newClientSessionCache() *clientSessionCache {
	return &clientSessionCache{}
}

func (c *clientSessionCache) Put(_ string, cs *tls.ClientSessionState) {
	if len(c.cache) == cacheSize {
		c.cache = c.cache[1:]
	}
	c.cache = append(c.cache, cs)
}

func (c *clientSessionCache) Get(_ string) (*tls.ClientSessionState, bool) {
	if len(c.cache) == 0 {
		return nil, false
	}
	ticket := c.cache[len(c.cache)-1]
	c.cache = c.cache[:len(c.cache)-1]
	return ticket, true
}

func (c *clientSessionCache) SetPubKey(k ci.PubKey) {
	if c.pubKey != nil && !c.pubKey.Equals(k) {
		panic("mismatching public key")
	}
	c.pubKey = k
}

func (c *clientSessionCache) GetPubKey() ci.PubKey {
	return c.pubKey
}

package libp2ptls

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"unsafe"

	ci "github.com/libp2p/go-libp2p-core/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session Ticket Cache", func() {
	var cache *clientSessionCache
	const key = "irrelevant"
	ticketSize := unsafe.Sizeof(&tls.ClientSessionState{})

	toSessionTicket := func(n int) *tls.ClientSessionState {
		b := make([]byte, ticketSize)
		binary.BigEndian.PutUint32(b, uint32(n))
		return (*tls.ClientSessionState)(unsafe.Pointer(&b))
	}

	fromSessionTicket := func(t *tls.ClientSessionState) int {
		b := (*[]byte)(unsafe.Pointer(t))
		return int(binary.BigEndian.Uint32(*b))
	}

	BeforeEach(func() {
		cache = newClientSessionCache()
	})

	It("encodes and decodes values from session tickets", func() {
		Expect(fromSessionTicket(toSessionTicket(1337))).To(Equal(1337))
	})

	It("doesn't return a session ticket if there's none", func() {
		t, ok := cache.Get(key)
		Expect(ok).To(BeFalse())
		Expect(t).To(BeNil())
	})

	It("saves and retrieves session tickets", func() {
		cache.Put(key, toSessionTicket(42))
		ticket, ok := cache.Get(key)
		Expect(ok).To(BeTrue())
		Expect(fromSessionTicket(ticket)).To(Equal(42))
		_, ok = cache.Get(key)
		Expect(ok).To(BeFalse())
	})

	It("returns the most recent ticket first", func() {
		cache.Put(key, toSessionTicket(1))
		cache.Put(key, toSessionTicket(2))
		ticket, ok := cache.Get(key)
		Expect(ok).To(BeTrue())
		Expect(fromSessionTicket(ticket)).To(Equal(2))
		ticket, ok = cache.Get(key)
		Expect(ok).To(BeTrue())
		Expect(fromSessionTicket(ticket)).To(Equal(1))
	})

	It("limits the number of tickets saved", func() {
		Expect(cacheSize).To(Equal(3))
		cache.Put(key, toSessionTicket(1))
		cache.Put(key, toSessionTicket(2))
		cache.Put(key, toSessionTicket(3))
		cache.Put(key, toSessionTicket(4))
		ticket, ok := cache.Get(key)
		Expect(ok).To(BeTrue())
		Expect(fromSessionTicket(ticket)).To(Equal(4))
		ticket, ok = cache.Get(key)
		Expect(ok).To(BeTrue())
		Expect(fromSessionTicket(ticket)).To(Equal(3))
		ticket, ok = cache.Get(key)
		Expect(ok).To(BeTrue())
		Expect(fromSessionTicket(ticket)).To(Equal(2))
		_, ok = cache.Get(key)
		Expect(ok).To(BeFalse())
	})

	It("sets and gets the public key", func() {
		_, pub, err := ci.GenerateEd25519Key(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		cache.SetPubKey(pub)
		Expect(cache.GetPubKey()).To(Equal(pub))
	})

	It("doesn't allow setting of different public keys", func() {
		_, pub1, err := ci.GenerateEd25519Key(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		_, pub2, err := ci.GenerateEd25519Key(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		cache.SetPubKey(pub1)
		Expect(func() { cache.SetPubKey(pub2) }).To(Panic())
	})
})

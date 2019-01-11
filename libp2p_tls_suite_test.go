package libp2ptls

import (
	mrand "math/rand"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLibp2pTLS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "libp2p TLS Suite")
}

var _ = BeforeSuite(func() {
	mrand.Seed(GinkgoRandomSeed())
})

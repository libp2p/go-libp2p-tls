package libp2ptls

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLibp2pTLS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "libp2p TLS Suite")
}

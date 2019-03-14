package libp2ptls

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Extensions", func() {
	It("generates a prefixed extension ID", func() {
		Expect(getPrefixedExtensionID([]int{13, 37})).To(Equal([]int{1, 3, 6, 1, 4, 1, 53594, 13, 37}))
	})

	It("compares extension IDs", func() {
		Expect(extensionIDEqual([]int{1, 2, 3, 4}, []int{1, 2, 3, 4})).To(BeTrue())
		Expect(extensionIDEqual([]int{1, 2, 3, 4}, []int{1, 2, 3})).To(BeFalse())
		Expect(extensionIDEqual([]int{1, 2, 3}, []int{1, 2, 3, 4})).To(BeFalse())
		Expect(extensionIDEqual([]int{1, 2, 3, 4}, []int{4, 3, 2, 1})).To(BeFalse())
	})
})

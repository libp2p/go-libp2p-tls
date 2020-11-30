package libp2ptls

// Object Identifier allocated by IANA to the libp2p project at Protocol Labs
// according to the libp2p TLS specification https://github.com/libp2p/specs/blob/master/tls/tls.md
var extensionPrefix = []int{1, 3, 6, 1, 4, 1, 53594}

// getPrefixedExtensionID returns an Object Identifier
// that can be used in x509 Certificates.
func getPrefixedExtensionID(suffix []int) []int {
	return append(extensionPrefix, suffix...)
}

// extensionIDEqual compares two extension IDs.
func extensionIDEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

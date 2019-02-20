package libp2ptls

// TODO: get an assigment for a valid OID
var extensionPrefix = []int{1, 3, 6, 1, 4, 1, 123456789}

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

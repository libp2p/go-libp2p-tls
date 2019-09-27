//go:build js
// +build js

package libp2ptls

// JS does not support hardware accelerated CPU instructions for crypto.
var (
	hasGCMAsmAMD64 = false // cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = false // cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	hasGCMAsmS390X = false // cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasGCMAsm = false // hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
)

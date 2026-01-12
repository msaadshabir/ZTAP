//go:build !linux

package enforcer

// EnforceWithEBPFIfAvailable is a no-op on non-Linux platforms.
func EnforceWithEBPFIfAvailable(opts EnforcementOptions) error {
	// eBPF not available on non-Linux platforms
	EnforceWithEBPF(opts)
	return nil
}

// StopLinuxEnforcement is a no-op on non-Linux platforms.
func StopLinuxEnforcement() error {
	return nil
}

// CanUseEBPF always returns false on non-Linux platforms.
func CanUseEBPF() bool {
	return false
}

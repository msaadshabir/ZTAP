//go:build !linux

package enforcer

import "ztap/pkg/policy"

// EnforceWithEBPFIfAvailable is a no-op on non-Linux platforms.
func EnforceWithEBPFIfAvailable(policies []policy.NetworkPolicy, cgroupPath string) error {
	// eBPF not available on non-Linux platforms
	EnforceWithEBPF(policies)
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

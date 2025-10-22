//go:build !linux

package enforcer

import "ztap/pkg/policy"

// enforceWithEBPFIfAvailable is a no-op on non-Linux platforms.
func enforceWithEBPFIfAvailable(policies []policy.NetworkPolicy, cgroupPath string) error {
	// eBPF not available on non-Linux platforms
	EnforceWithEBPF(policies)
	return nil
}

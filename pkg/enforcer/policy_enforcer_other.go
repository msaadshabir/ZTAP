//go:build !linux

package enforcer

import "ztap/pkg/policy"

// EnforceWithEBPFIfAvailable is a no-op on non-Linux platforms.
func EnforceWithEBPFIfAvailable(policies []policy.NetworkPolicy, cgroupPath string) error {
	// eBPF not available on non-Linux platforms
	EnforceWithEBPF(policies)
	return nil
}

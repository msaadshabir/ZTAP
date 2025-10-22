//go:build linux

package enforcer

import "ztap/pkg/policy"

// enforceWithEBPFIfAvailable uses the real eBPF enforcer on Linux.
func enforceWithEBPFIfAvailable(policies []policy.NetworkPolicy, cgroupPath string) error {
	return EnforceWithEBPFReal(policies, cgroupPath)
}

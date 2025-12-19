//go:build linux

package enforcer

import "ztap/pkg/policy"

// EnforceWithEBPFIfAvailable uses the real eBPF enforcer on Linux.
func EnforceWithEBPFIfAvailable(policies []policy.NetworkPolicy, cgroupPath string) error {
	return EnforceWithEBPFReal(policies, cgroupPath)
}

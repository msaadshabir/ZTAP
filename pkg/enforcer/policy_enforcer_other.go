//go:build !linux

package enforcer

import "ztap/pkg/policy"

// EnforceWithEBPFIfAvailable is a no-op on non-Linux platforms.
func EnforceWithEBPFIfAvailable(opts EnforcementOptions) error {
	// eBPF not available on non-Linux platforms
	EnforceWithEBPF(opts)
	return nil
}

// EnforceWithEBPFIfAvailableScoped is a no-op on non-Linux platforms.
func EnforceWithEBPFIfAvailableScoped(opts ScopedEnforcementOptions) error {
	flattened := make([]policy.NetworkPolicy, 0, len(opts.Policies))
	for _, sp := range opts.Policies {
		flattened = append(flattened, sp.Policy)
	}
	EnforceWithEBPF(EnforcementOptions{Policies: flattened, DryRun: opts.DryRun})
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

//go:build linux

package enforcer

import (
	"os"

	"ztap/pkg/logging"
	"ztap/pkg/policy"
)

var activeIptablesEnforcer *IptablesEnforcer

// EnforceWithEBPFIfAvailable uses the best available enforcer on Linux (eBPF or iptables).
func EnforceWithEBPFIfAvailable(opts EnforcementOptions) error {
	if CanUseEBPF() {
		if opts.DryRun {
			logging.Info("[DRY-RUN] Enforcing via eBPF (Linux)...", nil)
		} else {
			logging.Info("Enforcing via eBPF (Linux)...", nil)
		}
		return EnforceWithEBPFReal(opts)
	}

	if opts.DryRun {
		logging.Info("[DRY-RUN] Enforcing via iptables fallback (Linux)...", nil)
	} else {
		logging.Info("Enforcing via iptables fallback (Linux)...", nil)
	}
	activeIptablesEnforcer = NewIptablesEnforcer()
	if err := activeIptablesEnforcer.Init(); err != nil {
		return err
	}
	activeIptablesEnforcer.dryRun = opts.DryRun
	return activeIptablesEnforcer.LoadPolicies(opts.Policies)
}

// EnforceWithEBPFIfAvailableScoped enforces a tenant-aware policy set.
//
// If eBPF isn't available, falls back to iptables, but tenant/cgroup isolation
// is not enforced in that mode.
func EnforceWithEBPFIfAvailableScoped(opts ScopedEnforcementOptions) error {
	flattened := make([]policy.NetworkPolicy, 0, len(opts.Policies))
	for _, sp := range opts.Policies {
		flattened = append(flattened, sp.Policy)
	}

	if CanUseEBPF() {
		if opts.DryRun {
			logging.Info("[DRY-RUN] Enforcing via eBPF (Linux, tenant-scoped)...", nil)
		} else {
			logging.Info("Enforcing via eBPF (Linux, tenant-scoped)...", nil)
		}
		return EnforceWithEBPFRealScoped(opts)
	}

	logging.Warn("eBPF not available; falling back to iptables (tenant isolation not guaranteed)", nil)
	activeIptablesEnforcer = NewIptablesEnforcer()
	if err := activeIptablesEnforcer.Init(); err != nil {
		return err
	}
	activeIptablesEnforcer.dryRun = opts.DryRun
	return activeIptablesEnforcer.LoadPolicies(flattened)
}

// StopLinuxEnforcement stops whichever linux enforcer is currently active.
func StopLinuxEnforcement() error {
	if activeIptablesEnforcer != nil {
		err := activeIptablesEnforcer.Cleanup()
		activeIptablesEnforcer = nil
		return err
	}
	return StopEBPFEnforcement()
}

// CanUseEBPF returns true if the current environment supports eBPF enforcement.
func CanUseEBPF() bool {
	if os.Getenv("ZTAP_FORCE_IPTABLES") == "1" {
		logging.Warn("ZTAP_FORCE_IPTABLES is set, forcing iptables fallback", nil)
		return false
	}

	// Check for BPF filesystem
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return false
	}

	return true
}

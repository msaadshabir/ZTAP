//go:build linux

package enforcer

import (
	"log"
	"os"
)

var activeIptablesEnforcer *IptablesEnforcer

// EnforceWithEBPFIfAvailable uses the best available enforcer on Linux (eBPF or iptables).
func EnforceWithEBPFIfAvailable(opts EnforcementOptions) error {
	if CanUseEBPF() {
		if opts.DryRun {
			log.Println("[DRY-RUN] Enforcing via eBPF (Linux)...")
		} else {
			log.Println("Enforcing via eBPF (Linux)...")
		}
		return EnforceWithEBPFReal(opts)
	}

	if opts.DryRun {
		log.Println("[DRY-RUN] Enforcing via iptables fallback (Linux)...")
	} else {
		log.Println("Enforcing via iptables fallback (Linux)...")
	}
	activeIptablesEnforcer = NewIptablesEnforcer()
	if err := activeIptablesEnforcer.Init(); err != nil {
		return err
	}
	activeIptablesEnforcer.dryRun = opts.DryRun
	return activeIptablesEnforcer.LoadPolicies(opts.Policies)
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
		log.Println("ZTAP_FORCE_IPTABLES is set, forcing iptables fallback")
		return false
	}

	// Check for BPF filesystem
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return false
	}

	return true
}

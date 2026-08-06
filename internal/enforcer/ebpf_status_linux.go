//go:build linux

package enforcer

// IsEBPFEnforcementActive reports whether eBPF enforcement is active in this process.
func IsEBPFEnforcementActive() bool {
	activeEBPFMu.Lock()
	defer activeEBPFMu.Unlock()
	return activeEBPFEnforcer != nil
}

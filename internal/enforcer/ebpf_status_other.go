//go:build !linux

package enforcer

// IsEBPFEnforcementActive reports whether eBPF enforcement is active in this process.
func IsEBPFEnforcementActive() bool {
	return false
}

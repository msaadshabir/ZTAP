//go:build !linux

package enforcer

// StopEBPFEnforcement is a no-op on non-Linux platforms.
func StopEBPFEnforcement() error {
	return nil
}

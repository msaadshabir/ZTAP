//go:build !windows

package enforcer

import "errors"

// EnforceWithWFP is unavailable on non-Windows platforms.
func EnforceWithWFP(_ EnforcementOptions) error {
	return errors.New("wfp enforcement is only supported on windows")
}

// StopWFPEnforcement is unavailable on non-Windows platforms.
func StopWFPEnforcement() error {
	return errors.New("wfp enforcement is only supported on windows")
}

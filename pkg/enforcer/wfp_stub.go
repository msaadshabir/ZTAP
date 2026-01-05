//go:build !windows

package enforcer

import (
	"fmt"
	"ztap/pkg/policy"
)

// EnforceWithWFP is unavailable on non-Windows platforms.
func EnforceWithWFP(_ []policy.NetworkPolicy) error {
	return fmt.Errorf("wfp enforcement is only supported on windows")
}

// StopWFPEnforcement is unavailable on non-Windows platforms.
func StopWFPEnforcement() error {
	return fmt.Errorf("wfp enforcement is only supported on windows")
}

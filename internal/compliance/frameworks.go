package compliance

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	rePCIDSS = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
	reSOC2   = regexp.MustCompile(`^[A-Z]{1,3}[0-9]+(\.[0-9]+)?$`)
	// HIPAA Security Rule citations can be nested like 164.308(a)(1)(ii)(A)
	reHIPAA = regexp.MustCompile(`^164\.[0-9]{3}(\([A-Za-z0-9]+\))*$`)
)

func KnownFrameworks() []FrameworkID {
	return []FrameworkID{FrameworkPCIDSS, FrameworkSOC2, FrameworkHIPAA}
}

func ParseFrameworkID(s string) (FrameworkID, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "", false
	}
	switch FrameworkID(s) {
	case FrameworkPCIDSS, FrameworkSOC2, FrameworkHIPAA:
		return FrameworkID(s), true
	default:
		return "", false
	}
}

func ValidateControlID(framework FrameworkID, controlID string) error {
	controlID = strings.TrimSpace(controlID)
	if controlID == "" {
		return errors.New("control id is empty")
	}

	switch framework {
	case FrameworkPCIDSS:
		if !rePCIDSS.MatchString(controlID) {
			return fmt.Errorf("invalid pci-dss control id %q", controlID)
		}
		return nil
	case FrameworkSOC2:
		if !reSOC2.MatchString(controlID) {
			return fmt.Errorf("invalid soc2 control id %q", controlID)
		}
		return nil
	case FrameworkHIPAA:
		if !reHIPAA.MatchString(controlID) {
			return fmt.Errorf("invalid hipaa control id %q", controlID)
		}
		return nil
	default:
		return fmt.Errorf("unknown framework %q", framework)
	}
}

package enforcer

import (
	"fmt"
	"net"

	"ztap/pkg/policy"
)

// ValidatePoliciesForLinux enforces the current Linux enforcement constraints.
// It returns a descriptive error when the policy cannot be enforced safely.
func ValidatePoliciesForLinux(policies []policy.NetworkPolicy) error {
	for _, p := range policies {
		for i, egress := range p.Spec.Egress {
			if len(egress.To.PodSelector.MatchLabels) > 0 {
				return fmt.Errorf("policy %s spec.egress[%d]: podSelector is not supported by enforcer yet (resolved labels should be used)", p.Metadata.Name, i)
			}
			if egress.To.IPBlock.CIDR != "" {
				_, _, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
				if err != nil {
					return fmt.Errorf("policy %s spec.egress[%d].to.ipBlock.cidr: %w", p.Metadata.Name, i, err)
				}
			}
		}

		for i, ingress := range p.Spec.Ingress {
			if len(ingress.From.PodSelector.MatchLabels) > 0 {
				return fmt.Errorf("policy %s spec.ingress[%d]: podSelector is not supported by enforcer yet", p.Metadata.Name, i)
			}
			if ingress.From.IPBlock.CIDR != "" {
				_, _, err := net.ParseCIDR(ingress.From.IPBlock.CIDR)
				if err != nil {
					return fmt.Errorf("policy %s spec.ingress[%d].from.ipBlock.cidr: %w", p.Metadata.Name, i, err)
				}
			}
		}
	}

	return nil
}

// ValidatePoliciesForEBPF is kept for compatibility with callers that expect
// an eBPF-specific validation entrypoint. It mirrors the Linux validation
// logic, which already enforces the eBPF constraints when applicable.
func ValidatePoliciesForEBPF(policies []policy.NetworkPolicy) error {
	return ValidatePoliciesForLinux(policies)
}

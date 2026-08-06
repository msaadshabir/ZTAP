package enforcer

import (
	"fmt"
	"net"

	"ztap/internal/policy"
)

// ValidatePoliciesForLinux enforces the current Linux enforcement constraints.
// It returns a descriptive error when the policy cannot be enforced safely.
func ValidatePoliciesForLinux(policies []policy.NetworkPolicy) error {
	for _, p := range policies {
		for i, egress := range p.Spec.Egress {
			if selectorHasData(egress.To.PodSelector) || selectorHasData(egress.To.NamespaceSelector) {
				return fmt.Errorf("policy %s spec.egress[%d]: selectors are not supported by enforcer yet (resolved labels should be used)", p.Metadata.Name, i)
			}
			if egress.To.IPBlock.CIDR != "" {
				_, _, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
				if err != nil {
					return fmt.Errorf("policy %s spec.egress[%d].to.ipBlock.cidr: %w", p.Metadata.Name, i, err)
				}
			}
			for j, port := range egress.Ports {
				if port.PortName != "" {
					return fmt.Errorf("policy %s spec.egress[%d].ports[%d].port: named ports must be resolved before enforcement", p.Metadata.Name, i, j)
				}
			}
		}

		for i, ingress := range p.Spec.Ingress {
			if selectorHasData(ingress.From.PodSelector) || selectorHasData(ingress.From.NamespaceSelector) {
				return fmt.Errorf("policy %s spec.ingress[%d]: selectors are not supported by enforcer yet", p.Metadata.Name, i)
			}
			if ingress.From.IPBlock.CIDR != "" {
				_, _, err := net.ParseCIDR(ingress.From.IPBlock.CIDR)
				if err != nil {
					return fmt.Errorf("policy %s spec.ingress[%d].from.ipBlock.cidr: %w", p.Metadata.Name, i, err)
				}
			}
			for j, port := range ingress.Ports {
				if port.PortName != "" {
					return fmt.Errorf("policy %s spec.ingress[%d].ports[%d].port: ingress named ports require subject-scoped enforcement", p.Metadata.Name, i, j)
				}
			}
		}
	}

	return nil
}

func selectorHasData(selector policy.PodSelectorSpec) bool {
	return len(selector.MatchLabels) > 0 || len(selector.MatchExpressions) > 0
}

// ValidatePoliciesForEBPF is kept for compatibility with callers that expect
// an eBPF-specific validation entrypoint. It mirrors the Linux validation
// logic, which already enforces the eBPF constraints when applicable.
func ValidatePoliciesForEBPF(policies []policy.NetworkPolicy) error {
	return ValidatePoliciesForLinux(policies)
}

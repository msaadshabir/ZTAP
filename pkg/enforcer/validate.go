package enforcer

import (
	"fmt"
	"net"

	"ztap/pkg/policy"
)

// ValidatePoliciesForLinux enforces the current Linux enforcement constraints.
// It returns a descriptive error when the policy cannot be enforced safely.
func ValidatePoliciesForLinux(policies []policy.NetworkPolicy) error {
	useEBPF := CanUseEBPF()

	for _, p := range policies {
		for i, egress := range p.Spec.Egress {
			if len(egress.To.PodSelector.MatchLabels) > 0 {
				return fmt.Errorf("policy %s spec.egress[%d]: podSelector is not supported by enforcer yet (resolved labels should be used)", p.Metadata.Name, i)
			}
			if egress.To.IPBlock.CIDR != "" {
				ip, ipnet, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
				if err != nil {
					return fmt.Errorf("policy %s spec.egress[%d].to.ipBlock.cidr: %w", p.Metadata.Name, i, err)
				}
				if ip.To4() == nil {
					return fmt.Errorf("policy %s spec.egress[%d].to.ipBlock.cidr: only IPv4 is supported by enforcer yet", p.Metadata.Name, i)
				}

				if useEBPF {
					ones, bits := ipnet.Mask.Size()
					if bits != 32 || ones != 32 {
						return fmt.Errorf("policy %s spec.egress[%d].to.ipBlock.cidr: only /32 is supported by eBPF enforcer yet", p.Metadata.Name, i)
					}
				}
			}
			for j, port := range egress.Ports {
				if useEBPF && port.Protocol == "ICMP" {
					return fmt.Errorf("policy %s spec.egress[%d].ports[%d]: ICMP is not supported by eBPF enforcer yet", p.Metadata.Name, i, j)
				}
			}
		}

		for i, ingress := range p.Spec.Ingress {
			if len(ingress.From.PodSelector.MatchLabels) > 0 {
				return fmt.Errorf("policy %s spec.ingress[%d]: podSelector is not supported by enforcer yet", p.Metadata.Name, i)
			}
			if ingress.From.IPBlock.CIDR != "" {
				ip, ipnet, err := net.ParseCIDR(ingress.From.IPBlock.CIDR)
				if err != nil {
					return fmt.Errorf("policy %s spec.ingress[%d].from.ipBlock.cidr: %w", p.Metadata.Name, i, err)
				}
				if ip.To4() == nil {
					return fmt.Errorf("policy %s spec.ingress[%d].from.ipBlock.cidr: only IPv4 is supported by enforcer yet", p.Metadata.Name, i)
				}

				if useEBPF {
					ones, bits := ipnet.Mask.Size()
					if bits != 32 || ones != 32 {
						return fmt.Errorf("policy %s spec.ingress[%d].from.ipBlock.cidr: only /32 is supported by eBPF enforcer yet", p.Metadata.Name, i)
					}
				}
			}
			for j, port := range ingress.Ports {
				if useEBPF && port.Protocol == "ICMP" {
					return fmt.Errorf("policy %s spec.ingress[%d].ports[%d]: ICMP is not supported by eBPF enforcer yet", p.Metadata.Name, i, j)
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

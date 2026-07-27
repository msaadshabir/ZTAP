package enforcer

import (
	"slices"
	"strings"

	"ztap/pkg/policy"
)

func policyHasIngressNamedPorts(p policy.NetworkPolicy) bool {
	for _, ingress := range p.Spec.Ingress {
		for _, port := range ingress.Ports {
			if strings.TrimSpace(port.PortName) != "" {
				return true
			}
		}
	}
	return false
}

func resolveIngressNamedPorts(p policy.NetworkPolicy, portMap map[string]int) (policy.NetworkPolicy, []string) {
	if !policyHasIngressNamedPorts(p) {
		return p, nil
	}
	resolved := p
	resolved.Spec.Ingress = nil
	missingSet := make(map[string]struct{})
	for _, ingress := range p.Spec.Ingress {
		resolvedPorts, missing := policy.ResolveNamedPorts(ingress.Ports, portMap)
		for _, name := range missing {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			missingSet[name] = struct{}{}
		}
		if len(resolvedPorts) == 0 {
			continue
		}
		next := ingress
		next.Ports = resolvedPorts
		resolved.Spec.Ingress = append(resolved.Spec.Ingress, next)
	}
	missing := make([]string, 0, len(missingSet))
	for name := range missingSet {
		missing = append(missing, name)
	}
	slices.Sort(missing)
	return resolved, missing
}

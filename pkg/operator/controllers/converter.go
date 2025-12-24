package controllers

import (
	"ztap/pkg/operator/api/v1alpha1"
	"ztap/pkg/policy"
)

// ToInternalPolicy converts a ZtapNetworkPolicy CRD to the internal NetworkPolicy type.
func ToInternalPolicy(ztnp *v1alpha1.ZtapNetworkPolicy) policy.NetworkPolicy {
	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name: ztnp.Name,
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{
				MatchLabels: ztnp.Spec.PodSelector.MatchLabels,
			},
		},
	}

	// Convert Egress rules
	if len(ztnp.Spec.Egress) > 0 {
		p.Spec.Egress = make([]policy.EgressRule, len(ztnp.Spec.Egress))
		for i, e := range ztnp.Spec.Egress {
			p.Spec.Egress[i] = policy.EgressRule{
				To:    convertEgressTarget(e.To),
				Ports: convertPorts(e.Ports),
			}
		}
	}

	// Convert Ingress rules
	if len(ztnp.Spec.Ingress) > 0 {
		p.Spec.Ingress = make([]policy.IngressRule, len(ztnp.Spec.Ingress))
		for i, in := range ztnp.Spec.Ingress {
			p.Spec.Ingress[i] = policy.IngressRule{
				From:  convertIngressSource(in.From),
				Ports: convertPorts(in.Ports),
			}
		}
	}

	return p
}

func convertEgressTarget(t v1alpha1.EgressTarget) policy.EgressTarget {
	target := policy.EgressTarget{}
	if t.PodSelector != nil {
		target.PodSelector = policy.PodSelectorSpec{
			MatchLabels: t.PodSelector.MatchLabels,
		}
	}
	if t.IPBlock != nil {
		target.IPBlock = policy.IPBlockSpec{
			CIDR: t.IPBlock.CIDR,
		}
	}
	return target
}

func convertIngressSource(s v1alpha1.IngressSource) policy.IngressSource {
	source := policy.IngressSource{}
	if s.PodSelector != nil {
		source.PodSelector = policy.PodSelectorSpec{
			MatchLabels: s.PodSelector.MatchLabels,
		}
	}
	if s.IPBlock != nil {
		source.IPBlock = policy.IPBlockSpec{
			CIDR: s.IPBlock.CIDR,
		}
	}
	return source
}

func convertPorts(ports []v1alpha1.PortSpec) []policy.PortSpec {
	if len(ports) == 0 {
		return nil
	}
	res := make([]policy.PortSpec, len(ports))
	for i, p := range ports {
		res[i] = policy.PortSpec{
			Protocol: p.Protocol,
			Port:     p.Port,
		}
	}
	return res
}

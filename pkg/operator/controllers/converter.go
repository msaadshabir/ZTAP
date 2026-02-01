package controllers

import (
	"strings"

	"ztap/pkg/operator/api/v1alpha1"
	"ztap/pkg/policy"
)

const complianceAnnotationPrefix = "ztap.io/compliance."

// ToInternalPolicy converts a ZtapNetworkPolicy CRD to the internal NetworkPolicy type.
func ToInternalPolicy(ztnp *v1alpha1.ZtapNetworkPolicy) policy.NetworkPolicy {
	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name:        ztnp.Name,
			Annotations: filterComplianceAnnotations(ztnp.Annotations),
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{
				MatchLabels:      ztnp.Spec.PodSelector.MatchLabels,
				MatchExpressions: convertMatchExpressions(ztnp.Spec.PodSelector.MatchExpressions),
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

func filterComplianceAnnotations(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range in {
		if strings.HasPrefix(k, complianceAnnotationPrefix) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertEgressTarget(t v1alpha1.EgressTarget) policy.EgressTarget {
	target := policy.EgressTarget{}
	if t.PodSelector != nil {
		target.PodSelector = policy.PodSelectorSpec{
			MatchLabels:      t.PodSelector.MatchLabels,
			MatchExpressions: convertMatchExpressions(t.PodSelector.MatchExpressions),
		}
	}
	if t.NamespaceSelector != nil {
		target.NamespaceSelector = policy.PodSelectorSpec{
			MatchLabels:      t.NamespaceSelector.MatchLabels,
			MatchExpressions: convertMatchExpressions(t.NamespaceSelector.MatchExpressions),
		}
	}
	if t.IPBlock != nil {
		target.IPBlock = policy.IPBlockSpec{
			CIDR:   t.IPBlock.CIDR,
			Except: append([]string(nil), t.IPBlock.Except...),
		}
	}
	return target
}

func convertIngressSource(s v1alpha1.IngressSource) policy.IngressSource {
	source := policy.IngressSource{}
	if s.PodSelector != nil {
		source.PodSelector = policy.PodSelectorSpec{
			MatchLabels:      s.PodSelector.MatchLabels,
			MatchExpressions: convertMatchExpressions(s.PodSelector.MatchExpressions),
		}
	}
	if s.NamespaceSelector != nil {
		source.NamespaceSelector = policy.PodSelectorSpec{
			MatchLabels:      s.NamespaceSelector.MatchLabels,
			MatchExpressions: convertMatchExpressions(s.NamespaceSelector.MatchExpressions),
		}
	}
	if s.IPBlock != nil {
		source.IPBlock = policy.IPBlockSpec{
			CIDR:   s.IPBlock.CIDR,
			Except: append([]string(nil), s.IPBlock.Except...),
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
			PortName: p.PortName,
			EndPort:  p.EndPort,
		}
	}
	return res
}

func convertMatchExpressions(exprs []v1alpha1.LabelSelectorRequirement) []policy.LabelSelectorRequirement {
	if len(exprs) == 0 {
		return nil
	}
	out := make([]policy.LabelSelectorRequirement, len(exprs))
	for i, expr := range exprs {
		out[i] = policy.LabelSelectorRequirement{Key: expr.Key, Operator: expr.Operator, Values: append([]string(nil), expr.Values...)}
	}
	return out
}

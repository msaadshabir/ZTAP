package policy

import "testing"

func TestNormalizePolicies_ExpandsExcept(t *testing.T) {
	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "p"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []EgressRule{
					{
						To:    EgressTarget{IPBlock: IPBlockSpec{CIDR: "10.0.0.0/30", Except: []string{"10.0.0.0/31"}}},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
	}

	normalized, err := NormalizePolicies(policies)
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}
	if len(normalized) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(normalized))
	}
	if len(normalized[0].Spec.Egress) != 1 {
		t.Fatalf("expected 1 egress rule, got %d", len(normalized[0].Spec.Egress))
	}
	if got := normalized[0].Spec.Egress[0].To.IPBlock.CIDR; got != "10.0.0.2/31" {
		t.Fatalf("expected 10.0.0.2/31, got %s", got)
	}
}

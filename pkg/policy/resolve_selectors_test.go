package policy

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

type mockResolverDiscovery struct {
	responses map[string][]string
}

func (m *mockResolverDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	key := fmt.Sprintf("%v", labels)
	ips, ok := m.responses[key]
	if !ok {
		return nil, fmt.Errorf("no IPs found for labels %v", labels)
	}
	return ips, nil
}

func (m *mockResolverDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return nil
}

func (m *mockResolverDiscovery) DeregisterService(name string) error {
	return nil
}

func (m *mockResolverDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, nil
}

func (m *mockResolverDiscovery) Stop() error {
	return nil
}

func TestResolvePodSelectorsToIPBlocks(t *testing.T) {
	disc := &mockResolverDiscovery{
		responses: map[string][]string{
			"map[app:web]": {"10.0.0.1", "10.0.0.2"},
			"map[app:db]":  {"10.0.0.10"},
		},
	}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "web-to-db"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "db"}},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 5432}},
					},
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "1.1.1.1/32"},
						},
						Ports: []PortSpec{{Protocol: "UDP", Port: 53}},
					},
				},
			},
		},
	}

	resolved, err := resolver.ResolvePodSelectorsToIPBlocks(policies)
	if err != nil {
		t.Fatalf("ResolvePodSelectorsToIPBlocks failed: %v", err)
	}

	if len(resolved) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(resolved))
	}

	p := resolved[0]
	if len(p.Spec.Egress) != 2 {
		t.Fatalf("Expected 2 egress rules, got %d", len(p.Spec.Egress))
	}

	// Rule 1: Resolved from podSelector
	if p.Spec.Egress[0].To.IPBlock.CIDR != "10.0.0.10/32" {
		t.Errorf("Expected 10.0.0.10/32, got %s", p.Spec.Egress[0].To.IPBlock.CIDR)
	}
	if len(p.Spec.Egress[0].To.PodSelector.MatchLabels) != 0 {
		t.Error("Expected podSelector to be cleared")
	}

	// Rule 2: Preserved ipBlock
	if p.Spec.Egress[1].To.IPBlock.CIDR != "1.1.1.1/32" {
		t.Errorf("Expected 1.1.1.1/32, got %s", p.Spec.Egress[1].To.IPBlock.CIDR)
	}
}

func TestResolvePodSelectorsToIPBlocks_MultipleIPs(t *testing.T) {
	disc := &mockResolverDiscovery{
		responses: map[string][]string{
			"map[app:web]": {"10.0.0.1", "10.0.0.2"},
		},
	}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "ingress-test"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "lb"}},
				Ingress: []IngressRule{
					{
						From: IngressSource{
							PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 80}},
					},
				},
			},
		},
	}

	resolved, err := resolver.ResolvePodSelectorsToIPBlocks(policies)
	if err != nil {
		t.Fatalf("ResolvePodSelectorsToIPBlocks failed: %v", err)
	}

	p := resolved[0]
	if len(p.Spec.Ingress) != 2 {
		t.Fatalf("Expected 2 ingress rules (one for each IP), got %d", len(p.Spec.Ingress))
	}

	expectedIPs := []string{"10.0.0.1/32", "10.0.0.2/32"}
	actualIPs := []string{p.Spec.Ingress[0].From.IPBlock.CIDR, p.Spec.Ingress[1].From.IPBlock.CIDR}

	if !reflect.DeepEqual(expectedIPs, actualIPs) {
		t.Errorf("Expected %v, got %v", expectedIPs, actualIPs)
	}
}

func TestResolvePodSelectorsToIPBlocks_Error(t *testing.T) {
	disc := &mockResolverDiscovery{
		responses: map[string][]string{},
	}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "fail-test"},
			Spec: NetworkPolicySpec{
				Egress: []EgressRule{
					{
						To: EgressTarget{
							PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "missing"}},
						},
					},
				},
			},
		},
	}

	_, err := resolver.ResolvePodSelectorsToIPBlocks(policies)
	if err == nil {
		t.Error("Expected error for missing resolution, got nil")
	}
}

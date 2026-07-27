package policy

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
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

type mockSelectorDiscovery struct {
	responses map[string][]string
}

func (m *mockSelectorDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	key := SelectorKey(labels)
	if ips, ok := m.responses[key]; ok {
		return ips, nil
	}
	return nil, noMatchesErr{labels: labels}
}

func (m *mockSelectorDiscovery) ResolveSelector(selector PodSelectorSpec) ([]string, error) {
	key := SelectorKeySpec(selector)
	if ips, ok := m.responses[key]; ok {
		return ips, nil
	}
	return nil, noMatchesErr{labels: selector.MatchLabels}
}

func (m *mockSelectorDiscovery) ResolveSelectorScoped(scope string, selector PodSelectorSpec) ([]string, error) {
	return m.ResolveSelector(selector)
}

func (m *mockSelectorDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return nil
}

func (m *mockSelectorDiscovery) DeregisterService(name string) error {
	return nil
}

func (m *mockSelectorDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, nil
}

func (m *mockSelectorDiscovery) Stop() error {
	return nil
}

type mockNamespaceDiscovery struct {
	namespaces map[string][]string
	scoped     map[string]map[string][]string
}

func (m *mockNamespaceDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	return nil, fmt.Errorf("unscoped lookup not supported")
}

func (m *mockNamespaceDiscovery) ResolveLabelsScoped(scope string, labels map[string]string) ([]string, error) {
	key := SelectorKey(labels)
	if byScope, ok := m.scoped[scope]; ok {
		if ips, ok := byScope[key]; ok {
			return ips, nil
		}
	}
	return nil, noMatchesErr{labels: labels}
}

func (m *mockNamespaceDiscovery) ResolveNamespaces(selector PodSelectorSpec) ([]string, error) {
	key := SelectorKeySpec(selector)
	if namespaces, ok := m.namespaces[key]; ok {
		return namespaces, nil
	}
	return nil, noMatchesErr{labels: selector.MatchLabels}
}

func (m *mockNamespaceDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return nil
}

func (m *mockNamespaceDiscovery) DeregisterService(name string) error {
	return nil
}

func (m *mockNamespaceDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, nil
}

func (m *mockNamespaceDiscovery) WatchScoped(ctx context.Context, scope string, labels map[string]string) (<-chan []string, error) {
	return nil, nil
}

func (m *mockNamespaceDiscovery) Stop() error {
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

type noMatchesErr struct {
	labels map[string]string
}

func (e noMatchesErr) Error() string {
	return fmt.Sprintf("no matches for labels %v", e.labels)
}

func (e noMatchesErr) NoMatches() bool {
	return true
}

type mockNoMatchesDiscovery struct {
	responses map[string][]string
}

func (m *mockNoMatchesDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	key := fmt.Sprintf("%v", labels)
	if ips, ok := m.responses[key]; ok {
		return ips, nil
	}
	return nil, noMatchesErr{labels: labels}
}

func (m *mockNoMatchesDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return nil
}

func (m *mockNoMatchesDiscovery) DeregisterService(name string) error {
	return nil
}

func (m *mockNoMatchesDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, nil
}

func (m *mockNoMatchesDiscovery) Stop() error {
	return nil
}

func TestResolvePodSelectorsToIPBlocks_NoMatchesIsEmpty(t *testing.T) {
	disc := &mockNoMatchesDiscovery{responses: map[string][]string{}}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "no-match"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []EgressRule{
					{
						To:    EgressTarget{PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "missing"}}},
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
	if len(resolved) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(resolved))
	}
	if len(resolved[0].Spec.Egress) != 0 {
		t.Fatalf("Expected selector-only egress to be removed, got %d rules", len(resolved[0].Spec.Egress))
	}
}

func TestResolvePodSelectorsToIPBlocks_IPv6(t *testing.T) {
	disc := &mockNoMatchesDiscovery{
		responses: map[string][]string{
			"map[app:db]": {"2001:db8::1"},
		},
	}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "v6"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []EgressRule{
					{
						To:    EgressTarget{PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "db"}}},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
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
	if len(p.Spec.Egress) != 1 {
		t.Fatalf("Expected 1 egress rule, got %d", len(p.Spec.Egress))
	}
	if p.Spec.Egress[0].To.IPBlock.CIDR != "2001:db8::1/128" {
		t.Fatalf("Expected 2001:db8::1/128, got %s", p.Spec.Egress[0].To.IPBlock.CIDR)
	}
}

func TestResolvePodSelectorsToIPBlocks_DedupAndSort(t *testing.T) {
	disc := &mockNoMatchesDiscovery{
		responses: map[string][]string{
			"map[app:web]": {"10.0.0.2", "10.0.0.1", "10.0.0.2"},
		},
	}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "sort"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "lb"}},
				Ingress: []IngressRule{
					{
						From:  IngressSource{PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}}},
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
		t.Fatalf("Expected 2 ingress rules after dedupe, got %d", len(p.Spec.Ingress))
	}
	expected := []string{"10.0.0.1/32", "10.0.0.2/32"}
	actual := []string{p.Spec.Ingress[0].From.IPBlock.CIDR, p.Spec.Ingress[1].From.IPBlock.CIDR}
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Expected %v, got %v", expected, actual)
	}
}

func TestResolvePodSelectorsToIPBlocks_MatchExpressions(t *testing.T) {
	selector := PodSelectorSpec{
		MatchExpressions: []LabelSelectorRequirement{{Key: "app", Operator: "In", Values: []string{"web"}}},
	}
	key := SelectorKeySpec(selector)
	disc := &mockSelectorDiscovery{
		responses: map[string][]string{key: {"10.0.0.3"}},
	}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "expr"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "lb"}},
				Egress: []EgressRule{
					{
						To:    EgressTarget{PodSelector: selector},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
	}

	resolved, err := resolver.ResolvePodSelectorsToIPBlocks(policies)
	if err != nil {
		t.Fatalf("ResolvePodSelectorsToIPBlocks failed: %v", err)
	}
	if got := resolved[0].Spec.Egress[0].To.IPBlock.CIDR; got != "10.0.0.3/32" {
		t.Fatalf("expected resolved CIDR 10.0.0.3/32, got %s", got)
	}
}

func TestResolvePodSelectorsToIPBlocks_NamespaceSelector(t *testing.T) {
	selector := PodSelectorSpec{MatchLabels: map[string]string{"app": "db"}}
	nsSelector := PodSelectorSpec{MatchLabels: map[string]string{"team": "payments"}}
	key := SelectorKey(selector.MatchLabels)
	nsKey := SelectorKeySpec(nsSelector)
	disc := &mockNamespaceDiscovery{
		namespaces: map[string][]string{nsKey: {"ns-a", "ns-b"}},
		scoped: map[string]map[string][]string{
			"ns-a": {key: {"10.0.0.10"}},
			"ns-b": {key: {"10.0.0.11"}},
		},
	}
	resolver := NewPolicyResolver(disc)

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "ns"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							PodSelector:       selector,
							NamespaceSelector: nsSelector,
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
	}

	resolved, err := resolver.ResolvePodSelectorsToIPBlocksScoped("default", policies)
	if err != nil {
		t.Fatalf("ResolvePodSelectorsToIPBlocksScoped failed: %v", err)
	}
	if len(resolved) != 1 || len(resolved[0].Spec.Egress) != 2 {
		t.Fatalf("expected 2 egress rules, got %d", len(resolved[0].Spec.Egress))
	}
	got := []string{resolved[0].Spec.Egress[0].To.IPBlock.CIDR, resolved[0].Spec.Egress[1].To.IPBlock.CIDR}
	slices.Sort(got)
	expected := []string{"10.0.0.10/32", "10.0.0.11/32"}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

type mockPodDiscovery struct {
	pods []PodInfo
}

func (m *mockPodDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	return nil, fmt.Errorf("unexpected ResolveLabels call")
}

func (m *mockPodDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return nil
}

func (m *mockPodDiscovery) DeregisterService(name string) error {
	return nil
}

func (m *mockPodDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, nil
}

func (m *mockPodDiscovery) Stop() error {
	return nil
}

func (m *mockPodDiscovery) ResolvePods(selector PodSelectorSpec) ([]PodInfo, error) {
	return m.pods, nil
}

func (m *mockPodDiscovery) ResolvePodsScoped(scope string, selector PodSelectorSpec) ([]PodInfo, error) {
	return m.pods, nil
}

func TestResolvePodSelectorsToIPBlocks_NamedPortEgress(t *testing.T) {
	pods := []PodInfo{
		{IP: "10.0.0.1", Ports: []PodPort{{Name: "http", Port: 8080, Protocol: "TCP"}}},
		{IP: "10.0.0.2", Ports: []PodPort{{Name: "http", Port: 9090, Protocol: "TCP"}}},
		{IP: "10.0.0.3", Ports: []PodPort{{Name: "metrics", Port: 9091, Protocol: "TCP"}}},
	}
	resolver := NewPolicyResolver(&mockPodDiscovery{pods: pods})

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "named-egress"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []EgressRule{
					{
						To:    EgressTarget{PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "api"}}},
						Ports: []PortSpec{{Protocol: "TCP", PortName: "http"}},
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
		t.Fatalf("expected 1 policy, got %d", len(resolved))
	}
	if len(resolved[0].Spec.Egress) != 2 {
		t.Fatalf("expected 2 egress rules, got %d", len(resolved[0].Spec.Egress))
	}

	got := make(map[string]int)
	for _, rule := range resolved[0].Spec.Egress {
		if len(rule.Ports) != 1 {
			t.Fatalf("expected 1 port per rule, got %d", len(rule.Ports))
		}
		if strings.TrimSpace(rule.Ports[0].PortName) != "" {
			t.Fatalf("expected named port to be resolved, got %q", rule.Ports[0].PortName)
		}
		got[rule.To.IPBlock.CIDR] = rule.Ports[0].Port
	}

	expected := map[string]int{"10.0.0.1/32": 8080, "10.0.0.2/32": 9090}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

func TestResolvePodSelectorsToIPBlocks_NamedPortIngress(t *testing.T) {
	pods := []PodInfo{
		{IP: "10.0.0.10", Ports: []PodPort{{Name: "http", Port: 8080, Protocol: "TCP"}}},
		{IP: "10.0.0.11", Ports: []PodPort{{Name: "http", Port: 18080, Protocol: "TCP"}}},
		{IP: "10.0.0.12", Ports: []PodPort{{Name: "metrics", Port: 9091, Protocol: "TCP"}}},
	}
	resolver := NewPolicyResolver(&mockPodDiscovery{pods: pods})

	policies := []NetworkPolicy{
		{
			Metadata: NetworkPolicyMetadata{Name: "named-ingress"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "api"}},
				Ingress: []IngressRule{
					{
						From:  IngressSource{PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}}},
						Ports: []PortSpec{{Protocol: "TCP", PortName: "http"}},
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
		t.Fatalf("expected 1 policy, got %d", len(resolved))
	}
	if len(resolved[0].Spec.Ingress) != 2 {
		t.Fatalf("expected 2 ingress rules, got %d", len(resolved[0].Spec.Ingress))
	}

	got := make(map[string]int)
	for _, rule := range resolved[0].Spec.Ingress {
		if len(rule.Ports) != 1 {
			t.Fatalf("expected 1 port per rule, got %d", len(rule.Ports))
		}
		if strings.TrimSpace(rule.Ports[0].PortName) != "" {
			t.Fatalf("expected named port to be resolved, got %q", rule.Ports[0].PortName)
		}
		got[rule.From.IPBlock.CIDR] = rule.Ports[0].Port
	}

	expected := map[string]int{"10.0.0.10/32": 8080, "10.0.0.11/32": 18080}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

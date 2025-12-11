package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-policy.yaml")

	// Write test policy
	policyContent := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 5432
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	// Load policies
	policies, err := LoadFromFile(policyFile)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]

	// Verify policy fields
	if policy.APIVersion != "ztap/v1" {
		t.Errorf("Expected apiVersion 'ztap/v1', got '%s'", policy.APIVersion)
	}

	if policy.Metadata.Name != "test-policy" {
		t.Errorf("Expected name 'test-policy', got '%s'", policy.Metadata.Name)
	}

	if policy.Spec.PodSelector.MatchLabels["app"] != "web" {
		t.Errorf("Expected app label 'web', got '%s'", policy.Spec.PodSelector.MatchLabels["app"])
	}

	if len(policy.Spec.Egress) != 1 {
		t.Fatalf("Expected 1 egress rule, got %d", len(policy.Spec.Egress))
	}

	egress := policy.Spec.Egress[0]
	if egress.To.IPBlock.CIDR != "10.0.0.0/8" {
		t.Errorf("Expected CIDR '10.0.0.0/8', got '%s'", egress.To.IPBlock.CIDR)
	}

	if len(egress.Ports) != 1 {
		t.Fatalf("Expected 1 port, got %d", len(egress.Ports))
	}

	if egress.Ports[0].Protocol != "TCP" {
		t.Errorf("Expected protocol 'TCP', got '%s'", egress.Ports[0].Protocol)
	}

	if egress.Ports[0].Port != 5432 {
		t.Errorf("Expected port 5432, got %d", egress.Ports[0].Port)
	}
}

func TestLoadFromFileWithIngress(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-ingress-policy.yaml")

	policyContent := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-ingress-policy
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 8080
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	policies, err := LoadFromFile(policyFile)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]

	if len(policy.Spec.Ingress) != 1 {
		t.Fatalf("Expected 1 ingress rule, got %d", len(policy.Spec.Ingress))
	}

	ingress := policy.Spec.Ingress[0]
	if ingress.From.IPBlock.CIDR != "10.0.0.0/8" {
		t.Errorf("Expected CIDR '10.0.0.0/8', got '%s'", ingress.From.IPBlock.CIDR)
	}

	if len(ingress.Ports) != 1 {
		t.Fatalf("Expected 1 port, got %d", len(ingress.Ports))
	}

	if ingress.Ports[0].Protocol != "TCP" {
		t.Errorf("Expected protocol 'TCP', got '%s'", ingress.Ports[0].Protocol)
	}

	if ingress.Ports[0].Port != 8080 {
		t.Errorf("Expected port 8080, got %d", ingress.Ports[0].Port)
	}
}

func TestLoadFromFileWithBidirectional(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-bidirectional-policy.yaml")

	policyContent := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-bidirectional
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 5432
  ingress:
    - from:
        ipBlock:
          cidr: 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	policies, err := LoadFromFile(policyFile)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]

	if len(policy.Spec.Egress) != 1 {
		t.Errorf("Expected 1 egress rule, got %d", len(policy.Spec.Egress))
	}

	if len(policy.Spec.Ingress) != 1 {
		t.Errorf("Expected 1 ingress rule, got %d", len(policy.Spec.Ingress))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		policy      NetworkPolicy
		expectError bool
		errorField  string
	}{
		{
			name: "valid egress policy",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "valid-policy"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []EgressRule{
						{
							To: EgressTarget{
								IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 443},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid ingress policy",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "valid-ingress"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "api"},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								IPBlock: IPBlockSpec{CIDR: "192.168.0.0/16"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 8080},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid bidirectional policy",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "valid-bidirectional"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []EgressRule{
						{
							To: EgressTarget{
								IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 5432},
							},
						},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								IPBlock: IPBlockSpec{CIDR: "192.168.0.0/16"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 443},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid ingress with pod selector",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "ingress-pod-selector"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "db"},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								PodSelector: PodSelectorSpec{
									MatchLabels: map[string]string{"app": "web"},
								},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 5432},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "missing apiVersion",
			policy: NetworkPolicy{
				Kind:     "NetworkPolicy",
				Metadata: NetworkPolicyMetadata{Name: "test"},
			},
			expectError: true,
			errorField:  "apiVersion",
		},
		{
			name: "no egress or ingress rules",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "no-rules"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "web"},
					},
				},
			},
			expectError: true,
			errorField:  "spec",
		},
		{
			name: "invalid egress CIDR",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "invalid-egress-cidr"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []EgressRule{
						{
							To: EgressTarget{
								IPBlock: IPBlockSpec{CIDR: "invalid-cidr"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 443},
							},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.egress[0].to.ipBlock.cidr",
		},
		{
			name: "invalid ingress CIDR",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "invalid-ingress-cidr"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "api"},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								IPBlock: IPBlockSpec{CIDR: "not-a-cidr"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 8080},
							},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.ingress[0].from.ipBlock.cidr",
		},
		{
			name: "invalid egress port",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "invalid-port"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []EgressRule{
						{
							To: EgressTarget{
								IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 99999},
							},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.egress[0].ports[0].port",
		},
		{
			name: "invalid ingress port",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "invalid-ingress-port"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "api"},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								IPBlock: IPBlockSpec{CIDR: "192.168.0.0/16"},
							},
							Ports: []PortSpec{
								{Protocol: "TCP", Port: 0},
							},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.ingress[0].ports[0].port",
		},
		{
			name: "ingress missing from selector",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "missing-from"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "api"},
					},
					Ingress: []IngressRule{
						{
							From:  IngressSource{},
							Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.ingress[0].from",
		},
		{
			name: "ingress both podSelector and ipBlock",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "both-selectors"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "api"},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								PodSelector: PodSelectorSpec{
									MatchLabels: map[string]string{"app": "web"},
								},
								IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
							},
							Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.ingress[0].from",
		},
		{
			name: "ingress missing ports",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "missing-ports"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "api"},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
							},
							Ports: []PortSpec{},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.ingress[0].ports",
		},
		{
			name: "ingress invalid protocol",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "invalid-protocol"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "api"},
					},
					Ingress: []IngressRule{
						{
							From: IngressSource{
								IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
							},
							Ports: []PortSpec{
								{Protocol: "SCTP", Port: 8080},
							},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.ingress[0].ports[0].protocol",
		},
		{
			name: "duplicate egress rule",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata:   NetworkPolicyMetadata{Name: "dupe-egress"},
				Spec: NetworkPolicySpec{
					PodSelector: PodSelectorSpec{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []EgressRule{
						{
							To:    EgressTarget{IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"}},
							Ports: []PortSpec{{Protocol: "TCP", Port: 80}},
						},
						{
							To:    EgressTarget{IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"}},
							Ports: []PortSpec{{Protocol: "TCP", Port: 80}},
						},
					},
				},
			},
			expectError: true,
			errorField:  "spec.egress[1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.expectError && err != nil {
				if ve, ok := err.(ValidationError); ok {
					if tt.errorField != "" && ve.Field != tt.errorField {
						t.Errorf("Expected error field '%s', got '%s'", tt.errorField, ve.Field)
					}
				}
			}
		})
	}
}

func TestPolicyResolver(t *testing.T) {
	// Create mock discovery
	mockDisc := &mockDiscovery{
		services: map[string][]string{
			"app=web":      {"10.0.1.1", "10.0.1.2"},
			"tier=backend": {"10.0.2.1"},
		},
	}

	resolver := NewPolicyResolver(mockDisc)

	// Test successful resolution
	ips, err := resolver.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}

	// Test not found
	_, err = resolver.ResolveLabels(map[string]string{"app": "nonexistent"})
	if err == nil {
		t.Error("Expected error for nonexistent service")
	}
}

// Mock discovery for testing
type mockDiscovery struct {
	services map[string][]string
}

func (m *mockDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	// Simple key generation for testing
	key := ""
	for k, v := range labels {
		if key != "" {
			key += ","
		}
		key += k + "=" + v
	}

	if ips, ok := m.services[key]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no services found")
}

func (m *mockDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return nil
}

func (m *mockDiscovery) DeregisterService(name string) error {
	return nil
}

func (m *mockDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, nil
}

func TestCheckConflicts(t *testing.T) {
	existing := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "existing"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "db"}},
				Egress: []EgressRule{
					{
						To:    EgressTarget{IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"}},
						Ports: []PortSpec{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
	}

	candidate := NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   NetworkPolicyMetadata{Name: "new-policy"},
		Spec: NetworkPolicySpec{
			PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Egress: []EgressRule{
				{
					To:    EgressTarget{IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"}},
					Ports: []PortSpec{{Protocol: "TCP", Port: 5432}},
				},
			},
		},
	}

	if err := CheckConflicts([]NamedPolicy{{PolicyName: "existing", Policy: existing[0]}}, NamedPolicy{PolicyName: "new-policy", Policy: candidate}); err == nil {
		t.Fatal("expected conflict but got none")
	}

	nonConflict := NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata:   NetworkPolicyMetadata{Name: "non-conflict"},
		Spec: NetworkPolicySpec{
			PodSelector: PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Egress: []EgressRule{
				{
					To:    EgressTarget{IPBlock: IPBlockSpec{CIDR: "192.168.0.0/16"}},
					Ports: []PortSpec{{Protocol: "TCP", Port: 80}},
				},
			},
		},
	}

	if err := CheckConflicts([]NamedPolicy{{PolicyName: "existing", Policy: existing[0]}}, NamedPolicy{PolicyName: "non-conflict", Policy: nonConflict}); err != nil {
		t.Fatalf("expected no conflict, got %v", err)
	}
}

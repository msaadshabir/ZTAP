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

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		policy      NetworkPolicy
		expectError bool
	}{
		{
			name: "valid policy",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata: struct {
					Name string `yaml:"name"`
				}{Name: "valid-policy"},
				Spec: struct {
					PodSelector struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					} `yaml:"podSelector"`
					Egress []struct {
						To struct {
							PodSelector struct {
								MatchLabels map[string]string `yaml:"matchLabels"`
							} `yaml:"podSelector,omitempty"`
							IPBlock struct {
								CIDR string `yaml:"cidr"`
							} `yaml:"ipBlock,omitempty"`
						} `yaml:"to"`
						Ports []struct {
							Protocol string `yaml:"protocol"`
							Port     int    `yaml:"port"`
						} `yaml:"ports"`
					} `yaml:"egress"`
				}{
					PodSelector: struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					}{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []struct {
						To struct {
							PodSelector struct {
								MatchLabels map[string]string `yaml:"matchLabels"`
							} `yaml:"podSelector,omitempty"`
							IPBlock struct {
								CIDR string `yaml:"cidr"`
							} `yaml:"ipBlock,omitempty"`
						} `yaml:"to"`
						Ports []struct {
							Protocol string `yaml:"protocol"`
							Port     int    `yaml:"port"`
						} `yaml:"ports"`
					}{
						{
							To: struct {
								PodSelector struct {
									MatchLabels map[string]string `yaml:"matchLabels"`
								} `yaml:"podSelector,omitempty"`
								IPBlock struct {
									CIDR string `yaml:"cidr"`
								} `yaml:"ipBlock,omitempty"`
							}{
								IPBlock: struct {
									CIDR string `yaml:"cidr"`
								}{CIDR: "10.0.0.0/8"},
							},
							Ports: []struct {
								Protocol string `yaml:"protocol"`
								Port     int    `yaml:"port"`
							}{
								{Protocol: "TCP", Port: 443},
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
				Kind: "NetworkPolicy",
				Metadata: struct {
					Name string `yaml:"name"`
				}{Name: "test"},
			},
			expectError: true,
		},
		{
			name: "invalid CIDR",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata: struct {
					Name string `yaml:"name"`
				}{Name: "test"},
				Spec: struct {
					PodSelector struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					} `yaml:"podSelector"`
					Egress []struct {
						To struct {
							PodSelector struct {
								MatchLabels map[string]string `yaml:"matchLabels"`
							} `yaml:"podSelector,omitempty"`
							IPBlock struct {
								CIDR string `yaml:"cidr"`
							} `yaml:"ipBlock,omitempty"`
						} `yaml:"to"`
						Ports []struct {
							Protocol string `yaml:"protocol"`
							Port     int    `yaml:"port"`
						} `yaml:"ports"`
					} `yaml:"egress"`
				}{
					PodSelector: struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					}{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []struct {
						To struct {
							PodSelector struct {
								MatchLabels map[string]string `yaml:"matchLabels"`
							} `yaml:"podSelector,omitempty"`
							IPBlock struct {
								CIDR string `yaml:"cidr"`
							} `yaml:"ipBlock,omitempty"`
						} `yaml:"to"`
						Ports []struct {
							Protocol string `yaml:"protocol"`
							Port     int    `yaml:"port"`
						} `yaml:"ports"`
					}{
						{
							To: struct {
								PodSelector struct {
									MatchLabels map[string]string `yaml:"matchLabels"`
								} `yaml:"podSelector,omitempty"`
								IPBlock struct {
									CIDR string `yaml:"cidr"`
								} `yaml:"ipBlock,omitempty"`
							}{
								IPBlock: struct {
									CIDR string `yaml:"cidr"`
								}{CIDR: "invalid-cidr"},
							},
							Ports: []struct {
								Protocol string `yaml:"protocol"`
								Port     int    `yaml:"port"`
							}{
								{Protocol: "TCP", Port: 443},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid port",
			policy: NetworkPolicy{
				APIVersion: "ztap/v1",
				Kind:       "NetworkPolicy",
				Metadata: struct {
					Name string `yaml:"name"`
				}{Name: "test"},
				Spec: struct {
					PodSelector struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					} `yaml:"podSelector"`
					Egress []struct {
						To struct {
							PodSelector struct {
								MatchLabels map[string]string `yaml:"matchLabels"`
							} `yaml:"podSelector,omitempty"`
							IPBlock struct {
								CIDR string `yaml:"cidr"`
							} `yaml:"ipBlock,omitempty"`
						} `yaml:"to"`
						Ports []struct {
							Protocol string `yaml:"protocol"`
							Port     int    `yaml:"port"`
						} `yaml:"ports"`
					} `yaml:"egress"`
				}{
					PodSelector: struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					}{
						MatchLabels: map[string]string{"app": "web"},
					},
					Egress: []struct {
						To struct {
							PodSelector struct {
								MatchLabels map[string]string `yaml:"matchLabels"`
							} `yaml:"podSelector,omitempty"`
							IPBlock struct {
								CIDR string `yaml:"cidr"`
							} `yaml:"ipBlock,omitempty"`
						} `yaml:"to"`
						Ports []struct {
							Protocol string `yaml:"protocol"`
							Port     int    `yaml:"port"`
						} `yaml:"ports"`
					}{
						{
							To: struct {
								PodSelector struct {
									MatchLabels map[string]string `yaml:"matchLabels"`
								} `yaml:"podSelector,omitempty"`
								IPBlock struct {
									CIDR string `yaml:"cidr"`
								} `yaml:"ipBlock,omitempty"`
							}{
								IPBlock: struct {
									CIDR string `yaml:"cidr"`
								}{CIDR: "10.0.0.0/8"},
							},
							Ports: []struct {
								Protocol string `yaml:"protocol"`
								Port     int    `yaml:"port"`
							}{
								{Protocol: "TCP", Port: 99999},
							},
						},
					},
				},
			},
			expectError: true,
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

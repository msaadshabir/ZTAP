package policy

import (
	"testing"
)

func TestDetectConflicts_NoDuplicateNames(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "api"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "192.168.0.0/16"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 0 {
		t.Errorf("Expected no conflicts, got %d: %v", len(conflicts), conflicts)
	}
}

func TestDetectConflicts_DuplicateNames(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "same-name"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "same-name"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "api"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "192.168.0.0/16"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 1 {
		t.Fatalf("Expected 1 conflict, got %d", len(conflicts))
	}

	if conflicts[0].Type != ConflictDuplicateName {
		t.Errorf("Expected conflict type %s, got %s", ConflictDuplicateName, conflicts[0].Type)
	}
}

func TestDetectConflicts_SameSelectorDifferentPorts(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 1 {
		t.Fatalf("Expected 1 conflict, got %d", len(conflicts))
	}

	if conflicts[0].Type != ConflictSameSelectorRules {
		t.Errorf("Expected conflict type %s, got %s", ConflictSameSelectorRules, conflicts[0].Type)
	}
}

func TestDetectConflicts_OverlappingCIDR(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.1.0/24"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 1 {
		t.Fatalf("Expected 1 conflict, got %d", len(conflicts))
	}

	if conflicts[0].Type != ConflictOverlappingCIDR {
		t.Errorf("Expected conflict type %s, got %s", ConflictOverlappingCIDR, conflicts[0].Type)
	}
}

func TestDetectConflicts_IngressConflict(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "api"},
				},
				Ingress: []IngressRule{
					{
						From: IngressSource{
							IPBlock: IPBlockSpec{CIDR: "192.168.1.0/24"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "api"},
				},
				Ingress: []IngressRule{
					{
						From: IngressSource{
							IPBlock: IPBlockSpec{CIDR: "192.168.1.0/24"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 9090}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 1 {
		t.Fatalf("Expected 1 conflict, got %d", len(conflicts))
	}

	if conflicts[0].Type != ConflictSameSelectorRules {
		t.Errorf("Expected conflict type %s, got %s", ConflictSameSelectorRules, conflicts[0].Type)
	}
}

func TestDetectConflicts_DifferentPodSelectors(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "api"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 0 {
		t.Errorf("Expected no conflicts for different pod selectors, got %d", len(conflicts))
	}
}

func TestDetectConflicts_PodSelectorTargets(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							PodSelector: PodSelectorSpec{
								MatchLabels: map[string]string{"app": "db"},
							},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							PodSelector: PodSelectorSpec{
								MatchLabels: map[string]string{"app": "db"},
							},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 3306}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 1 {
		t.Fatalf("Expected 1 conflict, got %d", len(conflicts))
	}

	if conflicts[0].Type != ConflictSameSelectorRules {
		t.Errorf("Expected conflict type %s, got %s", ConflictSameSelectorRules, conflicts[0].Type)
	}
}

func TestDetectConflicts_SamePolicySamePorts(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) != 0 {
		t.Errorf("Expected no conflicts for identical rules, got %d", len(conflicts))
	}
}

func TestLabelsMatch(t *testing.T) {
	tests := []struct {
		name     string
		labels1  map[string]string
		labels2  map[string]string
		expected bool
	}{
		{
			name:     "identical labels",
			labels1:  map[string]string{"app": "web", "tier": "frontend"},
			labels2:  map[string]string{"app": "web", "tier": "frontend"},
			expected: true,
		},
		{
			name:     "different values",
			labels1:  map[string]string{"app": "web"},
			labels2:  map[string]string{"app": "api"},
			expected: false,
		},
		{
			name:     "different keys",
			labels1:  map[string]string{"app": "web"},
			labels2:  map[string]string{"tier": "frontend"},
			expected: false,
		},
		{
			name:     "different length",
			labels1:  map[string]string{"app": "web"},
			labels2:  map[string]string{"app": "web", "tier": "frontend"},
			expected: false,
		},
		{
			name:     "empty labels",
			labels1:  map[string]string{},
			labels2:  map[string]string{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := labelsMatch(tt.labels1, tt.labels2)
			if result != tt.expected {
				t.Errorf("labelsMatch() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPortsMatch(t *testing.T) {
	tests := []struct {
		name     string
		ports1   []PortSpec
		ports2   []PortSpec
		expected bool
	}{
		{
			name:     "identical ports",
			ports1:   []PortSpec{{Protocol: "TCP", Port: 443}},
			ports2:   []PortSpec{{Protocol: "TCP", Port: 443}},
			expected: true,
		},
		{
			name:     "different ports",
			ports1:   []PortSpec{{Protocol: "TCP", Port: 443}},
			ports2:   []PortSpec{{Protocol: "TCP", Port: 8080}},
			expected: false,
		},
		{
			name:     "different protocols",
			ports1:   []PortSpec{{Protocol: "TCP", Port: 53}},
			ports2:   []PortSpec{{Protocol: "UDP", Port: 53}},
			expected: false,
		},
		{
			name:     "different length",
			ports1:   []PortSpec{{Protocol: "TCP", Port: 443}},
			ports2:   []PortSpec{{Protocol: "TCP", Port: 443}, {Protocol: "TCP", Port: 8080}},
			expected: false,
		},
		{
			name:     "multiple ports same order",
			ports1:   []PortSpec{{Protocol: "TCP", Port: 443}, {Protocol: "TCP", Port: 8080}},
			ports2:   []PortSpec{{Protocol: "TCP", Port: 443}, {Protocol: "TCP", Port: 8080}},
			expected: true,
		},
		{
			name:     "multiple ports different order",
			ports1:   []PortSpec{{Protocol: "TCP", Port: 443}, {Protocol: "TCP", Port: 8080}},
			ports2:   []PortSpec{{Protocol: "TCP", Port: 8080}, {Protocol: "TCP", Port: 443}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := portsMatch(tt.ports1, tt.ports2)
			if result != tt.expected {
				t.Errorf("portsMatch() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestCIDRsOverlap(t *testing.T) {
	tests := []struct {
		name          string
		cidr1         string
		cidr2         string
		expectOverlap bool
		expectError   bool
	}{
		{
			name:          "identical CIDRs",
			cidr1:         "10.0.0.0/8",
			cidr2:         "10.0.0.0/8",
			expectOverlap: true,
			expectError:   false,
		},
		{
			name:          "subnet within larger network",
			cidr1:         "10.0.0.0/8",
			cidr2:         "10.0.1.0/24",
			expectOverlap: true,
			expectError:   false,
		},
		{
			name:          "non-overlapping CIDRs",
			cidr1:         "10.0.0.0/8",
			cidr2:         "192.168.0.0/16",
			expectOverlap: false,
			expectError:   false,
		},
		{
			name:          "invalid CIDR 1",
			cidr1:         "invalid",
			cidr2:         "10.0.0.0/8",
			expectOverlap: false,
			expectError:   true,
		},
		{
			name:          "invalid CIDR 2",
			cidr1:         "10.0.0.0/8",
			cidr2:         "invalid",
			expectOverlap: false,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overlap, err := cidrsOverlap(tt.cidr1, tt.cidr2)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && overlap != tt.expectOverlap {
				t.Errorf("cidrsOverlap() = %v, expected %v", overlap, tt.expectOverlap)
			}
		})
	}
}

func TestDetectConflicts_MultipleConflicts(t *testing.T) {
	policies := []NetworkPolicy{
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy1"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy2"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.0.0/8"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 8080}},
					},
				},
			},
		},
		{
			APIVersion: "ztap/v1",
			Kind:       "NetworkPolicy",
			Metadata:   NetworkPolicyMetadata{Name: "policy3"},
			Spec: NetworkPolicySpec{
				PodSelector: PodSelectorSpec{
					MatchLabels: map[string]string{"app": "web"},
				},
				Egress: []EgressRule{
					{
						To: EgressTarget{
							IPBlock: IPBlockSpec{CIDR: "10.0.1.0/24"},
						},
						Ports: []PortSpec{{Protocol: "TCP", Port: 9090}},
					},
				},
			},
		},
	}

	conflicts := DetectConflicts(policies)
	if len(conflicts) < 2 {
		t.Errorf("Expected at least 2 conflicts, got %d", len(conflicts))
	}
}

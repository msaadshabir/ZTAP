//go:build linux
// +build linux

package enforcer

import (
	"fmt"
	"testing"
	"ztap/pkg/policy"
)

func TestProtocolToNum(t *testing.T) {
	tests := []struct {
		protocol string
		expected uint8
	}{
		{"TCP", 6},
		{"tcp", 6},
		{"UDP", 17},
		{"udp", 17},
		{"ICMP", 1},
		{"icmp", 1},
		{"UNKNOWN", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			result := protocolToNum(tt.protocol)
			if result != tt.expected {
				t.Errorf("protocolToNum(%s) = %d, expected %d", tt.protocol, result, tt.expected)
			}
		})
	}
}

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint32
	}{
		{"10.0.0.1", 0x0A000001},
		{"192.168.1.1", 0xC0A80101},
		{"172.16.0.1", 0xAC100001},
		{"127.0.0.1", 0x7F000001},
		{"255.255.255.255", 0xFFFFFFFF},
		{"0.0.0.0", 0x00000000},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := parseIP(tt.ip)
			result := ipToUint32(ip)
			if result != tt.expected {
				t.Errorf("ipToUint32(%s) = 0x%X, expected 0x%X", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIPToUint32_Nil(t *testing.T) {
	result := ipToUint32(nil)
	if result != 0 {
		t.Errorf("ipToUint32(nil) = %d, expected 0", result)
	}
}

func TestPolicyKey(t *testing.T) {
	// Verify policyKey struct has correct fields for egress
	egressKey := policyKey{
		IP:        0xC0A80101, // 192.168.1.1
		Port:      443,
		Protocol:  6, // TCP
		Direction: DirectionEgress,
	}

	if egressKey.IP != 0xC0A80101 {
		t.Errorf("policyKey.IP incorrect")
	}

	if egressKey.Port != 443 {
		t.Errorf("policyKey.Port incorrect")
	}

	if egressKey.Protocol != 6 {
		t.Errorf("policyKey.Protocol incorrect")
	}

	if egressKey.Direction != DirectionEgress {
		t.Errorf("policyKey.Direction should be DirectionEgress (0)")
	}

	// Verify policyKey struct has correct fields for ingress
	ingressKey := policyKey{
		IP:        0x0A000001, // 10.0.0.1
		Port:      8080,
		Protocol:  6, // TCP
		Direction: DirectionIngress,
	}

	if ingressKey.Direction != DirectionIngress {
		t.Errorf("policyKey.Direction should be DirectionIngress (1)")
	}
}

func TestPolicyValue(t *testing.T) {
	// Test allow action
	allow := policyValue{Action: 1}
	if allow.Action != 1 {
		t.Errorf("Allow action should be 1")
	}

	// Test block action
	block := policyValue{Action: 0}
	if block.Action != 0 {
		t.Errorf("Block action should be 0")
	}
}

// Helper function to parse IP
func parseIP(ip string) []byte {
	parts := make([]byte, 4)
	var a, b, c, d int
	_, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	if err != nil {
		return nil
	}
	parts[0] = byte(a)
	parts[1] = byte(b)
	parts[2] = byte(c)
	parts[3] = byte(d)
	return parts
}

func TestCreatePolicyFromYAML(t *testing.T) {
	// Test that we can create a valid policy structure
	pol := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
	}
	pol.Metadata.Name = "test-policy"
	pol.Spec.PodSelector.MatchLabels = map[string]string{"app": "web"}

	// Add egress rule using named types
	egress := policy.EgressRule{
		To: policy.EgressTarget{
			IPBlock: struct {
				CIDR string `yaml:"cidr"`
			}{
				CIDR: "10.0.0.0/8",
			},
		},
		Ports: []policy.PortSpec{
			{Protocol: "TCP", Port: 443},
		},
	}

	pol.Spec.Egress = append(pol.Spec.Egress, egress)

	// Verify policy structure
	if len(pol.Spec.Egress) != 1 {
		t.Errorf("Expected 1 egress rule, got %d", len(pol.Spec.Egress))
	}

	if pol.Spec.Egress[0].To.IPBlock.CIDR != "10.0.0.0/8" {
		t.Errorf("CIDR mismatch")
	}

	if pol.Spec.Egress[0].Ports[0].Protocol != "TCP" {
		t.Errorf("Protocol mismatch")
	}

	if pol.Spec.Egress[0].Ports[0].Port != 443 {
		t.Errorf("Port mismatch")
	}
}

func TestCreatePolicyWithIngress(t *testing.T) {
	// Test that we can create a valid policy with ingress rules
	pol := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
	}
	pol.Metadata.Name = "test-ingress-policy"
	pol.Spec.PodSelector.MatchLabels = map[string]string{"app": "api"}

	// Add ingress rule using named types
	ingress := policy.IngressRule{
		From: policy.IngressSource{
			IPBlock: struct {
				CIDR string `yaml:"cidr"`
			}{
				CIDR: "192.168.0.0/16",
			},
		},
		Ports: []policy.PortSpec{
			{Protocol: "TCP", Port: 8080},
		},
	}

	pol.Spec.Ingress = append(pol.Spec.Ingress, ingress)

	// Verify policy structure
	if len(pol.Spec.Ingress) != 1 {
		t.Errorf("Expected 1 ingress rule, got %d", len(pol.Spec.Ingress))
	}

	if pol.Spec.Ingress[0].From.IPBlock.CIDR != "192.168.0.0/16" {
		t.Errorf("CIDR mismatch")
	}

	if pol.Spec.Ingress[0].Ports[0].Protocol != "TCP" {
		t.Errorf("Protocol mismatch")
	}

	if pol.Spec.Ingress[0].Ports[0].Port != 8080 {
		t.Errorf("Port mismatch")
	}
}

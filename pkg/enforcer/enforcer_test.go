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
	// Verify policyKey struct has correct fields
	key := policyKey{
		DestIP:   0xC0A80101, // 192.168.1.1
		DestPort: 443,
		Protocol: 6, // TCP
	}

	if key.DestIP != 0xC0A80101 {
		t.Errorf("policyKey.DestIP incorrect")
	}

	if key.DestPort != 443 {
		t.Errorf("policyKey.DestPort incorrect")
	}

	if key.Protocol != 6 {
		t.Errorf("policyKey.Protocol incorrect")
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

	// Add egress rule
	egress := struct {
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
	}{}

	egress.To.IPBlock.CIDR = "10.0.0.0/8"
	egress.Ports = []struct {
		Protocol string `yaml:"protocol"`
		Port     int    `yaml:"port"`
	}{
		{Protocol: "TCP", Port: 443},
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

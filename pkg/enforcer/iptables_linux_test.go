//go:build linux
// +build linux

package enforcer

import (
	"strings"
	"testing"
	"ztap/pkg/policy"
)

type mockIptablesRunner struct {
	lastStdin string
	commands  []string
}

func (m *mockIptablesRunner) Run(name string, arg ...string) error {
	m.commands = append(m.commands, name+" "+strings.Join(arg, " "))
	return nil
}

func (m *mockIptablesRunner) CombinedOutput(name string, arg ...string) ([]byte, error) {
	m.commands = append(m.commands, name+" "+strings.Join(arg, " "))
	return nil, nil
}

func (m *mockIptablesRunner) RunWithStdin(stdin string, name string, arg ...string) error {
	m.lastStdin = stdin
	m.commands = append(m.commands, name+" "+strings.Join(arg, " "))
	return nil
}

func TestIptablesRestoreGeneration(t *testing.T) {
	enforcer := &IptablesEnforcer{
		runner: &mockIptablesRunner{},
	}

	policies := []policy.NetworkPolicy{
		{
			Metadata: policy.NetworkPolicyMetadata{Name: "test-policy"},
			Spec: policy.NetworkPolicySpec{
				Ingress: []policy.IngressRule{
					{
						From: policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "1.2.3.4/32"}},
						Ports: []policy.PortSpec{
							{Protocol: "TCP", Port: 80},
						},
					},
					{
						From: policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "1.2.3.0/24"}},
						Ports: []policy.PortSpec{
							{Protocol: "ICMP", Port: 9999},
						},
					},
					{
						From: policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "2001:db8::1/128"}},
						Ports: []policy.PortSpec{
							{Protocol: "TCP", Port: 443},
						},
					},
					{
						From: policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "2001:db8::/64"}},
						Ports: []policy.PortSpec{
							{Protocol: "ICMP", Port: 9999},
						},
					},
				},
				Egress: []policy.EgressRule{
					{
						To: policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "8.8.8.8/32"}},
					},
					{
						To: policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "8.8.8.0/24"}},
						Ports: []policy.PortSpec{
							{Protocol: "ICMP", Port: 1234},
						},
					},
					{
						To: policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "2606:4700:4700::1111/128"}},
					},
					{
						To: policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "2606:4700:4700::/48"}},
						Ports: []policy.PortSpec{
							{Protocol: "ICMP", Port: 1234},
						},
					},
				},
			},
		},
	}

	v4, v6 := enforcer.generateRestoreInput(policies)

	expectedV4 := []string{
		"*filter",
		"-A ZTAP-INGRESS -s 1.2.3.4/32 -p tcp --dport 80 -j ACCEPT",
		"-A ZTAP-INGRESS -s 1.2.3.0/24 -p icmp -j ACCEPT",
		"-A ZTAP-EGRESS -d 8.8.8.8/32 -j ACCEPT",
		"-A ZTAP-EGRESS -d 8.8.8.0/24 -p icmp -j ACCEPT",
		"COMMIT",
	}

	expectedV6 := []string{
		"*filter",
		"-A ZTAP-INGRESS -s 2001:db8::1/128 -p tcp --dport 443 -j ACCEPT",
		"-A ZTAP-INGRESS -s 2001:db8::/64 -p ipv6-icmp -j ACCEPT",
		"-A ZTAP-EGRESS -d 2606:4700:4700::1111/128 -j ACCEPT",
		"-A ZTAP-EGRESS -d 2606:4700:4700::/48 -p ipv6-icmp -j ACCEPT",
		"COMMIT",
	}

	for _, expected := range expectedV4 {
		if !strings.Contains(v4, expected) {
			t.Errorf("Expected v4 restore input to contain: %s\nGot:\n%s", expected, v4)
		}
	}

	for _, expected := range expectedV6 {
		if !strings.Contains(v6, expected) {
			t.Errorf("Expected v6 restore input to contain: %s\nGot:\n%s", expected, v6)
		}
	}
}

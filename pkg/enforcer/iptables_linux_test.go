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
				},
				Egress: []policy.EgressRule{
					{
						To: policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "8.8.8.8/32"}},
					},
				},
			},
		},
	}

	restoreInput := enforcer.generateRestoreInput(policies)

	expectedLines := []string{
		"*filter",
		":ZTAP-INGRESS - [0:0]",
		":ZTAP-EGRESS - [0:0]",
		"-A ZTAP-INGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A ZTAP-INGRESS -i lo -j ACCEPT",
		"-A ZTAP-INGRESS -s 1.2.3.4/32 -p tcp --dport 80 -j ACCEPT",
		"-A ZTAP-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A ZTAP-EGRESS -o lo -j ACCEPT",
		"-A ZTAP-EGRESS -d 8.8.8.8/32 -j ACCEPT",
		"-A ZTAP-INGRESS -j DROP",
		"-A ZTAP-EGRESS -j DROP",
		"COMMIT",
	}

	for _, expected := range expectedLines {
		if !strings.Contains(restoreInput, expected) {
			t.Errorf("Expected restore input to contain: %s\nGot:\n%s", expected, restoreInput)
		}
	}
}

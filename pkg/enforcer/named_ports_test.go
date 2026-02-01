package enforcer

import (
	"testing"

	"ztap/pkg/policy"
)

func TestResolveIngressNamedPorts(t *testing.T) {
	p := policy.NetworkPolicy{
		Metadata: policy.NetworkPolicyMetadata{Name: "named"},
		Spec: policy.NetworkPolicySpec{
			Ingress: []policy.IngressRule{
				{
					From: policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/8"}},
					Ports: []policy.PortSpec{
						{Protocol: "TCP", PortName: "http"},
						{Protocol: "TCP", Port: 443},
					},
				},
				{
					From:  policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "192.168.0.0/16"}},
					Ports: []policy.PortSpec{{Protocol: "TCP", PortName: "metrics"}},
				},
			},
			Egress: []policy.EgressRule{
				{To: policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "1.1.1.1/32"}}, Ports: []policy.PortSpec{{Protocol: "TCP", Port: 80}}},
			},
		},
	}

	if !policyHasIngressNamedPorts(p) {
		t.Fatal("expected named ports to be detected")
	}

	portMap := map[string]int{policy.NamedPortKey("http", "TCP"): 8080}
	resolved, missing := resolveIngressNamedPorts(p, portMap)
	if len(missing) != 1 || missing[0] != "metrics" {
		t.Fatalf("expected missing metrics, got %v", missing)
	}
	if len(resolved.Spec.Ingress) != 1 {
		t.Fatalf("expected 1 ingress rule after resolution, got %d", len(resolved.Spec.Ingress))
	}
	if len(resolved.Spec.Ingress[0].Ports) != 2 {
		t.Fatalf("expected 2 ports after resolution, got %d", len(resolved.Spec.Ingress[0].Ports))
	}
	if resolved.Spec.Ingress[0].Ports[0].Port != 8080 || resolved.Spec.Ingress[0].Ports[0].PortName != "" {
		t.Fatalf("expected named port resolved to 8080, got %+v", resolved.Spec.Ingress[0].Ports[0])
	}
	if len(resolved.Spec.Egress) != 1 {
		t.Fatalf("expected egress rules to remain, got %d", len(resolved.Spec.Egress))
	}
	if policyHasIngressNamedPorts(resolved) {
		t.Fatal("expected no named ports after resolution")
	}
}

package policy

import "testing"

func TestPortSpecUnmarshalNamedPort(t *testing.T) {
	policyContent := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: named-port
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
          port: http
`

	policies, err := LoadFromBytes([]byte(policyContent))
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	port := policies[0].Spec.Egress[0].Ports[0]
	if port.PortName != "http" {
		t.Fatalf("expected port name http, got %q", port.PortName)
	}
	if port.Port != 0 {
		t.Fatalf("expected numeric port to be 0 for named port, got %d", port.Port)
	}
}

func TestPortSpecUnmarshalRange(t *testing.T) {
	policyContent := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: port-range
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
          port: 8000
          endPort: 8080
`

	policies, err := LoadFromBytes([]byte(policyContent))
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}
	port := policies[0].Spec.Egress[0].Ports[0]
	if port.Port != 8000 {
		t.Fatalf("expected port 8000, got %d", port.Port)
	}
	if port.EndPort == nil || *port.EndPort != 8080 {
		t.Fatalf("expected endPort 8080, got %#v", port.EndPort)
	}
}

package enforcer

import (
	"testing"
	"ztap/pkg/policy"
)

func TestTranslatePolicyToWFP(t *testing.T) {
	p := policy.NetworkPolicy{
		Metadata: policy.NetworkPolicyMetadata{
			Name: "test-policy",
		},
		Spec: policy.NetworkPolicySpec{
			Egress: []policy.EgressRule{
				{
					To: policy.EgressTarget{
						IPBlock: policy.IPBlockSpec{
							CIDR: "1.2.3.4/32",
						},
					},
					Ports: []policy.PortSpec{
						{
							Protocol: "TCP",
							Port:     80,
						},
					},
				},
			},
			Ingress: []policy.IngressRule{
				{
					From: policy.IngressSource{
						IPBlock: policy.IPBlockSpec{
							CIDR: "5.6.7.8/32",
						},
					},
					Ports: []policy.PortSpec{
						{
							Protocol: "UDP",
							Port:     53,
						},
					},
				},
			},
		},
	}

	specs, err := TranslatePolicyToWFP(p)
	if err != nil {
		t.Fatalf("TranslatePolicyToWFP failed: %v", err)
	}

	if len(specs) != 2 {
		t.Errorf("Expected 2 specs, got %d", len(specs))
	}

	// Verify Egress spec
	egressFound := false
	for _, s := range specs {
		if s.LayerKey == LayerALEAuthConnectV4 {
			egressFound = true
			if s.ActionType != FWP_ACTION_PERMIT {
				t.Errorf("Expected PERMIT action for egress, got %d", s.ActionType)
			}
			if len(s.Conditions) != 3 {
				t.Errorf("Expected 3 conditions for egress, got %d", len(s.Conditions))
			}
			// Check IP (1.2.3.4 -> 0x01020304)
			foundIP := false
			for _, c := range s.Conditions {
				if c.FieldKey == ConditionIPRemoteAddress {
					foundIP = true
					am, ok := c.Value.(V4AddrMask)
					if !ok {
						t.Fatalf("Expected V4AddrMask, got %T", c.Value)
					}
					if am.Addr != 0x01020304 {
						t.Errorf("Expected IP 0x01020304, got 0x%08x", am.Addr)
					}
					if am.Mask != 0xffffffff {
						t.Errorf("Expected mask 0xffffffff, got 0x%08x", am.Mask)
					}
				}
			}
			if !foundIP {
				t.Error("Remote address condition not found in egress spec")
			}
		}
	}
	if !egressFound {
		t.Error("Egress spec not found")
	}

	// Verify Ingress spec
	ingressFound := false
	for _, s := range specs {
		if s.LayerKey == LayerALEAuthRecvAcceptV4 {
			ingressFound = true
			if s.ActionType != FWP_ACTION_PERMIT {
				t.Errorf("Expected PERMIT action for ingress, got %d", s.ActionType)
			}
			// Check IP (5.6.7.8 -> 0x05060708)
			foundIP := false
			for _, c := range s.Conditions {
				if c.FieldKey == ConditionIPRemoteAddress {
					foundIP = true
					am, ok := c.Value.(V4AddrMask)
					if !ok {
						t.Fatalf("Expected V4AddrMask, got %T", c.Value)
					}
					if am.Addr != 0x05060708 {
						t.Errorf("Expected IP 0x05060708, got 0x%08x", am.Addr)
					}
					if am.Mask != 0xffffffff {
						t.Errorf("Expected mask 0xffffffff, got 0x%08x", am.Mask)
					}
				}
			}
			if !foundIP {
				t.Error("Remote address condition not found in ingress spec")
			}
		}
	}
	if !ingressFound {
		t.Error("Ingress spec not found")
	}
}

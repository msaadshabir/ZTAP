//go:build windows

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
					// WFP expects IPv4 values in host order.
					// 1.2.3.4 (network bytes 01 02 03 04) => 0x04030201 on little-endian.
					if am.Addr != 0x04030201 {
						t.Errorf("Expected IP 0x04030201, got 0x%08x", am.Addr)
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
					// 5.6.7.8 => 0x08070605 on little-endian.
					if am.Addr != 0x08070605 {
						t.Errorf("Expected IP 0x08070605, got 0x%08x", am.Addr)
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

func TestTranslatePolicyToWFP_ExpandedCIDRAndICMP(t *testing.T) {
	p := policy.NetworkPolicy{
		Metadata: policy.NetworkPolicyMetadata{Name: "expanded"},
		Spec: policy.NetworkPolicySpec{
			Egress: []policy.EgressRule{
				{
					To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "1.2.3.0/24"}},
					Ports: []policy.PortSpec{{Protocol: "TCP", Port: 80}},
				},
				{
					To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "1.2.3.4/32"}},
					Ports: []policy.PortSpec{{Protocol: "ICMP", Port: 8}},
				},
				{
					To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "2001:db8::1/128"}},
					Ports: []policy.PortSpec{{Protocol: "ICMP", Port: 8}},
				},
			},
			Ingress: []policy.IngressRule{
				{
					From:  policy.IngressSource{IPBlock: policy.IPBlockSpec{CIDR: "2001:db8::/64"}},
					Ports: []policy.PortSpec{{Protocol: "UDP", Port: 53}},
				},
			},
		},
	}

	specs, err := TranslatePolicyToWFP(p)
	if err != nil {
		t.Fatalf("TranslatePolicyToWFP failed: %v", err)
	}

	// Find the v4 /24 TCP spec and validate mask conversion.
	var v4CIDRFound bool
	for _, s := range specs {
		if s.LayerKey != LayerALEAuthConnectV4 {
			continue
		}
		if len(s.Conditions) != 3 {
			continue
		}
		for _, c := range s.Conditions {
			if c.FieldKey != ConditionIPRemoteAddress {
				continue
			}
			am, ok := c.Value.(V4AddrMask)
			if !ok {
				continue
			}
			// 1.2.3.0 => 0x00030201, /24 mask => 0x00ffffff (host order).
			if am.Addr != 0x00030201 {
				t.Errorf("expected addr 0x00030201, got 0x%08x", am.Addr)
			}
			if am.Mask != 0x00ffffff {
				t.Errorf("expected mask 0x00ffffff, got 0x%08x", am.Mask)
			}
			v4CIDRFound = true
		}
	}
	if !v4CIDRFound {
		t.Fatal("expected IPv4 /24 egress spec with V4AddrMask")
	}

	// Ensure ICMP v4 emits no port condition.
	var icmpV4Found bool
	for _, s := range specs {
		if s.LayerKey != LayerALEAuthConnectV4 {
			continue
		}
		// ICMP should have remote address + protocol only.
		if len(s.Conditions) != 2 {
			continue
		}
		var hasAddr, hasProto, hasPort bool
		for _, c := range s.Conditions {
			switch c.FieldKey {
			case ConditionIPRemoteAddress:
				hasAddr = true
			case ConditionIPProtocol:
				hasProto = true
			case ConditionIPRemotePort, ConditionIPLocalPort:
				hasPort = true
			}
		}
		if hasAddr && hasProto && !hasPort {
			icmpV4Found = true
		}
	}
	if !icmpV4Found {
		t.Fatal("expected IPv4 ICMP egress spec without port condition")
	}

	// Ensure ICMP v6 protocol is 58 and no port condition.
	var icmpV6Found bool
	for _, s := range specs {
		if s.LayerKey != LayerALEAuthConnectV6 {
			continue
		}
		var hasAddr, hasProto, hasPort bool
		for _, c := range s.Conditions {
			switch c.FieldKey {
			case ConditionIPRemoteAddress:
				hasAddr = true
			case ConditionIPProtocol:
				hasProto = true
				if v, ok := c.Value.(uint8); ok && v == 58 {
					// ok
				} else {
					t.Errorf("expected ICMPv6 protocol 58, got %T=%v", c.Value, c.Value)
				}
			case ConditionIPRemotePort, ConditionIPLocalPort:
				hasPort = true
			}
		}
		if hasAddr && hasProto && !hasPort {
			icmpV6Found = true
		}
	}
	if !icmpV6Found {
		t.Fatal("expected IPv6 ICMP egress spec without port condition")
	}

	// Ensure IPv6 ingress uses v6 layer and V6AddrMask.
	var ingressV6Found bool
	for _, s := range specs {
		if s.LayerKey != LayerALEAuthRecvAcceptV6 {
			continue
		}
		for _, c := range s.Conditions {
			if c.FieldKey != ConditionIPRemoteAddress {
				continue
			}
			am, ok := c.Value.(V6AddrMask)
			if !ok {
				t.Fatalf("expected V6AddrMask, got %T", c.Value)
			}
			if am.PrefixLength != 64 {
				t.Errorf("expected prefixLength 64, got %d", am.PrefixLength)
			}
			if am.Addr[0] != 0x20 || am.Addr[1] != 0x01 {
				t.Errorf("expected addr to start with 2001::, got %x%x", am.Addr[0], am.Addr[1])
			}
			ingressV6Found = true
		}
	}
	if !ingressV6Found {
		t.Fatal("expected IPv6 ingress spec with V6AddrMask")
	}
}

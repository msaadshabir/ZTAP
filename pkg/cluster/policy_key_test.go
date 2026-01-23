package cluster

import "testing"

func TestParsePolicyKey(t *testing.T) {
	k, err := ParsePolicyKey("ns-a/policy")
	if err != nil {
		t.Fatalf("ParsePolicyKey failed: %v", err)
	}
	if k.Tenant != "ns-a" || k.Name != "policy" {
		t.Fatalf("unexpected key: %+v", k)
	}
	if k.String() != "ns-a/policy" {
		t.Fatalf("unexpected string: %s", k.String())
	}

	k, err = ParsePolicyKey("policy")
	if err != nil {
		t.Fatalf("ParsePolicyKey failed: %v", err)
	}
	if k.Tenant != DefaultTenant || k.Name != "policy" {
		t.Fatalf("unexpected key: %+v", k)
	}
	if k.String() != "default/policy" {
		t.Fatalf("unexpected string: %s", k.String())
	}
}

package cluster

import "testing"

// FuzzParsePolicyKey exercises tenant/name parsing and ensures the resulting
// key round-trips back through ParsePolicyKey without error.
func FuzzParsePolicyKey(f *testing.F) {
	f.Add("ns-a/policy")
	f.Add("policy")
	f.Add("default/p")
	f.Add("")
	f.Add("/")
	f.Add("a/b/c")

	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParsePolicyKey(s)
		if err != nil {
			return
		}
		// A successfully parsed key must re-parse from its canonical string form.
		if _, err := ParsePolicyKey(k.String()); err != nil {
			t.Fatalf("re-parse of %q -> %q failed: %v", s, k.String(), err)
		}
	})
}
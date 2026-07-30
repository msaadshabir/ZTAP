package compliance

import "testing"

// FuzzParseMappingFile exercises the compliance mapping file parser against
// arbitrary byte input and asserts successful parses are deterministic.
func FuzzParseMappingFile(f *testing.F) {
	valid := `apiVersion: ztap/v1
kind: ComplianceMapping
spec:
  defaults:
    policyKey: default/base
  mappings:
    - policyObjectName: p1
      controls:
        pci-dss: ["10.2.1"]
        soc2: ["CC7.2"]
`
	f.Add([]byte(valid), "default/base")
	f.Add([]byte("not yaml [[["), "default/x")
	f.Add([]byte(""), "")
	f.Add([]byte("{}"), "default/y")

	f.Fuzz(func(t *testing.T, b []byte, defaultPolicyKey string) {
		entries, _, _, err := ParseMappingFile(b, defaultPolicyKey, MappingFileOptions{})
		if err != nil {
			if entries != nil {
				t.Fatalf("ParseMappingFile returned non-nil entries with error")
			}
			return
		}
		// A successful parse must be deterministic.
		entries2, _, _, err2 := ParseMappingFile(b, defaultPolicyKey, MappingFileOptions{})
		if err2 != nil {
			t.Fatalf("non-deterministic: second parse errored: %v", err2)
		}
		if len(entries) != len(entries2) {
			t.Fatalf("non-deterministic entry count %d vs %d", len(entries), len(entries2))
		}
	})
}
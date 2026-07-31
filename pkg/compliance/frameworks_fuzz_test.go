package compliance

import "testing"

// FuzzValidateControlID exercises control-id validation across frameworks and
// ensures the validators never panic on arbitrary input.
func FuzzValidateControlID(f *testing.F) {
	for _, fw := range KnownFrameworks() {
		f.Add(string(fw), "10.2.1")
		f.Add(string(fw), "")
	}
	f.Add("pci-dss", "1.2.3")
	f.Add("soc2", "CC7.2")
	f.Add("hipaa", "164.308(a)(1)(ii)(A)")
	f.Add("unknown", "x")

	f.Fuzz(func(t *testing.T, framework string, controlID string) {
		fw, ok := ParseFrameworkID(framework)
		if !ok {
			// Unknown frameworks must error rather than be silently accepted.
			if err := ValidateControlID(fw, controlID); err == nil {
				t.Fatalf("unknown framework %q accepted control %q", framework, controlID)
			}
			return
		}
		_ = ValidateControlID(fw, controlID)
	})
}

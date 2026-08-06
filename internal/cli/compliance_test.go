package cli

import "testing"

func TestComplianceEvidenceWindowParsing(t *testing.T) {
	in := complianceInputs{window: "90d"}
	d, err := in.evidenceWindow()
	if err != nil {
		t.Fatalf("evidenceWindow: %v", err)
	}
	if d.Hours() != 2160 {
		t.Fatalf("expected 2160h, got %v", d)
	}

	in = complianceInputs{window: "1.5d"}
	d, err = in.evidenceWindow()
	if err != nil {
		t.Fatalf("evidenceWindow: %v", err)
	}
	if d.Hours() != 36 {
		t.Fatalf("expected 36h, got %v", d)
	}
}

package compliance

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/policy"
)

func TestBuildReportFromAnnotationsWithEvidence(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.log")
	al, err := audit.NewAuditLogger(auditPath)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	_ = al.Log(audit.EventPolicyEnforced, "system", "default/test-policy", "enforce", map[string]any{"platform": "linux"})
	_ = al.Close()

	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name: "test-policy",
			Annotations: map[string]string{
				"ztap.io/compliance.pci-dss": "10.2.1",
				"ztap.io/compliance.soc2":    "CC7.2",
			},
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
			}},
		},
	}

	report, err := BuildReport(context.Background(), []policy.NetworkPolicy{p}, BuildOptions{
		PolicyName:     "test-policy",
		AuditLogPath:   auditPath,
		EvidenceWindow: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}

	if report.Audit.IntegrityStatus != EvidencePresent {
		t.Fatalf("expected integrity present, got %s", report.Audit.IntegrityStatus)
	}
	if len(report.Controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(report.Controls))
	}

	// Evidence should be present for those controls.
	for _, c := range report.Controls {
		if c.Evidence.Status != EvidencePresent {
			t.Fatalf("expected control evidence present for %s %s, got %s", c.Framework, c.ControlID, c.Evidence.Status)
		}
	}
}

func TestAnnotationMappingParsesAndDedupes(t *testing.T) {
	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name: "p1",
			Annotations: map[string]string{
				"ztap.io/compliance.pci-dss": "10.2.1, 10.2.1, 1.2.7",
				"ztap.io/compliance.soc2":    "CC7.2, CC7.2",
			},
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
			}},
		},
	}

	mappings, warnings, err := ExtractMappingsFromAnnotations([]policy.NetworkPolicy{p}, "default/p1", AnnotationParseOptions{})
	if err != nil {
		t.Fatalf("ExtractMappingsFromAnnotations: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	if got := mappings[0].Controls[FrameworkPCIDSS]; len(got) != 2 || got[0] != "1.2.7" || got[1] != "10.2.1" {
		t.Fatalf("unexpected pci-dss controls: %v", got)
	}
	if got := mappings[0].Controls[FrameworkSOC2]; len(got) != 1 || got[0] != "CC7.2" {
		t.Fatalf("unexpected soc2 controls: %v", got)
	}
}

func TestAnnotationMappingUnknownFrameworkStrict(t *testing.T) {
	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name: "p1",
			Annotations: map[string]string{
				"ztap.io/compliance.not-a-framework": "X",
				"ztap.io/compliance.pci-dss":         "10.2.1",
			},
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
			}},
		},
	}

	_, warnings, err := ExtractMappingsFromAnnotations([]policy.NetworkPolicy{p}, "default/p1", AnnotationParseOptions{})
	if err != nil {
		t.Fatalf("expected non-strict to succeed, got %v", err)
	}
	if len(warnings) == 0 {
		t.Fatalf("expected warnings")
	}

	_, _, err = ExtractMappingsFromAnnotations([]policy.NetworkPolicy{p}, "default/p1", AnnotationParseOptions{Strict: true})
	if err == nil {
		t.Fatalf("expected strict mode to error")
	}
}

func TestAuditIntegrityFailureIsReported(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.log")
	al, err := audit.NewAuditLogger(auditPath)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	_ = al.Log(audit.EventPolicyEnforced, "system", "default/test-policy", "enforce", map[string]any{"platform": "linux"})
	_ = al.Close()

	// Tamper with the file.
	b, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(b) < 10 {
		t.Fatalf("unexpected audit log length")
	}
	b[len(b)-2] ^= 0xff
	if err := os.WriteFile(auditPath, b, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name: "test-policy",
			Annotations: map[string]string{
				"ztap.io/compliance.pci-dss": "10.2.1",
			},
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
			}},
		},
	}

	report, err := BuildReport(context.Background(), []policy.NetworkPolicy{p}, BuildOptions{AuditLogPath: auditPath, EvidenceWindow: 24 * time.Hour})
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if report.Audit.IntegrityStatus != EvidenceMissing {
		t.Fatalf("expected integrity missing, got %s", report.Audit.IntegrityStatus)
	}
	if len(report.Policies) != 1 {
		t.Fatalf("expected 1 policy mapping, got %d", len(report.Policies))
	}
	if report.Policies[0].Evidence.Enforced != EvidenceUnknown {
		t.Fatalf("expected enforcement evidence unknown when integrity fails, got %s", report.Policies[0].Evidence.Enforced)
	}
}

func TestMappingFileOverridesAnnotations(t *testing.T) {
	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name: "p1",
			Annotations: map[string]string{
				"ztap.io/compliance.pci-dss": "10.2.1",
			},
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
			}},
		},
	}

	mappingYAML := []byte(`apiVersion: ztap.io/v1alpha1
kind: ComplianceMapping
spec:
  mappings:
    - policyObjectName: p1
      policyKey: default/p1
      controls:
        pci-dss: ["1.2.1"]
`)

	report, err := BuildReport(context.Background(), []policy.NetworkPolicy{p}, BuildOptions{MappingFileYAML: mappingYAML})
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}

	if len(report.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(report.Controls))
	}
	if report.Controls[0].ControlID != "1.2.1" {
		t.Fatalf("expected mapping file control 1.2.1, got %s", report.Controls[0].ControlID)
	}
}

func TestEnforcementEvidenceRespectsWindow(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.log")
	al, err := audit.NewAuditLogger(auditPath)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	_ = al.Log(audit.EventPolicyEnforced, "system", "default/p1", "enforce", map[string]any{"platform": "linux"})
	_ = al.Close()

	// Ensure the event is older than the evidence window.
	time.Sleep(10 * time.Millisecond)

	p := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.NetworkPolicyMetadata{
			Name: "p1",
			Annotations: map[string]string{
				"ztap.io/compliance.pci-dss": "10.2.1",
			},
		},
		Spec: policy.NetworkPolicySpec{
			PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
			Egress: []policy.EgressRule{{
				To:    policy.EgressTarget{IPBlock: policy.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []policy.PortSpec{{Protocol: "TCP", Port: 443}},
			}},
		},
	}

	report, err := BuildReport(context.Background(), []policy.NetworkPolicy{p}, BuildOptions{AuditLogPath: auditPath, EvidenceWindow: 1 * time.Millisecond})
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if len(report.Policies) != 1 {
		t.Fatalf("expected 1 policy mapping, got %d", len(report.Policies))
	}
	if report.Policies[0].Evidence.Enforced != EvidenceMissing {
		t.Fatalf("expected enforcement evidence missing due to window, got %s", report.Policies[0].Evidence.Enforced)
	}
}

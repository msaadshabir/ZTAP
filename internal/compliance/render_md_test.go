package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderMarkdownHasStableSections(t *testing.T) {
	report := Report{
		Metadata: ReportMetadata{
			GeneratedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			HostOS:        "darwin",
			HostArch:      "arm64",
			PolicyKey:     "default/p1",
			MappingSource: "annotations",
			AuditLogPath:  "/tmp/audit.log",
		},
		Audit: AuditEvidence{IntegrityStatus: EvidencePresent, EntryCount: 2, LastHash: "abc"},
		Controls: []ControlMapping{
			{Framework: FrameworkSOC2, ControlID: "CC7.2", Policies: []PolicyRef{{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}}, Evidence: ControlEvidence{Framework: FrameworkSOC2, ControlID: "CC7.2", Status: EvidenceMissing}},
			{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Policies: []PolicyRef{{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}}, Evidence: ControlEvidence{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Status: EvidencePresent}},
		},
		Policies: []PolicyMapping{
			{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}, Controls: []ControlRef{{Framework: FrameworkPCIDSS, ControlID: "10.2.1"}}, Evidence: PolicyEvidence{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}, Enforced: EvidencePresent, EnforcedCount: 1}},
			{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}, Controls: []ControlRef{{Framework: FrameworkSOC2, ControlID: "CC7.2"}}, Evidence: PolicyEvidence{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}, Enforced: EvidenceMissing, EnforcedCount: 0}},
		},
		Warnings: []string{"w1"},
	}

	md, err := RenderMarkdown(report)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}

	if !strings.Contains(md, "# Compliance Report") {
		t.Fatalf("missing title")
	}
	if !strings.Contains(md, "## Audit Evidence") {
		t.Fatalf("missing audit section")
	}
	if !strings.Contains(md, "## Control Coverage") {
		t.Fatalf("missing control section")
	}
	if !strings.Contains(md, "## Policy Index") {
		t.Fatalf("missing policy section")
	}
	if !strings.Contains(md, "## Warnings") {
		t.Fatalf("missing warnings section")
	}

	// Ensure framework grouping order is stable (pci-dss before soc2).
	idxPCI := strings.Index(md, "### pci-dss")
	idxSOC := strings.Index(md, "### soc2")
	if idxPCI == -1 || idxSOC == -1 {
		t.Fatalf("missing framework headings")
	}
	if idxPCI > idxSOC {
		t.Fatalf("expected pci-dss section before soc2")
	}
}

func TestRenderMarkdownGolden(t *testing.T) {
	report := Report{
		Metadata: ReportMetadata{
			GeneratedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			HostOS:        "darwin",
			HostArch:      "arm64",
			PolicyKey:     "default/p1",
			MappingSource: "annotations",
			AuditLogPath:  "/tmp/audit.log",
		},
		Audit: AuditEvidence{IntegrityStatus: EvidencePresent, EntryCount: 2, LastHash: "abc"},
		Controls: []ControlMapping{
			{Framework: FrameworkSOC2, ControlID: "CC7.2", Policies: []PolicyRef{{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}}, Evidence: ControlEvidence{Framework: FrameworkSOC2, ControlID: "CC7.2", Status: EvidenceMissing}},
			{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Policies: []PolicyRef{{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}}, Evidence: ControlEvidence{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Status: EvidencePresent}},
		},
		Policies: []PolicyMapping{
			{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}, Controls: []ControlRef{{Framework: FrameworkPCIDSS, ControlID: "10.2.1"}}, Evidence: PolicyEvidence{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}, Enforced: EvidencePresent, EnforcedCount: 1}},
			{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}, Controls: []ControlRef{{Framework: FrameworkSOC2, ControlID: "CC7.2"}}, Evidence: PolicyEvidence{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}, Enforced: EvidenceMissing, EnforcedCount: 0}},
		},
		Warnings: []string{"w1"},
	}

	md, err := RenderMarkdown(report)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}

	expected := readTestdata(t, "report_golden.md")
	norm := func(s string) string {
		s = strings.ReplaceAll(s, "\r\n", "\n")
		s = strings.ReplaceAll(s, "\r", "\n")
		lines := strings.Split(s, "\n")
		for i := range lines {
			lines[i] = strings.TrimRight(lines[i], " \t")
		}
		s = strings.Join(lines, "\n")
		s = strings.TrimRight(s, "\n") + "\n"
		return s
	}
	if norm(md) != norm(expected) {
		t.Fatalf("markdown output mismatch\n--- expected ---\n%s\n--- got ---\n%s", expected, md)
	}
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return string(b)
}

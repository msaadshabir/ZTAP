package compliance

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestWriteJSONExportShape(t *testing.T) {
	report := Report{
		Metadata: ReportMetadata{GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), HostOS: "darwin", HostArch: "arm64", PolicyKey: "default/p1"},
		Audit:    AuditEvidence{IntegrityStatus: EvidencePresent, EntryCount: 10, LastHash: "abc"},
		Controls: []ControlMapping{{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Policies: []PolicyRef{{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}}, Evidence: ControlEvidence{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Status: EvidencePresent}}},
		Policies: []PolicyMapping{{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}, Controls: []ControlRef{{Framework: FrameworkPCIDSS, ControlID: "10.2.1"}}, Evidence: PolicyEvidence{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}, Enforced: EvidencePresent, EnforcedCount: 1}}},
		Warnings: []string{"w1"},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, report); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, k := range []string{"metadata", "audit", "controls", "policies"} {
		if _, ok := decoded[k]; !ok {
			t.Fatalf("missing top-level key %q", k)
		}
	}
	if _, ok := decoded["warnings"]; !ok {
		t.Fatalf("expected warnings")
	}
}

func TestWriteCSVExportHeaderAndOrdering(t *testing.T) {
	report := Report{
		Controls: []ControlMapping{
			{Framework: FrameworkSOC2, ControlID: "CC7.2", Policies: []PolicyRef{{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}}, Evidence: ControlEvidence{Framework: FrameworkSOC2, ControlID: "CC7.2", Status: EvidenceMissing}},
			{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Policies: []PolicyRef{{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}}, Evidence: ControlEvidence{Framework: FrameworkPCIDSS, ControlID: "10.2.1", Status: EvidencePresent}},
		},
		Policies: []PolicyMapping{
			{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p1", PolicyObjectName: "p1"}, Rationale: "r1, has comma", Owner: "sec@example.com"},
			{Policy: PolicyRef{Tenant: "default", PolicyKey: "default/p2", PolicyObjectName: "p2"}, Rationale: "line1\nline2", Owner: "owner"},
		},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, report); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	r := csv.NewReader(bytes.NewReader(buf.Bytes()))
	var rows [][]string
	for {
		rec, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("csv read: %v", err)
		}
		rows = append(rows, rec)
	}

	if len(rows) != 3 {
		t.Fatalf("expected 3 records (header + 2 rows), got %d", len(rows))
	}

	if got := strings.Join(rows[0], ","); got != "framework_id,framework_version,control_id,tenant,policy_key,policy_object_name,rationale,owner,evidence_status" {
		t.Fatalf("unexpected header: %s", got)
	}

	if rows[1][0] != "pci-dss" {
		t.Fatalf("expected first row pci-dss, got %s", rows[1][0])
	}
	if rows[2][0] != "soc2" {
		t.Fatalf("expected second row soc2, got %s", rows[2][0])
	}

	if rows[1][6] != "r1, has comma" {
		t.Fatalf("unexpected rationale for row1: %q", rows[1][6])
	}
	if rows[2][6] != "line1\nline2" {
		t.Fatalf("unexpected rationale for row2: %q", rows[2][6])
	}
}

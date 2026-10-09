package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/restartproof"
)

func continuitySampleFixture(mode string) restartproof.Sample {
	return restartproof.Sample{Mode: mode, OutageMS: 2000, CgroupID: 42, PolicyEpochBefore: 1, PolicyEpochAfter: 1, AgentEpochBefore: 10, AgentEpochAfter: 11,
		Before: restartproof.Counts{IngressAllowed: 1, EgressAllowed: 2, Replies: 1, IngressBlocked: 2, EgressBlocked: 2}, During: restartproof.Counts{IngressAllowed: 20, EgressAllowed: 30, Replies: 20, IngressBlocked: 30, EgressBlocked: 30}, After: restartproof.Counts{IngressAllowed: 50, EgressAllowed: 60, Replies: 50, IngressBlocked: 70, EgressBlocked: 70}}
}

func TestVersionedContinuityRequiresAllZeroCounters(t *testing.T) {
	value := restartEvidence{SchemaVersion: 2, Continuity: []restartproof.Sample{continuitySampleFixture("SIGTERM")}, Scope: restartproof.ContinuityScope}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	// Version 2 excludes historical gap fields completely.
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "restart_samples_ms")
	delete(object, "restart_p95_ms")
	payload, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRequiredJSONFields(payload, &restartEvidence{}); err != nil {
		t.Fatal(err)
	}
	missing := strings.Replace(string(payload), `"egress_prohibited":0,`, "", 1)
	if missing == string(payload) {
		missing = strings.Replace(string(payload), `,"egress_prohibited":0`, "", 1)
	}
	if err := validateRequiredJSONFields([]byte(missing), &restartEvidence{}); err == nil {
		t.Fatal("missing zero prohibited counter accepted")
	}
	object["restart_samples_ms"] = nil
	bad, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRequiredJSONFields(bad, &restartEvidence{}); err == nil {
		t.Fatal("mixed historical and continuity formats accepted")
	}
}

func TestHostedContinuityRecordsRequireOutageControlsAndNoLeaks(t *testing.T) {
	base := time.Unix(100, 0).UnixNano()
	path := filepath.Join(t.TempDir(), "packets.jsonl")
	reports := make([]hostedContinuityReport, 12)
	for index := range reports {
		reports[index] = hostedContinuityReport{SchemaVersion: 2, StartedNS: base - int64(time.Second), TimestampNS: base + int64(index)*int64(time.Second), Allowed: uint64(10 * (index + 1)), AllowedAttempts: uint64(12 * (index + 1)), ProhibitedAttempts: uint64(10 * (index + 1))}
	}
	write := func(reports []hostedContinuityReport) {
		t.Helper()
		var lines strings.Builder
		for _, r := range reports {
			payload, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			lines.Write(payload)
			lines.WriteByte('\n')
		}
		if err := os.WriteFile(path, []byte(lines.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(reports)
	start, rollout, end := uint64(base+2*int64(time.Second)), uint64(base+8*int64(time.Second)), uint64(base+12*int64(time.Second))
	if err := validateHostedContinuityPackets(path, start, rollout, end, 120); err != nil {
		t.Fatal(err)
	}
	leaked := append([]hostedContinuityReport(nil), reports...)
	leaked[5].Prohibited = 1
	write(leaked)
	if err := validateHostedContinuityPackets(path, start, rollout, end, 120); err == nil {
		t.Fatal("a transient prohibited connection was hidden by final zero counters")
	}
	idle := append([]hostedContinuityReport(nil), reports...)
	for index := 2; index < 8; index++ {
		idle[index].Allowed = 20
	}
	write(idle)
	if err := validateHostedContinuityPackets(path, start, rollout, end, 120); err == nil {
		t.Fatal("idle outage control accepted")
	}
	write(reports)
	if err := validateHostedContinuityPackets(path, start, rollout, end, 119); err == nil {
		t.Fatal("summary totals disagree with raw records")
	}
}

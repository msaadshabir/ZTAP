package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyFileIntegrityAndQueryFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")

	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	_ = logger.Log(EventPolicyEnforced, "system", "default/p1", "enforce", map[string]any{"platform": "linux"})
	_ = logger.Log(EventPolicyEnforced, "system", "default/p2", "enforce", map[string]any{"platform": "linux"})
	_ = logger.Close()

	stats, err := GetFileStats(path)
	if err != nil {
		t.Fatalf("GetFileStats: %v", err)
	}
	if stats.EntryCount != 2 {
		t.Fatalf("expected entry_count=2, got %d", stats.EntryCount)
	}
	if stats.LastHash == "" {
		t.Fatalf("expected last_hash")
	}

	ok, err := VerifyFileIntegrity(path)
	if err != nil {
		t.Fatalf("VerifyFileIntegrity: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok")
	}

	evt := EventPolicyEnforced
	res := "default/p1"
	entries, err := QueryFile(path, QueryOptions{EventType: &evt, Resource: &res})
	if err != nil {
		t.Fatalf("QueryFile: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Resource != "default/p1" {
		t.Fatalf("unexpected resource %q", entries[0].Resource)
	}

	start := time.Now().Add(24 * time.Hour)
	entries, err = QueryFile(path, QueryOptions{EventType: &evt, Resource: &res, StartTime: &start})
	if err != nil {
		t.Fatalf("QueryFile: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestVerifyFileIntegrityDetectsTamper(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")

	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	_ = logger.Log(EventPolicyCreated, "admin", "default/p1", "created", nil)
	_ = logger.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) < 5 {
		t.Fatalf("unexpected audit log length")
	}
	data[len(data)-3] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ok, err := VerifyFileIntegrity(path)
	if err == nil {
		t.Fatalf("expected error")
	}
	if ok {
		t.Fatalf("expected ok=false")
	}
}

package cluster

import "testing"

func TestSanitizeForLog(t *testing.T) {
	got := sanitizeForLog("node\nid\rtest")
	if got != "nodeidtest" {
		t.Fatalf("expected sanitized value without newlines, got %q", got)
	}
}

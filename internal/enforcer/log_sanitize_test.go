package enforcer

import "testing"

func TestSanitizeForLog(t *testing.T) {
	if got := sanitizeForLog("policy\r\nname"); got != "policyname" {
		t.Fatalf("expected sanitized value, got %q", got)
	}
}

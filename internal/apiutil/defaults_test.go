package apiutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultAuditLoggerRejectsInvalidAuditConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configYAML := []byte("audit:\n  integrity_mode: hmac-sha256\n")
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("ZTAP_CONFIG", configPath)

	logger, err := DefaultAuditLogger()
	if logger != nil {
		_ = logger.Close()
	}
	if err == nil {
		t.Fatal("expected invalid audit configuration to fail")
	}
	if !strings.Contains(err.Error(), "hmac-sha256 integrity mode requires hmac_key_file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

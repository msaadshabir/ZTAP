package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func TestFullWorkflow(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLoggerWithOptions(AuditLoggerOptions{
		LogPath: logPath,
		Signer:  NewEd25519Signer(priv, "test-key"),
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	for i := range 3 {
		if err := logger.Log(EventPolicyCreated, "admin", "policy", "created", map[string]any{"index": i}); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}
	_ = logger.Close()

	verifier := NewEd25519Verifier(pub, "test-key")
	logger2, err := NewAuditLoggerWithOptions(AuditLoggerOptions{LogPath: logPath})
	if err != nil {
		t.Fatalf("failed to reopen logger: %v", err)
	}
	result := logger2.VerifyIntegrityDetailed(verifier)
	if !result.Valid || !result.SignatureValid {
		t.Fatalf("expected valid verification, got: %+v", result)
	}
	_ = logger2.Close()
}

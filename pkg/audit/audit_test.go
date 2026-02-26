package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	if logger.logPath != logPath {
		t.Errorf("expected logPath %s, got %s", logPath, logger.logPath)
	}

	if logger.lastHash == "" {
		t.Error("lastHash should be initialized")
	}
}

func TestAuditLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	details := map[string]interface{}{
		"policy_name": "web-policy",
		"version":     1,
	}

	err = logger.Log(EventPolicyCreated, "admin", "web-policy", "created", details)
	if err != nil {
		t.Fatalf("failed to log entry: %v", err)
	}

	if logger.entryCount != 1 {
		t.Errorf("expected entry count 1, got %d", logger.entryCount)
	}
}

func TestAuditLogger_LogFailure(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	details := map[string]interface{}{
		"policy_name": "invalid-policy",
	}

	err = logger.LogFailure(EventPolicyCreated, "admin", "invalid-policy", "created",
		"invalid CIDR format", details)
	if err != nil {
		t.Fatalf("failed to log failure: %v", err)
	}

	// Query the failure
	entries, err := logger.Query(QueryOptions{Limit: 10})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Outcome != "failure" {
		t.Errorf("expected outcome 'failure', got %s", entry.Outcome)
	}

	if entry.ErrorMessage != "invalid CIDR format" {
		t.Errorf("expected error message 'invalid CIDR format', got %s", entry.ErrorMessage)
	}
}

func TestAuditLogger_HashChaining(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Log first entry
	err = logger.Log(EventPolicyCreated, "admin", "policy-1", "created", nil)
	if err != nil {
		t.Fatalf("failed to log entry 1: %v", err)
	}
	firstHash := logger.lastHash

	// Log second entry
	err = logger.Log(EventPolicyUpdated, "admin", "policy-1", "updated", nil)
	if err != nil {
		t.Fatalf("failed to log entry 2: %v", err)
	}
	secondHash := logger.lastHash

	// Hashes should be different
	if firstHash == secondHash {
		t.Error("hashes should be different for different entries")
	}

	// Query entries
	entries, err := logger.Query(QueryOptions{})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Second entry should chain to first
	if entries[1].PreviousHash != entries[0].Hash {
		t.Errorf("hash chain broken: entry 2 previous hash %s != entry 1 hash %s",
			entries[1].PreviousHash, entries[0].Hash)
	}
}

func TestAuditLogger_VerifyIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	// Log multiple entries
	for i := 0; i < 5; i++ {
		details := map[string]interface{}{"index": i}
		err = logger.Log(EventPolicyCreated, "admin", "policy", "created", details)
		if err != nil {
			t.Fatalf("failed to log entry %d: %v", i, err)
		}
	}

	_ = logger.Close()

	// Reopen and verify
	logger, err = NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to reopen audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	valid, err := logger.VerifyIntegrity()
	if err != nil {
		t.Fatalf("failed to verify integrity: %v", err)
	}

	if !valid {
		t.Error("audit log should be valid")
	}
}

func TestAuditLogger_VerifyIntegrityDetectsTampering(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	// Log entries
	for i := 0; i < 3; i++ {
		err = logger.Log(EventPolicyCreated, "admin", "policy", "created", nil)
		if err != nil {
			t.Fatalf("failed to log entry %d: %v", i, err)
		}
	}

	_ = logger.Close()

	// Tamper with the log file (modify a byte)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	// Modify a character in the middle
	if len(data) > 100 {
		data[100] = 'X'
	}

	err = os.WriteFile(logPath, data, 0600)
	if err != nil {
		t.Fatalf("failed to write tampered log: %v", err)
	}

	// Reopen and verify - should detect tampering
	logger, err = NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to reopen audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	valid, err := logger.VerifyIntegrity()
	if valid {
		t.Error("integrity check should have detected tampering")
	}

	if err == nil {
		t.Error("expected error from integrity check on tampered log")
	}
}

func TestVerifyIntegrity_DetectsCorruption(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	if err := logger.Log(EventPolicyCreated, "admin", "policy", "created", nil); err != nil {
		t.Fatalf("failed to log entry: %v", err)
	}
	_ = logger.Close()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("failed to open log for corruption: %v", err)
	}
	_, _ = f.WriteString("{invalid json")
	_ = f.Close()

	logger, err = NewAuditLogger(logPath)
	if err == nil {
		_, err = logger.VerifyIntegrity()
		_ = logger.Close()
	}
	if err == nil {
		t.Fatal("expected corruption error")
	}
}

func TestAuditLogger_Ed25519Signing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	signer := NewEd25519Signer(priv, "test-key")
	verifier := NewEd25519Verifier(pub, "test-key")

	tmpDir := t.TempDir()
	opts := AuditLoggerOptions{
		LogPath: filepath.Join(tmpDir, "audit.log"),
		Signer:  signer,
	}

	logger, err := NewAuditLoggerWithOptions(opts)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	if err := logger.Log(EventPolicyCreated, "admin", "test-policy", "create", nil); err != nil {
		t.Fatalf("failed to log: %v", err)
	}
	_ = logger.Close()

	logger2, err := NewAuditLoggerWithOptions(AuditLoggerOptions{LogPath: opts.LogPath})
	if err != nil {
		t.Fatalf("failed to reopen logger: %v", err)
	}
	result := logger2.VerifyIntegrityDetailed(verifier)
	if !result.Valid || !result.SignatureValid {
		t.Errorf("expected valid signature, got: %+v", result)
	}
	_ = logger2.Close()

	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong keypair: %v", err)
	}
	wrongVerifier := NewEd25519Verifier(wrongPriv.Public().(ed25519.PublicKey), "wrong-key")
	logger3, err := NewAuditLoggerWithOptions(AuditLoggerOptions{LogPath: opts.LogPath})
	if err != nil {
		t.Fatalf("failed to reopen logger for wrong key: %v", err)
	}
	result2 := logger3.VerifyIntegrityDetailed(wrongVerifier)
	if result2.SignatureValid {
		t.Error("expected signature verification to fail with wrong key")
	}
	if result2.Valid {
		t.Error("expected overall verification to fail with wrong key")
	}
	_ = logger3.Close()
}

func TestAuditLogger_TruncationDetection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	verifier := NewEd25519Verifier(pub, "test-key")

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")
	checkpointPath := logPath + ".checkpoint"

	logger, err := NewAuditLoggerWithOptions(AuditLoggerOptions{
		LogPath:        logPath,
		Signer:         NewEd25519Signer(priv, "test-key"),
		CheckpointPath: checkpointPath,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := logger.Log(EventPolicyCreated, "admin", "policy", "created", map[string]any{"index": i}); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}
	_ = logger.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("unexpected empty log")
	}
	// Remove the last complete JSON entry (newline-delimited).
	// Find the second-to-last newline and truncate there.
	trimmed := data
	if trimmed[len(trimmed)-1] == '\n' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	lastNL := -1
	for i := len(trimmed) - 1; i >= 0; i-- {
		if trimmed[i] == '\n' {
			lastNL = i
			break
		}
	}
	if lastNL < 0 {
		t.Fatalf("could not find entry boundary in log")
	}
	data = data[:lastNL+1] // keep up to and including the newline
	if err := os.WriteFile(logPath, data, 0600); err != nil {
		t.Fatalf("failed to truncate log: %v", err)
	}

	logger2, err := NewAuditLoggerWithOptions(AuditLoggerOptions{LogPath: logPath, CheckpointPath: checkpointPath})
	if err != nil {
		t.Fatalf("failed to reopen logger: %v", err)
	}
	result := logger2.VerifyIntegrityDetailed(verifier)
	if result.CheckpointValid {
		t.Fatalf("expected checkpoint mismatch after truncation")
	}
	_ = logger2.Close()
}

func TestAuditLogger_TamperAndRecompute(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	verifier := NewEd25519Verifier(pub, "test-key")

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLoggerWithOptions(AuditLoggerOptions{
		LogPath: logPath,
		Signer:  NewEd25519Signer(priv, "test-key"),
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	for i := 0; i < 4; i++ {
		if err := logger.Log(EventPolicyCreated, "admin", "policy", "created", map[string]any{"index": i}); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}
	_ = logger.Close()

	entries, err := QueryFile(logPath, QueryOptions{})
	if err != nil {
		t.Fatalf("failed to read entries: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 entries")
	}
	entries[1].Actor = "mallory"
	h, err := EntryHash(&entries[1])
	if err != nil {
		t.Fatalf("failed to compute hash: %v", err)
	}
	entries[1].Hash = h
	for i := 2; i < len(entries); i++ {
		entries[i].PreviousHash = entries[i-1].Hash
		ih, err := EntryHash(&entries[i])
		if err != nil {
			t.Fatalf("failed to compute hash for entry %d: %v", i, err)
		}
		entries[i].Hash = ih
	}

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to rewrite log: %v", err)
	}
	enc := json.NewEncoder(f)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			_ = f.Close()
			t.Fatalf("failed to encode entry: %v", err)
		}
	}
	_ = f.Close()

	logger2, err := NewAuditLoggerWithOptions(AuditLoggerOptions{LogPath: logPath})
	if err != nil {
		t.Fatalf("failed to reopen logger: %v", err)
	}
	result := logger2.VerifyIntegrityDetailed(verifier)
	if result.SignatureValid {
		t.Fatalf("expected signature verification to fail after tamper")
	}
	if result.Valid {
		t.Fatalf("expected overall verification to fail after tamper")
	}
	_ = logger2.Close()
}

func TestAuditLogger_Query(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Log different event types
	_ = logger.Log(EventPolicyCreated, "admin", "policy-1", "created", nil)
	time.Sleep(10 * time.Millisecond)
	_ = logger.Log(EventPolicyUpdated, "operator", "policy-1", "updated", nil)
	time.Sleep(10 * time.Millisecond)
	_ = logger.Log(EventUserCreated, "admin", "user-1", "created", nil)

	// Test: Query by event type
	eventType := EventPolicyCreated
	entries, err := logger.Query(QueryOptions{EventType: &eventType})
	if err != nil {
		t.Fatalf("failed to query by event type: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("expected 1 entry for policy.created, got %d", len(entries))
	}

	if entries[0].EventType != EventPolicyCreated {
		t.Errorf("expected EventPolicyCreated, got %s", entries[0].EventType)
	}

	// Test: Query by actor
	actor := "admin"
	entries, err = logger.Query(QueryOptions{Actor: &actor})
	if err != nil {
		t.Fatalf("failed to query by actor: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries for admin, got %d", len(entries))
	}

	// Test: Query with limit
	entries, err = logger.Query(QueryOptions{Limit: 2})
	if err != nil {
		t.Fatalf("failed to query with limit: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries with limit=2, got %d", len(entries))
	}

	// Test: Query by time range
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	entries, err = logger.Query(QueryOptions{StartTime: &past, EndTime: &now})
	if err != nil {
		t.Fatalf("failed to query by time range: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("expected 3 entries in time range, got %d", len(entries))
	}
}

func TestAuditLogger_QueryByResource(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Log entries for different resources
	_ = logger.Log(EventPolicyCreated, "admin", "web-policy", "created", nil)
	_ = logger.Log(EventPolicyCreated, "admin", "db-policy", "created", nil)
	_ = logger.Log(EventPolicyUpdated, "admin", "web-policy", "updated", nil)

	// Query for specific resource
	resource := "web-policy"
	entries, err := logger.Query(QueryOptions{Resource: &resource})
	if err != nil {
		t.Fatalf("failed to query by resource: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries for web-policy, got %d", len(entries))
	}

	for _, entry := range entries {
		if entry.Resource != "web-policy" {
			t.Errorf("expected resource 'web-policy', got %s", entry.Resource)
		}
	}
}

func TestAuditLogger_GetStats(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Log some entries
	for i := 0; i < 10; i++ {
		_ = logger.Log(EventPolicyCreated, "admin", "policy", "created", nil)
	}

	stats, err := logger.GetStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}

	if stats["path"] != logPath {
		t.Errorf("expected path %s, got %v", logPath, stats["path"])
	}

	entryCount := stats["entry_count"].(int64)
	if entryCount != 10 {
		t.Errorf("expected entry count 10, got %d", entryCount)
	}

	sizeBytes := stats["size_bytes"].(int64)
	if sizeBytes == 0 {
		t.Error("expected non-zero file size")
	}
}

func TestAuditLogger_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// Create logger and log entries
	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	_ = logger.Log(EventPolicyCreated, "admin", "policy-1", "created", nil)
	_ = logger.Log(EventPolicyUpdated, "admin", "policy-1", "updated", nil)
	firstHash := logger.lastHash
	_ = logger.Close()

	// Reopen logger
	logger, err = NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to reopen audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Last hash should be restored
	if logger.lastHash != firstHash {
		t.Errorf("expected lastHash %s, got %s", firstHash, logger.lastHash)
	}

	// Entry count should be restored
	if logger.entryCount != 2 {
		t.Errorf("expected entry count 2, got %d", logger.entryCount)
	}

	// Log another entry - should continue the chain
	_ = logger.Log(EventPolicyDeleted, "admin", "policy-1", "deleted", nil)

	entries, _ := logger.Query(QueryOptions{})
	if len(entries) != 3 {
		t.Errorf("expected 3 entries total, got %d", len(entries))
	}

	// Verify hash chain is continuous
	valid, err := logger.VerifyIntegrity()
	if err != nil {
		t.Fatalf("integrity check failed: %v", err)
	}

	if !valid {
		t.Error("audit log should be valid after reopening")
	}
}

func TestAuditLogger_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write entries concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(index int) {
			details := map[string]interface{}{"index": index}
			_ = logger.Log(EventPolicyCreated, "admin", "policy", "created", details)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all entries were logged
	if logger.entryCount != 10 {
		t.Errorf("expected 10 entries, got %d", logger.entryCount)
	}

	// Verify integrity despite concurrent writes
	valid, err := logger.VerifyIntegrity()
	if err != nil {
		t.Fatalf("integrity check failed: %v", err)
	}

	if !valid {
		t.Error("audit log should be valid after concurrent writes")
	}
}

func TestVerifyIntegrityDetailed_EntryCount(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	// Log exactly 5 entries
	for i := 0; i < 5; i++ {
		err := logger.Log(EventPolicyCreated, "admin", "policy", "created", map[string]interface{}{"i": i})
		if err != nil {
			t.Fatalf("failed to log entry %d: %v", i, err)
		}
	}

	lastHash := logger.lastHash
	lastSeq := logger.nextSeq - 1
	_ = logger.Close()

	// Reopen and verify
	logger2, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to reopen audit logger: %v", err)
	}

	result := logger2.VerifyIntegrityDetailed(nil)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %v", result.Error)
	}
	if result.EntryCount != 5 {
		t.Errorf("expected EntryCount=5, got %d", result.EntryCount)
	}
	if result.LastSeq != lastSeq {
		t.Errorf("expected LastSeq=%d, got %d", lastSeq, result.LastSeq)
	}
	if result.LastHash != lastHash {
		t.Errorf("expected LastHash=%s, got %s", lastHash, result.LastHash)
	}
	_ = logger2.Close()
}

func TestLoadLastHash_ResetsCounterOnReopen(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// Create logger and log 3 entries
	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	for i := 0; i < 3; i++ {
		_ = logger.Log(EventPolicyCreated, "admin", "policy", "created", nil)
	}
	if logger.entryCount != 3 {
		t.Fatalf("expected entryCount=3 after logging, got %d", logger.entryCount)
	}
	_ = logger.Close()

	// Reopen - entryCount should be exactly 3 (not accumulated)
	logger2, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to reopen: %v", err)
	}
	if logger2.entryCount != 3 {
		t.Errorf("expected entryCount=3 after reopen, got %d", logger2.entryCount)
	}
	_ = logger2.Close()

	// Reopen again - should still be 3, not 6
	logger3, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to reopen: %v", err)
	}
	if logger3.entryCount != 3 {
		t.Errorf("expected entryCount=3 after second reopen, got %d", logger3.entryCount)
	}
	_ = logger3.Close()
}

func TestVerifyIntegrityDetailed_EmptyLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	result := logger.VerifyIntegrityDetailed(nil)
	if !result.Valid {
		t.Errorf("expected valid result for empty log, got error: %v", result.Error)
	}
	if result.EntryCount != 0 {
		t.Errorf("expected EntryCount=0, got %d", result.EntryCount)
	}
	if result.LastHash != zeroHash {
		t.Errorf("expected LastHash=%s, got %s", zeroHash, result.LastHash)
	}
	_ = logger.Close()
}

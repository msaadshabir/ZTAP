# Internal: Audit Log Integrity Hardening Implementation Plan

## Decision: Recommended Integrity Mode

**Default when enabled: Ed25519 signing with a stored keypair**

### Rationale
- Stronger security model: verifiers only need public key, not shared secret
- Non-repudiation properties useful for compliance/audit scenarios
- Public key can be distributed broadly without compromising integrity
- Better separation of concerns: writer has private key, readers/verifiers have public key

### When to use HMAC-SHA256
- Simpler operational requirements
- Single-node deployments where key distribution isn't a concern
- Performance-critical scenarios (though Ed25519 is quite fast)

## Implementation Phases

### Phase 1: Foundation & Bug Fixes

#### 1.1 Fix Reader Correctness Bug
**File:** `pkg/audit/audit.go`

Current issue: `VerifyIntegrity()` treats non-EOF decode errors as EOF:
```go
for {
    var entry AuditEntry
    if err := decoder.Decode(&entry); err != nil {
        break // EOF  <-- BUG: treats ANY error as EOF
    }
    // ...
}
```

**Fix:** Distinguish between EOF and actual errors:
```go
for {
    var entry AuditEntry
    if err := decoder.Decode(&entry); err != nil {
        if err == io.EOF {
            break
        }
        return false, fmt.Errorf("corrupted entry at position %d: %w", position, err)
    }
    // ...
}
```

Also fix `loadLastHash()` and `Query()` to handle decode errors properly.

#### 1.2 Add Sequence Numbers
**File:** `pkg/audit/audit.go`

Add to `AuditEntry`:
```go
type AuditEntry struct {
    // ... existing fields ...
    Seq int64 `json:"seq,omitempty"`  // Monotonic sequence number (1, 2, 3, ...)
}
```

Update `AuditLogger` to track and increment sequence counter:
```go
type AuditLogger struct {
    // ... existing fields ...
    nextSeq int64
}
```

### Phase 2: Cryptographic Primitives

#### 2.1 Create Signing Interface
**New File:** `pkg/audit/signer.go`

```go
package audit

import (
    "crypto/ed25519"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
)

// Signer provides cryptographic signing for audit entries
type Signer interface {
    Sign(data []byte) ([]byte, error)
    Algorithm() string
    KeyID() string
}

// Verifier provides cryptographic verification for audit entries
type Verifier interface {
    Verify(data []byte, sig []byte) (bool, error)
    Algorithm() string
    KeyID() string
}

// Ed25519Signer implements Signer using Ed25519
type Ed25519Signer struct {
    PrivateKey ed25519.PrivateKey
    PublicKey  ed25519.PublicKey
    keyID      string
}

func NewEd25519Signer(privateKey ed25519.PrivateKey, keyID string) *Ed25519Signer {
    return &Ed25519Signer{
        PrivateKey: privateKey,
        PublicKey:  privateKey.Public().(ed25519.PublicKey),
        keyID:      keyID,
    }
}

func (s *Ed25519Signer) Sign(data []byte) ([]byte, error) {
    return ed25519.Sign(s.PrivateKey, data), nil
}

func (s *Ed25519Signer) Algorithm() string { return "ed25519" }
func (s *Ed25519Signer) KeyID() string     { return s.keyID }

// Ed25519Verifier implements Verifier using Ed25519
type Ed25519Verifier struct {
    PublicKey ed25519.PublicKey
    keyID     string
}

func (v *Ed25519Verifier) Verify(data []byte, sig []byte) (bool, error) {
    return ed25519.Verify(v.PublicKey, data, sig), nil
}

func (v *Ed25519Verifier) Algorithm() string { return "ed25519" }
func (v *Ed25519Verifier) KeyID() string     { return v.keyID }

// HMACSigner implements Signer using HMAC-SHA256
type HMACSigner struct {
    key   []byte
    keyID string
}

func NewHMACSigner(key []byte, keyID string) *HMACSigner {
    return &HMACSigner{key: key, keyID: keyID}
}

func (s *HMACSigner) Sign(data []byte) ([]byte, error) {
    mac := hmac.New(sha256.New, s.key)
    mac.Write(data)
    return mac.Sum(nil), nil
}

func (s *HMACSigner) Algorithm() string { return "hmac-sha256" }
func (s *HMACSigner) KeyID() string     { return s.keyID }

// HMACVerifier implements Verifier using HMAC-SHA256
type HMACVerifier struct {
    key   []byte
    keyID string
}

func (v *HMACVerifier) Verify(data []byte, sig []byte) (bool, error) {
    mac := hmac.New(sha256.New, v.key)
    mac.Write(data)
    expected := mac.Sum(nil)
    return hmac.Equal(expected, sig), nil
}

func (v *HMACVerifier) Algorithm() string { return "hmac-sha256" }
func (v *HMACVerifier) KeyID() string     { return v.keyID }
```

#### 2.2 Add Signature to Audit Entry
**File:** `pkg/audit/audit.go`

Add to `AuditEntry`:
```go
type AuditEntry struct {
    // ... existing fields ...
    IntegrityAlg string `json:"integrity_alg,omitempty"`  // "ed25519" or "hmac-sha256"
    KeyID        string `json:"key_id,omitempty"`        // Identifier for the key used
    Sig          string `json:"sig,omitempty"`           // Hex-encoded signature/MAC
}
```

### Phase 3: Checkpoint System

#### 3.1 Checkpoint Structure
**New File:** `pkg/audit/checkpoint.go`

```go
package audit

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
)

// Checkpoint represents the state of the audit log at a point in time
type Checkpoint struct {
    LastSeq     int64     `json:"last_seq"`
    LastHash    string    `json:"last_hash"`
    EntryCount  int64     `json:"entry_count"`
    UpdatedAt   time.Time `json:"updated_at"`
    KeyID       string    `json:"key_id"`
    Algorithm   string    `json:"algorithm"`
    
    // Signature of the checkpoint itself
    Signature   string    `json:"signature"`
}

// CheckpointWriter handles writing checkpoints
type CheckpointWriter struct {
    signer Signer
    path   string
}

func NewCheckpointWriter(signer Signer, path string) *CheckpointWriter {
    return &CheckpointWriter{signer: signer, path: path}
}

func (cw *CheckpointWriter) Write(checkpoint Checkpoint) error {
    // Sign the checkpoint
    data := fmt.Sprintf("%d:%s:%d:%s:%s", 
        checkpoint.LastSeq, checkpoint.LastHash, 
        checkpoint.EntryCount, checkpoint.KeyID, checkpoint.Algorithm)
    sig, err := cw.signer.Sign([]byte(data))
    if err != nil {
        return fmt.Errorf("signing checkpoint: %w", err)
    }
    checkpoint.Signature = hex.EncodeToString(sig)
    
    // Write to temp file, then rename for atomicity
    tmpPath := cw.path + ".tmp"
    file, err := os.Create(tmpPath)
    if err != nil {
        return fmt.Errorf("creating checkpoint file: %w", err)
    }
    
    encoder := json.NewEncoder(file)
    if err := encoder.Encode(checkpoint); err != nil {
        file.Close()
        os.Remove(tmpPath)
        return fmt.Errorf("encoding checkpoint: %w", err)
    }
    
    file.Close()
    if err := os.Rename(tmpPath, cw.path); err != nil {
        os.Remove(tmpPath)
        return fmt.Errorf("renaming checkpoint file: %w", err)
    }
    
    return nil
}

// CheckpointReader handles reading and verifying checkpoints
type CheckpointReader struct {
    verifier Verifier
    path     string
}

func NewCheckpointReader(verifier Verifier, path string) *CheckpointReader {
    return &CheckpointReader{verifier: verifier, path: path}
}

func (cr *CheckpointReader) Read() (Checkpoint, error) {
    file, err := os.Open(cr.path)
    if err != nil {
        return Checkpoint{}, fmt.Errorf("opening checkpoint file: %w", err)
    }
    defer file.Close()
    
    var checkpoint Checkpoint
    decoder := json.NewDecoder(file)
    if err := decoder.Decode(&checkpoint); err != nil {
        return Checkpoint{}, fmt.Errorf("decoding checkpoint: %w", err)
    }
    
    // Verify signature
    data := fmt.Sprintf("%d:%s:%d:%s:%s",
        checkpoint.LastSeq, checkpoint.LastHash,
        checkpoint.EntryCount, checkpoint.KeyID, checkpoint.Algorithm)
    sig, err := hex.DecodeString(checkpoint.Signature)
    if err != nil {
        return Checkpoint{}, fmt.Errorf("decoding signature: %w", err)
    }
    
    valid, err := cr.verifier.Verify([]byte(data), sig)
    if err != nil {
        return Checkpoint{}, fmt.Errorf("verifying checkpoint: %w", err)
    }
    if !valid {
        return Checkpoint{}, fmt.Errorf("checkpoint signature invalid")
    }
    
    return checkpoint, nil
}
```

### Phase 4: Enhanced Audit Logger

#### 4.1 New Constructor with Options
**File:** `pkg/audit/audit.go`

```go
// AuditLoggerOptions configures the audit logger
type AuditLoggerOptions struct {
    LogPath         string
    Signer          Signer          // Optional: for per-entry signing
    CheckpointPath  string          // Optional: path to checkpoint file
    CheckpointInterval time.Duration // How often to write checkpoint (default: every 100 entries or 5 min)
    
    // For reading/verifying only
    Verifier Verifier  // Optional: for verification
}

// NewAuditLoggerWithOptions creates an audit logger with integrity features
func NewAuditLoggerWithOptions(opts AuditLoggerOptions) (*AuditLogger, error) {
    // Implementation...
}
```

#### 4.2 Update Log Method
**File:** `pkg/audit/audit.go`

```go
func (al *AuditLogger) LogWithOutcome(eventType EventType, actor, resource, action, outcome, errorMsg string, details map[string]interface{}) error {
    al.mu.Lock()
    defer al.mu.Unlock()

    entry := AuditEntry{
        ID:           generateID(),
        Timestamp:    time.Now().UTC(),
        EventType:    eventType,
        Actor:        actor,
        Resource:     resource,
        Action:       action,
        Details:      details,
        PreviousHash: al.lastHash,
        Outcome:      outcome,
        ErrorMessage: errorMsg,
        Seq:          al.nextSeq,  // Add sequence number
    }
    
    // Calculate hash (unchanged - this is the hash chain)
    entry.Hash = al.calculateHash(&entry)
    
    // If we have a signer, add cryptographic signature
    if al.signer != nil {
        entry.IntegrityAlg = al.signer.Algorithm()
        entry.KeyID = al.signer.KeyID()
        
        // Sign: hash + seq + timestamp (prevents replay)
        dataToSign := fmt.Sprintf("%s:%d:%s", entry.Hash, entry.Seq, entry.Timestamp.Format(time.RFC3339Nano))
        sig, err := al.signer.Sign([]byte(dataToSign))
        if err != nil {
            return fmt.Errorf("signing audit entry: %w", err)
        }
        entry.Sig = hex.EncodeToString(sig)
    }

    // Write to log file
    if err := al.encoder.Encode(entry); err != nil {
        return fmt.Errorf("failed to write audit entry: %w", err)
    }

    // Flush to ensure write
    if err := al.logFile.Sync(); err != nil {
        return fmt.Errorf("failed to sync audit log: %w", err)
    }

    // Update state
    al.lastHash = entry.Hash
    al.entryCount++
    al.nextSeq++
    
    // Write checkpoint if needed
    if al.checkpointWriter != nil && al.shouldWriteCheckpoint() {
        al.writeCheckpoint()
    }

    // Update index cache
    al.cacheMu.Lock()
    al.indexCache = append(al.indexCache, indexEntry{
        timestamp: entry.Timestamp,
        eventType: entry.EventType,
        actor:     entry.Actor,
        resource:  entry.Resource,
    })
    al.cacheMu.Unlock()

    return nil
}
```

#### 4.3 Enhanced VerifyIntegrity
**File:** `pkg/audit/audit.go`

```go
// VerifyResult contains detailed verification status
type VerifyResult struct {
    Valid              bool
    HashChainValid     bool
    SignatureValid     bool  // true if no sigs present or all sigs valid
    CheckpointValid    bool  // true if no checkpoint or checkpoint matches
    EntryCount         int64
    LastSeq            int64
    LastHash           string
    FirstInvalidEntry  string  // ID of first entry that failed
    Error              error
}

// VerifyIntegrityDetailed checks the audit log with full integrity verification
func (al *AuditLogger) VerifyIntegrityDetailed(verifier Verifier) VerifyResult {
    // ... implementation ...
}
```

### Phase 5: Key Management CLI

**File:** `cmd/audit.go` (new subcommands)

```go
var auditKeygenCmd = &cobra.Command{
    Use:   "keygen",
    Short: "Generate Ed25519 keypair for audit log signing",
    RunE: func(cmd *cobra.Command, args []string) error {
        outputDir, _ := cmd.Flags().GetString("output-dir")
        
        // Generate keypair
        pub, priv, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
            return fmt.Errorf("generating keypair: %w", err)
        }
        
        // Write private key (with 0600 permissions)
        privPath := filepath.Join(outputDir, "audit-signing.key")
        if err := os.WriteFile(privPath, priv, 0600); err != nil {
            return fmt.Errorf("writing private key: %w", err)
        }
        
        // Write public key
        pubPath := filepath.Join(outputDir, "audit-signing.pub")
        if err := os.WriteFile(pubPath, pub, 0644); err != nil {
            return fmt.Errorf("writing public key: %w", err)
        }
        
        fmt.Printf("Generated Ed25519 keypair:\n")
        fmt.Printf("  Private: %s (keep secure!)\n", privPath)
        fmt.Printf("  Public:  %s\n", pubPath)
        fmt.Printf("  Key ID:  %s\n", hex.EncodeToString(pub[:8]))
        
        return nil
    },
}

func init() {
    auditKeygenCmd.Flags().String("output-dir", "", "Directory to write keys (default: ~/.ztap)")
    auditCmd.AddCommand(auditKeygenCmd)
}
```

### Phase 6: Configuration Integration

**File:** `config.yaml.example` additions:

```yaml
# Audit logging settings (NEW SECTION)
audit:
  # Path to audit log file (default: ~/.ztap/audit.log)
  log_path: ""
  
  # Integrity mode: "none", "hmac-sha256", or "ed25519" (default: "none")
  # "none" = hash chaining only (legacy behavior)
  # "hmac-sha256" = HMAC-SHA256 per-entry signing
  # "ed25519" = Ed25519 per-entry signing (recommended)
  integrity_mode: "none"
  
  # Key identifier (used in audit entries)
  key_id: ""
  
  # For HMAC mode: path to file containing shared secret
  hmac_key_file: ""
  
  # For Ed25519 mode: path to private key file
  ed25519_private_key_file: ""
  
  # Checkpoint settings
  checkpoint_path: ""
  checkpoint_interval: "5m"  # Write checkpoint every N duration or 100 entries
  
  # Optional external anchoring
  anchor_url: ""  # HTTP endpoint to POST checkpoints
  anchor_interval: "1h"
```

**File:** `cmd/` (new config loader following pattern of `cmd/auth_sessions.go`):

```go
// loadAuditConfig loads audit configuration from config file and env vars
func loadAuditConfig() (audit.AuditLoggerOptions, error) {
    // Load from config.yaml...
    // Apply env var overrides (ZTAP_AUDIT_*)...
}
```

**Env vars to support:**
- `ZTAP_AUDIT_INTEGRITY_MODE`
- `ZTAP_AUDIT_KEY_ID`
- `ZTAP_AUDIT_HMAC_KEY_FILE`
- `ZTAP_AUDIT_ED25519_PRIVATE_KEY_FILE`
- `ZTAP_AUDIT_CHECKPOINT_PATH`
- `ZTAP_AUDIT_ANCHOR_URL`

### Phase 7: Enhanced Verify Command

**File:** `cmd/audit.go` (update verify)

```go
func runAuditVerify(cmd *cobra.Command, args []string) error {
    logPath, err := getAuditLogPath()
    if err != nil {
        return err
    }

    // Load config to determine if we should verify signatures
    cfg, err := loadAuditConfig()
    if err != nil {
        return err
    }

    logger, err := audit.NewAuditLoggerWithOptions(cfg)
    if err != nil {
        return fmt.Errorf("failed to open audit log: %w", err)
    }
    defer logger.Close()

    fmt.Println("Verifying audit log integrity...")
    fmt.Printf("Log file: %s\n\n", logPath)

    result := logger.VerifyIntegrityDetailed(cfg.Verifier)
    
    // Print detailed results
    fmt.Printf("[%-5s] Hash chain\n", statusString(result.HashChainValid))
    if cfg.Verifier != nil {
        fmt.Printf("[%-5s] Signatures (%s)\n", statusString(result.SignatureValid), cfg.Verifier.Algorithm())
    }
    if cfg.CheckpointPath != "" {
        fmt.Printf("[%-5s] Checkpoint\n", statusString(result.CheckpointValid))
    }
    fmt.Printf("\nEntries checked: %d\n", result.EntryCount)
    fmt.Printf("Last sequence: %d\n", result.LastSeq)
    
    if !result.Valid {
        fmt.Println("\n[FAIL] Audit log integrity check failed.")
        fmt.Println("       TAMPERING DETECTED!")
        if result.Error != nil {
            return result.Error
        }
        return fmt.Errorf("audit log has been tampered with")
    }

    fmt.Println("\n[PASS] Audit log integrity verified successfully.")
    fmt.Println("       No tampering detected.")
    return nil
}

func statusString(ok bool) string {
    if ok {
        return "PASS"
    }
    return "FAIL"
}
```

### Phase 8: External Anchoring (Optional)

**New File:** `pkg/audit/anchor.go`

```go
package audit

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

// AnchorClient pushes checkpoints to an external HTTP endpoint
type AnchorClient struct {
    url      string
    client   *http.Client
    interval time.Duration
}

func NewAnchorClient(url string, interval time.Duration) *AnchorClient {
    return &AnchorClient{
        url:      url,
        client:   &http.Client{Timeout: 30 * time.Second},
        interval: interval,
    }
}

func (ac *AnchorClient) Start(ctx context.Context, getCheckpoint func() (Checkpoint, error)) {
    ticker := time.NewTicker(ac.interval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            checkpoint, err := getCheckpoint()
            if err != nil {
                // Log error
                continue
            }
            
            data, _ := json.Marshal(checkpoint)
            resp, err := ac.client.Post(ac.url, "application/json", bytes.NewReader(data))
            if err != nil {
                // Log error
                continue
            }
            resp.Body.Close()
        }
    }
}
```

## Testing Plan

### Unit Tests

**File:** `pkg/audit/audit_test.go` (additions)

```go
func TestAuditLogger_Ed25519Signing(t *testing.T) {
    // Generate test keypair
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    signer := NewEd25519Signer(priv, "test-key")
    verifier := &Ed25519Verifier{PublicKey: pub, keyID: "test-key"}
    
    tmpDir := t.TempDir()
    opts := AuditLoggerOptions{
        LogPath: filepath.Join(tmpDir, "audit.log"),
        Signer:  signer,
    }
    
    logger, err := NewAuditLoggerWithOptions(opts)
    if err != nil {
        t.Fatalf("failed to create logger: %v", err)
    }
    
    // Log an entry
    err = logger.Log(EventPolicyCreated, "admin", "test-policy", "create", nil)
    if err != nil {
        t.Fatalf("failed to log: %v", err)
    }
    logger.Close()
    
    // Verify with correct key
    logger2, _ := NewAuditLoggerWithOptions(AuditLoggerOptions{
        LogPath:  opts.LogPath,
        Verifier: verifier,
    })
    result := logger2.VerifyIntegrityDetailed(verifier)
    if !result.Valid || !result.SignatureValid {
        t.Errorf("expected valid signature, got: %+v", result)
    }
    
    // Verify with wrong key should fail
    _, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
    wrongVerifier := &Ed25519Verifier{PublicKey: wrongPriv.Public().(ed25519.PublicKey), keyID: "wrong-key"}
    result2 := logger2.VerifyIntegrityDetailed(wrongVerifier)
    if result2.SignatureValid {
        t.Error("expected signature verification to fail with wrong key")
    }
}

func TestAuditLogger_TruncationDetection(t *testing.T) {
    // Create logger with checkpoint
    // Log N entries
    // Truncate file (remove last line)
    // Verify should detect truncation via checkpoint mismatch
}

func TestAuditLogger_TamperAndRecompute(t *testing.T) {
    // Create logger with signing
    // Log entries
    // Tamper with middle entry
    // Try to recompute hash chain
    // Signature verification should still fail
}

func TestVerifyIntegrity_DetectsCorruption(t *testing.T) {
    // Test that non-EOF decode errors are properly detected
}
```

### Integration Tests

**File:** `pkg/audit/integration_test.go` (new)

```go
// Test full workflow: keygen -> log with signing -> verify -> checkpoint -> truncate detection
func TestFullWorkflow(t *testing.T) {
    // Implementation
}
```

### Regression Tests

Ensure existing tests still pass:
- `TestAuditLogger_HashChaining`
- `TestAuditLogger_VerifyIntegrity`
- `TestAuditLogger_VerifyIntegrityDetectsTampering`
- `TestVerifyFileIntegrityAndQueryFile`
- `TestVerifyFileIntegrityDetectsTamper`

## Backwards Compatibility

### Strategy
1. **New fields are optional** - Old entries without `seq`, `integrity_alg`, `key_id`, `sig` are treated as unsigned
2. **Legacy constructor** - `NewAuditLogger(path)` continues to work with hash chaining only
3. **New constructor** - `NewAuditLoggerWithOptions(opts)` enables new features
4. **Verification** - `VerifyIntegrity()` works with both old and new logs
   - For old logs: checks hash chain only
   - For new logs: checks hash chain + signatures + checkpoint if configured

### Migration Path
1. Phase 1: Deploy with bug fixes (no breaking changes)
2. Phase 2: Deploy with signing enabled (writes signed entries, but can read old)
3. Phase 3: Enable checkpoint verification (optional)
4. Phase 4: (Future) Consider requiring signatures for new logs

## Security Considerations

### Threat Model

**Protected against:**
- Entry modification (both hash chain and signature would fail)
- Entry deletion in middle (hash chain breaks)
- Entry insertion in middle (hash chain breaks)
- Log truncation (checkpoint/anchor detection)
- Replay attacks (seq + timestamp in signature)

**NOT protected against:**
- Complete log deletion (no log = nothing to verify)
- Host compromise with key access (attacker can sign valid entries)
- Key compromise (attacker can generate valid signatures)
- Backup tampering (if attacker also tampers backups)
- Real-time tampering (attacker with write access can modify entries as written)

### Mitigations
- **Key protection**: Private key should have 0600 permissions, stored outside log directory
- **Key rotation**: Support multiple key IDs, old entries verified with old keys
- **External anchoring**: Push checkpoints to separate system (S3 with object lock, etc.)
- **Regular verification**: Run `ztap audit verify` on schedule and alert on failure

## Documentation Updates

**File:** `docs/audit.md` (sections to add)

1. **Integrity Modes**
   - Hash chaining (default, legacy)
   - HMAC-SHA256 (shared secret)
   - Ed25519 (keypair, recommended)

2. **Setup Instructions**
   - Generating keys: `ztap audit keygen`
   - Configuration examples

3. **Verification**
   - What each check means (hash chain, signatures, checkpoint)
   - Interpreting results

4. **Limitations**
   - What this doesn't protect against
   - Best practices for key management

5. **Compliance Notes**
   - How integrity features map to compliance requirements
   - Evidence preservation

## Implementation Order

1. ✅ **Week 1**: Phase 1 (bug fixes, seq numbers)
2. ✅ **Week 2**: Phase 2 (crypto primitives)
3. ✅ **Week 3**: Phase 3 (checkpoint system)
4. ✅ **Week 4**: Phase 4 (enhanced logger)
5. ✅ **Week 5**: Phase 5 (CLI keygen) + Phase 6 (config)
6. ✅ **Week 6**: Phase 7 (enhanced verify) + tests
7. ✅ **Week 7**: Phase 8 (anchoring, optional) + docs
8. ✅ **Week 8**: Integration testing, security review

## Rollback Plan

If issues arise:
1. Revert to `NewAuditLogger(path)` constructor (drop signing)
2. Old logs remain valid (hash chain still works)
3. New entries will be unsigned but still have hash chain
4. Can re-enable later with same keys

## Success Criteria

- [ ] All existing tests pass
- [ ] New tests for signing/verification pass
- [ ] Tampering detection works for all attack scenarios
- [ ] Checkpoint truncation detection works
- [ ] CLI keygen works and generates secure keys
- [ ] Config loading works from file and env vars
- [ ] Documentation is complete
- [ ] Security review completed
- [ ] No breaking changes to existing API

---

**Note**: This document is for internal implementation planning only. Delete after implementation is complete and tested.

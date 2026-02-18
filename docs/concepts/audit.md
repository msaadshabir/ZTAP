# Audit Logging System

Tamper-evident audit logging with SHA-256 hash chaining, optional signing, and CLI/API access.

## Overview

ZTAP includes a tamper-evident audit logging system that records all policy operations, user actions, and system events with cryptographic integrity guarantees. The audit log uses SHA-256 hash chaining to detect any tampering or unauthorized modifications.

## Features

- **Cryptographic Hash Chaining**: Each log entry contains the hash of the previous entry, creating an immutable chain
- **Optional Per-Entry Signatures**: HMAC-SHA256 or Ed25519 signing for stronger integrity
- **Checkpoint Support**: Periodic signed snapshots detect truncation
- **Comprehensive Event Tracking**: Records policy operations, user actions, cluster events, and service changes
- **Flexible Querying**: Filter logs by time range, event type, actor, resource, and more
- **CLI Integration**: Full command-line interface for viewing, verifying, and managing audit logs
- **Automatic Logging**: Policy enforcement operations are automatically logged
- **Concurrent-Safe**: Thread-safe design ensures correct hash chaining under concurrent writes

## Architecture

### Hash Chaining

Each audit entry contains:

- **Hash**: SHA-256 hash of the current entry's content
- **Previous Hash**: Hash of the immediately preceding entry
- **Seq**: Monotonic sequence number
- **Signature Fields** (optional): `integrity_alg`, `key_id`, `sig`

This creates a blockchain-like structure where any modification to a past entry breaks the chain, making tampering immediately detectable.

```
Entry 1: hash=A, previous=0
Entry 2: hash=B, previous=A
Entry 3: hash=C, previous=B
...
```

If Entry 2 is modified, its hash changes to B', breaking the chain at Entry 3 (which expects previous=B, not B').

### Event Types

The audit system tracks the following event types:

#### Policy Events

- `policy.created` - New policy created
- `policy.updated` - Policy modified
- `policy.deleted` - Policy removed
- `policy.enforced` - Policy applied to system

Note: policy rollback is recorded as a `policy.updated` event with action `rollback`.

#### User Events

- `user.created` - New user account created
- `user.login` - User authentication
- `user.logout` - User session ended
- `user.disabled` - User account disabled
- `user.enabled` - User account enabled

#### Service Events

- `service.added` - Service registered in discovery
- `service.removed` - Service deregistered

#### Cluster Events

- `cluster.joined` - Node joined cluster
- `cluster.left` - Node left cluster
- `cluster.leader_elected` - New leader elected

### Storage Format

Audit logs are stored as newline-delimited JSON (NDJSON) in `~/.ztap/audit.log`:

```json
{"id":"1729800000000-12345","timestamp":"2025-10-24T12:00:00Z","event_type":"policy.created","actor":"admin","resource":"default/web-policy","action":"created","details":{"version":1},"previous_hash":"0000...","hash":"a1b2...","outcome":"success","seq":1,"integrity_alg":"ed25519","key_id":"abcd1234","sig":"deadbeef..."}
{"id":"1729800060000-12346","timestamp":"2025-10-24T12:01:00Z","event_type":"policy.enforced","actor":"system","resource":"default/web-policy","action":"enforce","details":{"version":1,"duration_ms":45.2,"dry_run":false},"previous_hash":"a1b2...","hash":"c3d4...","outcome":"success","seq":2,"integrity_alg":"ed25519","key_id":"abcd1234","sig":"deadbeef..."}
```

In Kubernetes deployments, `resource` is typically `namespace/policy`.

Note: `policy.enforced` events include a `dry_run` field in `details` to indicate if the enforcement was simulated. Signature fields are omitted when integrity mode is disabled.

## CLI Commands

### View Audit Logs

```bash
# View recent entries (default: last 50)
ztap audit view

# Filter by event type
ztap audit view --type policy.created
ztap audit view --type user.login

# Filter by actor (user or system)
ztap audit view --actor admin
ztap audit view --actor system

# Filter by resource
ztap audit view --resource default/web-policy

# Filter by time range (RFC3339 format)
ztap audit view --start 2025-10-24T00:00:00Z --end 2025-10-24T23:59:59Z

# Limit number of results
ztap audit view --limit 100

# Combine filters
ztap audit view --actor admin --type policy.created --limit 20
```

### Verify Integrity

```bash
# Verify the entire audit log for tampering
ztap audit verify
```

Output:

```
Verifying audit log integrity...
Log file: /Users/username/.ztap/audit.log

[PASS ] Hash chain
[PASS ] Signatures (ed25519)
[PASS ] Checkpoint

Entries checked: 127
Last sequence: 127

[PASS] Audit log integrity verified successfully.
       No tampering detected.
```

If tampering is detected:

```
[FAIL] Audit log integrity check failed.
       TAMPERING DETECTED!
Error: entry 1729800060000-12346 has been tampered with
```

### Display Statistics

```bash
# Show audit log statistics
ztap audit stats
```

Output:

```
Audit Log Statistics
====================
Path:         /Users/username/.ztap/audit.log
Size:         45823 bytes (44.75 KB)
Entry Count:  127
Last Hash:    c3d4e5f6a7b8...
Modified:     2025-10-24T12:30:15Z
```

## Integration with Policy Enforcer

The audit logger is automatically integrated into the PolicyEnforcer, logging all enforcement operations:

```go
// Successful policy enforcement
{
    "event_type": "policy.enforced",
    "actor": "system",
    "resource": "default/web-policy",
    "action": "enforce",
    "details": {
        "version": 1,
        "source": "node-1",
        "duration_ms": 45.2
    },
    "outcome": "success"
}

// Failed policy enforcement
{
    "event_type": "policy.enforced",
    "actor": "system",
    "resource": "invalid-policy",
    "action": "enforce",
    "details": {
        "version": 1,
        "source": "node-1"
    },
    "outcome": "failure",
    "error_message": "invalid CIDR format: 999.999.999.999/99"
}
```

## Programmatic Usage

### Creating an Audit Logger

```go
import "ztap/pkg/audit"

// Create audit logger (hash chaining only)
logger, err := audit.NewAuditLogger("/path/to/audit.log")
if err != nil {
    log.Fatal(err)
}
defer logger.Close()

// Create audit logger with signing + checkpoints
logger2, err := audit.NewAuditLoggerWithOptions(audit.AuditLoggerOptions{
    LogPath:        "/path/to/audit.log",
    Signer:         signer,
    CheckpointPath: "/path/to/audit.log.checkpoint",
})
if err != nil {
    log.Fatal(err)
}
defer logger2.Close()
```

### Logging Events

```go
// Log successful operation
details := map[string]interface{}{
    "policy_name": "web-policy",
    "version":     1,
}
err = logger.Log(audit.EventPolicyCreated, "admin", "web-policy", "created", details)

// Log failed operation
err = logger.LogFailure(audit.EventPolicyCreated, "admin", "invalid-policy", "created",
    "invalid CIDR format", details)
```

### Querying Logs

```go
// Query by event type
eventType := audit.EventPolicyCreated
opts := audit.QueryOptions{
    EventType: &eventType,
    Limit:     50,
}
entries, err := logger.Query(opts)

// Query by time range
now := time.Now()
yesterday := now.Add(-24 * time.Hour)
opts := audit.QueryOptions{
    StartTime: &yesterday,
    EndTime:   &now,
}
entries, err := logger.Query(opts)

// Query by actor
actor := "admin"
opts := audit.QueryOptions{
    Actor: &actor,
    Limit: 100,
}
entries, err := logger.Query(opts)
```

### Verifying Integrity

```go
// Verify entire log (hash chain only)
valid, err := logger.VerifyIntegrity()
if err != nil {
    log.Printf("Integrity check failed: %v", err)
}

if !valid {
    log.Println("TAMPERING DETECTED!")
}

// Detailed verification with signatures/checkpoints
result := logger.VerifyIntegrityDetailed(verifier)
if !result.Valid {
    log.Printf("Integrity check failed: %v", result.Error)
}
```

## Security Considerations

### What the Audit System Protects Against

1. **Unauthorized Modifications**: Any change to past log entries is immediately detectable
2. **Entry Deletion**: Deleting entries breaks the hash chain
3. **Entry Insertion**: Inserting entries into the middle of the log breaks the chain
4. **Reordering**: Changing the order of entries breaks the chain

### What the Audit System Does NOT Protect Against

1. **Complete Log Deletion**: If the entire log file is deleted, there's no chain to verify
2. **Backup Tampering**: If an attacker has access to modify both the log and backups
3. **Real-Time Modification**: An attacker with write access could modify entries as they're written

### Best Practices

1. **Regular Backups**: Back up audit logs to immutable storage (e.g., AWS S3 with object lock)
2. **Periodic Verification**: Run `ztap audit verify` regularly to detect tampering
3. **File Permissions**: Set audit log to read-only for non-admin users (chmod 600)
4. **External Monitoring**: Send audit events to external SIEM system for redundancy
5. **Archive Old Logs**: Rotate and archive logs periodically while maintaining chain integrity

## Compliance

The audit logging system helps meet compliance requirements for:

- **NIST SP 800-207** (Zero Trust Architecture): Section 3.6 - Audit and Monitoring
- **SOC 2 Type II**: CC7.2 - System Operations monitoring
- **ISO 27001**: A.12.4.1 - Event logging
- **PCI DSS**: Requirement 10 - Track and monitor all access to network resources
- **HIPAA**: 164.312(b) - Audit controls

ZTAP compliance reports (see [Compliance Reporting](compliance.md)) use the audit log for:

- integrity verification (hash chain)
- enforcement evidence (`policy.enforced` events)

## Testing

The audit system includes comprehensive tests:

```bash
# Run audit package tests
go test ./pkg/audit -v -cover

# Expected output:
# PASS: TestNewAuditLogger
# PASS: TestAuditLogger_Log
# PASS: TestAuditLogger_LogFailure
# PASS: TestAuditLogger_HashChaining
# PASS: TestAuditLogger_VerifyIntegrity
# PASS: TestAuditLogger_VerifyIntegrityDetectsTampering
# PASS: TestAuditLogger_Ed25519Signing
# PASS: TestAuditLogger_TruncationDetection
# PASS: TestAuditLogger_TamperAndRecompute
# PASS: TestVerifyIntegrity_DetectsCorruption
# PASS: TestFullWorkflow
# PASS: TestAuditLogger_Query
# PASS: TestAuditLogger_QueryByResource
# PASS: TestAuditLogger_GetStats
# PASS: TestAuditLogger_Persistence
# PASS: TestAuditLogger_ConcurrentWrites
# PASS: TestVerifyFileIntegrityAndQueryFile
# PASS: TestVerifyFileIntegrityDetectsTamper
# coverage: (varies)
```

## Performance

- **Write Performance**: ~10,000 entries/second on modern hardware
- **Read Performance**: ~50,000 entries/second for sequential reads
- **Verification Performance**: ~20,000 entries/second during integrity checks
- **Storage**: ~500 bytes per entry (average with typical details)

## Troubleshooting

### "Failed to initialize audit logger"

**Cause**: Unable to create or open audit log file

**Solution**:

```bash
# Ensure .ztap directory exists
mkdir -p ~/.ztap

# Check permissions
chmod 755 ~/.ztap
chmod 600 ~/.ztap/audit.log  # if file exists
```

### "Integrity check failed: hash chain broken"

**Cause**: Audit log has been tampered with

**Actions**:

1. Immediately investigate security breach
2. Compare with backup copies
3. Review recent system access logs
4. Report to security team

### Large Audit Log Files

**Solution**: Implement log rotation

```bash
# Archive old logs (preserving chain)
mv ~/.ztap/audit.log ~/.ztap/audit-$(date +%Y%m%d).log

# Verify archive integrity
ztap audit verify

# Start new log (new chain)
# Next audit event will create new file
```

## References

- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [Blockchain Data Structures](https://en.wikipedia.org/wiki/Blockchain)

---

**See Also:**

- [Architecture](architecture.md)
- [Testing Guide](../guides/testing.md)

### Generate Signing Keys

```bash
ztap audit keygen --output-dir ~/.ztap
```

### Configuration

Audit logging can be configured via `config.yaml` (or a file path set via `ZTAP_CONFIG`) and environment variables.

Example `config.yaml`:

```yaml
audit:
  log_path: "~/.ztap/audit.log"
  integrity_mode: "ed25519" # none | hmac-sha256 | ed25519
  key_id: ""                # optional
  ed25519_private_key_file: "~/.ztap/audit-signing.key"
  checkpoint_path: "~/.ztap/audit.log.checkpoint"
  checkpoint_interval: "5m"
```

Environment variables:

- `ZTAP_AUDIT_LOG_PATH`
- `ZTAP_AUDIT_INTEGRITY_MODE`
- `ZTAP_AUDIT_KEY_ID`
- `ZTAP_AUDIT_HMAC_KEY_FILE`
- `ZTAP_AUDIT_ED25519_PRIVATE_KEY_FILE`
- `ZTAP_AUDIT_CHECKPOINT_PATH`
- `ZTAP_AUDIT_CHECKPOINT_INTERVAL`

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType represents the type of audit event.
type EventType string

const (
	EventPolicyCreated  EventType = "policy.created"
	EventPolicyUpdated  EventType = "policy.updated"
	EventPolicyDeleted  EventType = "policy.deleted"
	EventPolicyEnforced EventType = "policy.enforced"
	EventUserCreated    EventType = "user.created"
	EventUserLogin      EventType = "user.login"
	EventUserLogout     EventType = "user.logout"
	EventUserDisabled   EventType = "user.disabled"
	EventUserEnabled    EventType = "user.enabled"
	EventServiceAdded   EventType = "service.added"
	EventServiceRemoved EventType = "service.removed"
	EventClusterJoined  EventType = "cluster.joined"
	EventClusterLeft    EventType = "cluster.left"
	EventLeaderElected  EventType = "cluster.leader_elected"
)

// AuditEntry represents a single audit log entry with cryptographic integrity.
type AuditEntry struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    EventType              `json:"event_type"`
	Actor        string                 `json:"actor"`         // Username or system identifier
	Resource     string                 `json:"resource"`      // Policy name, service ID, etc.
	Action       string                 `json:"action"`        // Created, updated, deleted, etc.
	Details      map[string]interface{} `json:"details"`       // Additional context
	PreviousHash string                 `json:"previous_hash"` // Hash of previous entry
	Hash         string                 `json:"hash"`          // SHA-256 hash of this entry
	Outcome      string                 `json:"outcome"`       // Success, failure, error
	ErrorMessage string                 `json:"error_message,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	NodeID       string                 `json:"node_id,omitempty"` // For distributed deployments
}

// AuditLogger provides tamper-proof audit logging with cryptographic hash chaining.
type AuditLogger struct {
	mu         sync.RWMutex
	logFile    *os.File
	logPath    string
	lastHash   string
	entryCount int64
	encoder    *json.Encoder
}

// NewAuditLogger creates a new audit logger instance.
// The log file is append-only and uses hash chaining to detect tampering.
func NewAuditLogger(logPath string) (*AuditLogger, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	logger := &AuditLogger{
		logFile:  file,
		logPath:  logPath,
		lastHash: "0000000000000000000000000000000000000000000000000000000000000000",
		encoder:  json.NewEncoder(file),
	}

	// Load last hash from existing log file
	if err := logger.loadLastHash(); err != nil {
		return nil, fmt.Errorf("failed to load last hash: %w", err)
	}

	return logger, nil
}

// Log creates a new audit entry with the given parameters.
func (al *AuditLogger) Log(eventType EventType, actor, resource, action string, details map[string]interface{}) error {
	return al.LogWithOutcome(eventType, actor, resource, action, "success", "", details)
}

// LogWithOutcome creates a new audit entry with a specific outcome.
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
	}

	// Calculate hash of this entry
	entry.Hash = al.calculateHash(&entry)

	// Write to log file
	if err := al.encoder.Encode(entry); err != nil {
		return fmt.Errorf("failed to write audit entry: %w", err)
	}

	// Flush to ensure write
	if err := al.logFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync audit log: %w", err)
	}

	// Update last hash and counter
	al.lastHash = entry.Hash
	al.entryCount++

	return nil
}

// LogFailure creates an audit entry for a failed operation.
func (al *AuditLogger) LogFailure(eventType EventType, actor, resource, action, errorMsg string, details map[string]interface{}) error {
	return al.LogWithOutcome(eventType, actor, resource, action, "failure", errorMsg, details)
}

// Query retrieves audit entries matching the specified filters.
type QueryOptions struct {
	StartTime *time.Time
	EndTime   *time.Time
	EventType *EventType
	Actor     *string
	Resource  *string
	Limit     int
}

// Query returns audit entries matching the given filters.
func (al *AuditLogger) Query(opts QueryOptions) ([]AuditEntry, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	file, err := os.Open(al.logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer file.Close()

	var entries []AuditEntry
	decoder := json.NewDecoder(file)

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			break // EOF or error
		}

		// Apply filters
		if opts.StartTime != nil && entry.Timestamp.Before(*opts.StartTime) {
			continue
		}
		if opts.EndTime != nil && entry.Timestamp.After(*opts.EndTime) {
			continue
		}
		if opts.EventType != nil && entry.EventType != *opts.EventType {
			continue
		}
		if opts.Actor != nil && entry.Actor != *opts.Actor {
			continue
		}
		if opts.Resource != nil && entry.Resource != *opts.Resource {
			continue
		}

		entries = append(entries, entry)

		// Apply limit
		if opts.Limit > 0 && len(entries) >= opts.Limit {
			break
		}
	}

	return entries, nil
}

// VerifyIntegrity checks the entire audit log for tampering.
// Returns true if the log is intact, false if tampering is detected.
func (al *AuditLogger) VerifyIntegrity() (bool, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	file, err := os.Open(al.logPath)
	if err != nil {
		return false, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	previousHash := "0000000000000000000000000000000000000000000000000000000000000000"

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			break // EOF
		}

		// Verify previous hash matches
		if entry.PreviousHash != previousHash {
			return false, fmt.Errorf("hash chain broken at entry %s: expected previous hash %s, got %s",
				entry.ID, previousHash, entry.PreviousHash)
		}

		// Verify entry hash
		expectedHash := al.calculateHash(&entry)
		if entry.Hash != expectedHash {
			return false, fmt.Errorf("entry %s has been tampered with: expected hash %s, got %s",
				entry.ID, expectedHash, entry.Hash)
		}

		previousHash = entry.Hash
	}

	return true, nil
}

// Close closes the audit log file.
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.logFile != nil {
		return al.logFile.Close()
	}
	return nil
}

// GetStats returns statistics about the audit log.
func (al *AuditLogger) GetStats() (map[string]interface{}, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	fileInfo, err := os.Stat(al.logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat audit log: %w", err)
	}

	stats := map[string]interface{}{
		"path":        al.logPath,
		"size_bytes":  fileInfo.Size(),
		"entry_count": al.entryCount,
		"last_hash":   al.lastHash,
		"modified_at": fileInfo.ModTime(),
	}

	return stats, nil
}

// calculateHash computes SHA-256 hash of the entry (excluding the Hash field itself).
func (al *AuditLogger) calculateHash(entry *AuditEntry) string {
	// Create a copy without the hash field for hashing
	data := struct {
		ID           string                 `json:"id"`
		Timestamp    time.Time              `json:"timestamp"`
		EventType    EventType              `json:"event_type"`
		Actor        string                 `json:"actor"`
		Resource     string                 `json:"resource"`
		Action       string                 `json:"action"`
		Details      map[string]interface{} `json:"details"`
		PreviousHash string                 `json:"previous_hash"`
		Outcome      string                 `json:"outcome"`
		ErrorMessage string                 `json:"error_message,omitempty"`
		IPAddress    string                 `json:"ip_address,omitempty"`
		NodeID       string                 `json:"node_id,omitempty"`
	}{
		ID:           entry.ID,
		Timestamp:    entry.Timestamp,
		EventType:    entry.EventType,
		Actor:        entry.Actor,
		Resource:     entry.Resource,
		Action:       entry.Action,
		Details:      entry.Details,
		PreviousHash: entry.PreviousHash,
		Outcome:      entry.Outcome,
		ErrorMessage: entry.ErrorMessage,
		IPAddress:    entry.IPAddress,
		NodeID:       entry.NodeID,
	}

	jsonBytes, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// loadLastHash reads the audit log and retrieves the last entry's hash.
func (al *AuditLogger) loadLastHash() error {
	file, err := os.Open(al.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // New log file
		}
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var lastEntry AuditEntry

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			break // EOF
		}
		lastEntry = entry
		al.entryCount++
	}

	if lastEntry.Hash != "" {
		al.lastHash = lastEntry.Hash
	}

	return nil
}

// generateID creates a unique identifier for an audit entry.
func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

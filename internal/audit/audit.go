package audit

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ztap/internal/logging"
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

const (
	zeroHash                  = "0000000000000000000000000000000000000000000000000000000000000000"
	checkpointEntryInterval   = int64(100)
	defaultCheckpointInterval = 5 * time.Minute
)

// AuditEntry represents a single audit log entry with cryptographic integrity.
type AuditEntry struct {
	ID           string         `json:"id"`
	Timestamp    time.Time      `json:"timestamp"`
	EventType    EventType      `json:"event_type"`
	Actor        string         `json:"actor"`         // Username or system identifier
	Resource     string         `json:"resource"`      // Policy name, service ID, etc.
	Action       string         `json:"action"`        // Created, updated, deleted, etc.
	Details      map[string]any `json:"details"`       // Additional context
	PreviousHash string         `json:"previous_hash"` // Hash of previous entry
	Hash         string         `json:"hash"`          // SHA-256 hash of this entry
	Outcome      string         `json:"outcome"`       // Success, failure, error
	ErrorMessage string         `json:"error_message,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	NodeID       string         `json:"node_id,omitempty"` // For distributed deployments
	Seq          int64          `json:"seq,omitempty"`
	IntegrityAlg string         `json:"integrity_alg,omitempty"`
	KeyID        string         `json:"key_id,omitempty"`
	Sig          string         `json:"sig,omitempty"`
}

// AuditLogger provides tamper-proof audit logging with cryptographic hash chaining.
type AuditLogger struct {
	mu         sync.RWMutex
	logFile    *os.File
	logPath    string
	lastHash   string
	entryCount int64
	encoder    *json.Encoder
	indexCache []indexEntry // Cache for faster queries
	cacheMu    sync.RWMutex
	cacheValid bool

	signer             Signer
	checkpointWriter   *CheckpointWriter
	checkpointPath     string
	checkpointInterval time.Duration
	lastCheckpointAt   time.Time

	nextSeq int64
}

// AuditLoggerOptions configures the audit logger with integrity features.
type AuditLoggerOptions struct {
	LogPath            string
	Signer             Signer
	CheckpointPath     string
	CheckpointInterval time.Duration
}

// indexEntry provides quick access to audit entries
// The offset field is not used for file seeking (which would be complex with variable-length JSON)
// but reserved for potential future use
type indexEntry struct {
	timestamp time.Time
	eventType EventType
	actor     string
	resource  string
}

// NewAuditLogger creates a new audit logger instance.
// The log file is append-only and uses hash chaining to detect tampering.
func NewAuditLogger(logPath string) (*AuditLogger, error) {
	return NewAuditLoggerWithOptions(AuditLoggerOptions{LogPath: logPath})
}

// NewAuditLoggerWithOptions creates an audit logger with integrity features.
func NewAuditLoggerWithOptions(opts AuditLoggerOptions) (*AuditLogger, error) {
	if opts.LogPath == "" {
		return nil, errors.New("audit log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(opts.LogPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	file, err := os.OpenFile(opts.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	logger := &AuditLogger{
		logFile:            file,
		logPath:            opts.LogPath,
		lastHash:           zeroHash,
		encoder:            json.NewEncoder(file),
		indexCache:         make([]indexEntry, 0, 1000),
		cacheValid:         false,
		signer:             opts.Signer,
		checkpointPath:     opts.CheckpointPath,
		checkpointInterval: opts.CheckpointInterval,
		nextSeq:            1,
	}

	if logger.checkpointInterval <= 0 {
		logger.checkpointInterval = defaultCheckpointInterval
	}

	if logger.checkpointPath != "" && opts.Signer != nil {
		if err := os.MkdirAll(filepath.Dir(logger.checkpointPath), 0700); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("failed to create checkpoint directory: %w", err)
		}
		logger.checkpointWriter = NewCheckpointWriter(opts.Signer, logger.checkpointPath)
	}

	if err := logger.loadLastHash(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to load last hash: %w", err)
	}

	return logger, nil
}

// Log creates a new audit entry with the given parameters.
func (al *AuditLogger) Log(eventType EventType, actor, resource, action string, details map[string]any) error {
	return al.LogWithOutcome(eventType, actor, resource, action, "success", "", details)
}

// LogWithOutcome creates a new audit entry with a specific outcome.
func (al *AuditLogger) LogWithOutcome(eventType EventType, actor, resource, action, outcome, errorMsg string, details map[string]any) error {
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
		Seq:          al.nextSeq,
	}

	// Calculate hash of this entry
	hash, err := al.calculateHash(&entry)
	if err != nil {
		return fmt.Errorf("failed to calculate entry hash: %w", err)
	}
	entry.Hash = hash

	// Sign entry if signer is configured
	if al.signer != nil {
		entry.IntegrityAlg = al.signer.Algorithm()
		entry.KeyID = al.signer.KeyID()
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

	// Update last hash and counter
	al.lastHash = entry.Hash
	al.entryCount++
	al.nextSeq++

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

// LogFailure creates an audit entry for a failed operation.
func (al *AuditLogger) LogFailure(eventType EventType, actor, resource, action, errorMsg string, details map[string]any) error {
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
	defer func() { _ = file.Close() }()

	// Pre-allocate with estimated capacity
	estimatedSize := 100
	if opts.Limit > 0 && opts.Limit < estimatedSize {
		estimatedSize = opts.Limit
	}
	entries := make([]AuditEntry, 0, estimatedSize)

	// Use index cache for faster filtering when available
	al.cacheMu.RLock()
	canUseCache := al.cacheValid && len(al.indexCache) > 0
	cacheLen := len(al.indexCache)
	al.cacheMu.RUnlock()

	decoder := json.NewDecoder(file)
	entryNum := 0

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("corrupted entry at position %d: %w", entryNum, err)
		}

		// Fast path: use cache to skip entries that don't match (if within cache bounds)
		if canUseCache && entryNum < cacheLen {
			idx := al.indexCache[entryNum]

			// Pre-filter using cache before full decode
			if opts.EventType != nil && idx.eventType != *opts.EventType {
				entryNum++
				continue
			}
			if opts.Actor != nil && idx.actor != *opts.Actor {
				entryNum++
				continue
			}
			if opts.Resource != nil && idx.resource != *opts.Resource {
				entryNum++
				continue
			}
			if opts.StartTime != nil && idx.timestamp.Before(*opts.StartTime) {
				entryNum++
				continue
			}
			if opts.EndTime != nil && idx.timestamp.After(*opts.EndTime) {
				entryNum++
				continue
			}
		}
		entryNum++

		// Apply filters on full entry
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
	defer func() { _ = file.Close() }()

	decoder := json.NewDecoder(file)
	previousHash := zeroHash
	position := 0

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false, fmt.Errorf("corrupted entry at position %d: %w", position, err)
		}

		// Verify previous hash matches
		if entry.PreviousHash != previousHash {
			return false, fmt.Errorf("hash chain broken at entry %s: expected previous hash %s, got %s",
				entry.ID, previousHash, entry.PreviousHash)
		}

		// Verify entry hash
		expectedHash, err := al.calculateHash(&entry)
		if err != nil {
			return false, fmt.Errorf("failed to calculate hash at position %d: %w", position, err)
		}
		if entry.Hash != expectedHash {
			return false, fmt.Errorf("entry %s has been tampered with: expected hash %s, got %s",
				entry.ID, expectedHash, entry.Hash)
		}

		previousHash = entry.Hash
		position++
	}

	return true, nil
}

// VerifyResult contains detailed verification status.
type VerifyResult struct {
	Valid             bool
	HashChainValid    bool
	SignatureValid    bool
	CheckpointValid   bool
	EntryCount        int64
	LastSeq           int64
	LastHash          string
	FirstInvalidEntry string
	Error             error
}

// VerifyIntegrityDetailed checks the audit log with full integrity verification.
func (al *AuditLogger) VerifyIntegrityDetailed(verifier Verifier) VerifyResult {
	al.mu.RLock()
	defer al.mu.RUnlock()

	result := VerifyResult{
		Valid:           true,
		HashChainValid:  true,
		SignatureValid:  true,
		CheckpointValid: true,
		LastHash:        zeroHash,
	}

	file, err := os.Open(al.logPath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Errorf("failed to open audit log: %w", err)
		return result
	}
	defer func() { _ = file.Close() }()

	decoder := json.NewDecoder(file)
	previousHash := zeroHash
	position := int64(0)
	var lastSeq int64
	var lastHash string

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			result.Valid = false
			result.HashChainValid = false
			result.Error = fmt.Errorf("corrupted entry at position %d: %w", position, err)
			return result
		}
		position++
		lastSeq = entry.Seq
		lastHash = entry.Hash

		if entry.PreviousHash != previousHash {
			result.Valid = false
			result.HashChainValid = false
			result.FirstInvalidEntry = entry.ID
			result.Error = fmt.Errorf("hash chain broken at entry %s: expected previous hash %s, got %s",
				entry.ID, previousHash, entry.PreviousHash)
			return result
		}

		expectedHash, err := al.calculateHash(&entry)
		if err != nil {
			result.Valid = false
			result.HashChainValid = false
			result.FirstInvalidEntry = entry.ID
			result.Error = fmt.Errorf("failed to calculate hash at entry %s: %w", entry.ID, err)
			return result
		}
		if entry.Hash != expectedHash {
			result.Valid = false
			result.HashChainValid = false
			result.FirstInvalidEntry = entry.ID
			result.Error = fmt.Errorf("entry %s has been tampered with: expected hash %s, got %s",
				entry.ID, expectedHash, entry.Hash)
			return result
		}

		if entry.Sig != "" {
			if verifier == nil {
				result.Valid = false
				result.SignatureValid = false
				result.FirstInvalidEntry = entry.ID
				result.Error = errors.New("signature present but no verifier configured")
				return result
			}
			if entry.IntegrityAlg != verifier.Algorithm() {
				result.Valid = false
				result.SignatureValid = false
				result.FirstInvalidEntry = entry.ID
				result.Error = fmt.Errorf("signature algorithm mismatch at entry %s", entry.ID)
				return result
			}
			if entry.KeyID != "" && verifier.KeyID() != "" && entry.KeyID != verifier.KeyID() {
				result.Valid = false
				result.SignatureValid = false
				result.FirstInvalidEntry = entry.ID
				result.Error = fmt.Errorf("signature key id mismatch at entry %s", entry.ID)
				return result
			}
			decodedSig, err := hex.DecodeString(entry.Sig)
			if err != nil {
				result.Valid = false
				result.SignatureValid = false
				result.FirstInvalidEntry = entry.ID
				result.Error = fmt.Errorf("invalid signature encoding at entry %s: %w", entry.ID, err)
				return result
			}
			dataToVerify := fmt.Sprintf("%s:%d:%s", entry.Hash, entry.Seq, entry.Timestamp.Format(time.RFC3339Nano))
			ok, err := verifier.Verify([]byte(dataToVerify), decodedSig)
			if err != nil || !ok {
				result.Valid = false
				result.SignatureValid = false
				result.FirstInvalidEntry = entry.ID
				if err != nil {
					result.Error = fmt.Errorf("signature verification error at entry %s: %w", entry.ID, err)
				} else {
					result.Error = fmt.Errorf("signature verification failed at entry %s", entry.ID)
				}
				return result
			}
		}
		if entry.Sig == "" && (entry.IntegrityAlg != "" || entry.KeyID != "") {
			result.Valid = false
			result.SignatureValid = false
			result.FirstInvalidEntry = entry.ID
			result.Error = fmt.Errorf("signature metadata present without signature at entry %s", entry.ID)
			return result
		}

		previousHash = entry.Hash
	}

	result.EntryCount = position
	result.LastSeq = lastSeq
	if lastHash != "" {
		result.LastHash = lastHash
	}

	if al.checkpointPath != "" {
		if verifier == nil {
			result.Valid = false
			result.CheckpointValid = false
			result.Error = errors.New("checkpoint configured but no verifier provided")
			return result
		}
		checkpointReader := NewCheckpointReader(verifier, al.checkpointPath)
		checkpoint, err := checkpointReader.Read()
		if err != nil {
			result.Valid = false
			result.CheckpointValid = false
			result.Error = err
			return result
		}
		if checkpoint.EntryCount != result.EntryCount || checkpoint.LastHash != result.LastHash || checkpoint.LastSeq != result.LastSeq {
			result.Valid = false
			result.CheckpointValid = false
			result.Error = errors.New("checkpoint mismatch")
			return result
		}
	}

	return result
}

// Close closes the audit log file.
func (al *AuditLogger) Ready(ctx context.Context) error {
	_ = ctx

	al.mu.RLock()
	f := al.logFile
	path := al.logPath
	al.mu.RUnlock()

	if f == nil {
		return errors.New("audit log file is nil")
	}
	if _, err := f.Stat(); err != nil {
		return fmt.Errorf("stat audit log file: %w", err)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("stat audit log path: %w", err)
	}
	return nil
}

func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.checkpointWriter != nil && al.signer != nil {
		checkpoint := Checkpoint{
			LastSeq:    al.nextSeq - 1,
			LastHash:   al.lastHash,
			EntryCount: al.entryCount,
			UpdatedAt:  time.Now().UTC(),
			KeyID:      al.signer.KeyID(),
			Algorithm:  al.signer.Algorithm(),
		}
		if err := al.checkpointWriter.Write(checkpoint); err != nil {
			logging.Warnf("failed to write final checkpoint: %v", err)
		}
	}
	if al.logFile != nil {
		return al.logFile.Close()
	}
	return nil
}

// GetStats returns statistics about the audit log.
func (al *AuditLogger) GetStats() (map[string]any, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	fileInfo, err := os.Stat(al.logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat audit log: %w", err)
	}

	stats := map[string]any{
		"path":        al.logPath,
		"size_bytes":  fileInfo.Size(),
		"entry_count": al.entryCount,
		"last_hash":   al.lastHash,
		"modified_at": fileInfo.ModTime(),
	}

	return stats, nil
}

// calculateHash computes SHA-256 hash of the entry (excluding the Hash field itself).
func (al *AuditLogger) calculateHash(entry *AuditEntry) (string, error) {
	return EntryHash(entry)
}

func (al *AuditLogger) shouldWriteCheckpoint() bool {
	if al.checkpointWriter == nil {
		return false
	}
	if al.entryCount%checkpointEntryInterval == 0 {
		return true
	}
	if al.lastCheckpointAt.IsZero() {
		return true
	}
	return time.Since(al.lastCheckpointAt) >= al.checkpointInterval
}

func (al *AuditLogger) writeCheckpoint() {
	if al.checkpointWriter == nil {
		return
	}
	if al.signer == nil {
		return
	}
	checkpoint := Checkpoint{
		LastSeq:    al.nextSeq - 1,
		LastHash:   al.lastHash,
		EntryCount: al.entryCount,
		UpdatedAt:  time.Now().UTC(),
		KeyID:      al.signer.KeyID(),
		Algorithm:  al.signer.Algorithm(),
	}
	if err := al.checkpointWriter.Write(checkpoint); err == nil {
		al.lastCheckpointAt = time.Now()
	} else {
		logging.Warnf("failed to write checkpoint: %v", err)
	}
}

// loadLastHash reads the audit log and retrieves the last entry's hash.
func (al *AuditLogger) loadLastHash() error {
	file, err := os.Open(al.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			al.cacheValid = true
			return nil // New log file
		}
		return err
	}
	defer func() { _ = file.Close() }()

	// Use buffered reader for better performance
	reader := bufio.NewReader(file)
	decoder := json.NewDecoder(reader)
	var lastEntry AuditEntry

	// Build index cache locally, then replace atomically
	newCache := make([]indexEntry, 0, 1000)

	var entryCount int64
	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			al.cacheMu.Lock()
			al.cacheValid = false
			al.cacheMu.Unlock()
			return fmt.Errorf("corrupted entry at position %d: %w", entryCount, err)
		}

		lastEntry = entry
		entryCount++

		// Add to index cache (sequential access, no file seeking needed)
		newCache = append(newCache, indexEntry{
			timestamp: entry.Timestamp,
			eventType: entry.EventType,
			actor:     entry.Actor,
			resource:  entry.Resource,
		})
	}

	// Atomically replace cache and counters
	al.cacheMu.Lock()
	al.indexCache = newCache
	al.cacheValid = true
	al.cacheMu.Unlock()

	al.entryCount = entryCount

	if lastEntry.Hash != "" {
		al.lastHash = lastEntry.Hash
	} else {
		al.lastHash = zeroHash
	}
	if lastEntry.Seq > 0 {
		al.nextSeq = lastEntry.Seq + 1
	} else if entryCount > 0 {
		al.nextSeq = entryCount + 1
	}

	return nil
}

// generateID creates a unique identifier for an audit entry.
func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

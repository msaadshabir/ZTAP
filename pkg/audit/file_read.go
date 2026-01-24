package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// EntryHash computes the SHA-256 hash of an audit entry, excluding the Hash field itself.
// This must remain compatible with the hash chaining used by AuditLogger.
func EntryHash(entry *AuditEntry) string {
	if entry == nil {
		return ""
	}

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

	b, _ := json.Marshal(data)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FileStats is a lightweight summary of an audit log file.
type FileStats struct {
	Path       string    `json:"path"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`

	EntryCount int64  `json:"entry_count"`
	LastHash   string `json:"last_hash"`
}

// GetFileStats scans the audit log file and returns basic stats.
func GetFileStats(path string) (FileStats, error) {
	st, err := os.Stat(path)
	if err != nil {
		return FileStats{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		return FileStats{}, err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReader(f))
	var last AuditEntry
	var count int64
	for {
		var e AuditEntry
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return FileStats{}, err
		}
		last = e
		count++
	}

	lastHash := last.Hash
	if lastHash == "" {
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	return FileStats{
		Path:       path,
		SizeBytes:  st.Size(),
		ModifiedAt: st.ModTime(),
		EntryCount: count,
		LastHash:   lastHash,
	}, nil
}

// VerifyFileIntegrity checks the hash chain of an audit log file.
func VerifyFileIntegrity(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReader(f))
	previousHash := "0000000000000000000000000000000000000000000000000000000000000000"

	for {
		var entry AuditEntry
		if err := dec.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			return false, err
		}
		if entry.PreviousHash != previousHash {
			return false, fmt.Errorf("hash chain broken at entry %s: expected previous hash %s, got %s", entry.ID, previousHash, entry.PreviousHash)
		}
		expected := EntryHash(&entry)
		if entry.Hash != expected {
			return false, fmt.Errorf("entry %s has been tampered with: expected hash %s, got %s", entry.ID, expected, entry.Hash)
		}
		previousHash = entry.Hash
	}

	return true, nil
}

// QueryFile scans the audit log file and returns entries matching the filters.
func QueryFile(path string, opts QueryOptions) ([]AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReader(f))

	estimatedSize := 100
	if opts.Limit > 0 && opts.Limit < estimatedSize {
		estimatedSize = opts.Limit
	}
	out := make([]AuditEntry, 0, estimatedSize)

	for {
		var entry AuditEntry
		if err := dec.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

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

		out = append(out, entry)
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}

	return out, nil
}

// ScanFile scans the audit log file and invokes fn for each matching entry.
// Returning false from fn stops the scan early.
func ScanFile(path string, opts QueryOptions, fn func(AuditEntry) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReader(f))
	for {
		var entry AuditEntry
		if err := dec.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

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

		if !fn(entry) {
			break
		}
	}

	return nil
}

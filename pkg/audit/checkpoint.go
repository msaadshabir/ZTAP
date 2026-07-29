package audit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Checkpoint represents the state of the audit log at a point in time.
type Checkpoint struct {
	LastSeq    int64     `json:"last_seq"`
	LastHash   string    `json:"last_hash"`
	EntryCount int64     `json:"entry_count"`
	UpdatedAt  time.Time `json:"updated_at"`
	KeyID      string    `json:"key_id"`
	Algorithm  string    `json:"algorithm"`
	Signature  string    `json:"signature"`
}

// CheckpointWriter handles writing checkpoints.
type CheckpointWriter struct {
	signer Signer
	path   string
}

func NewCheckpointWriter(signer Signer, path string) *CheckpointWriter {
	return &CheckpointWriter{signer: signer, path: path}
}

func (cw *CheckpointWriter) Write(checkpoint Checkpoint) error {
	data := fmt.Sprintf("%d:%s:%d:%s:%s",
		checkpoint.LastSeq, checkpoint.LastHash,
		checkpoint.EntryCount, checkpoint.KeyID, checkpoint.Algorithm)
	sig, err := cw.signer.Sign([]byte(data))
	if err != nil {
		return fmt.Errorf("signing checkpoint: %w", err)
	}
	checkpoint.Signature = hex.EncodeToString(sig)

	tmpPath := cw.path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating checkpoint file: %w", err)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(checkpoint); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("encoding checkpoint: %w", err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing checkpoint file: %w", err)
	}
	if err := os.Rename(tmpPath, cw.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming checkpoint file: %w", err)
	}

	return nil
}

// CheckpointReader handles reading and verifying checkpoints.
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
	defer func() { _ = file.Close() }()

	var checkpoint Checkpoint
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&checkpoint); err != nil {
		return Checkpoint{}, fmt.Errorf("decoding checkpoint: %w", err)
	}

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
		return Checkpoint{}, errors.New("checkpoint signature invalid")
	}

	return checkpoint, nil
}

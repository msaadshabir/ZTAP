package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ztap/internal/config"
	"ztap/internal/paths"
)

// OptionsFromSection builds audit logger options and an optional verifier from
// the central config's audit section. Empty fields fall back to the package
// defaults (log path ~/.ztap/audit.log, integrity mode "none").
func OptionsFromSection(cfg config.Audit) (AuditLoggerOptions, Verifier, error) {
	opts := AuditLoggerOptions{
		LogPath:            paths.Expand(string(cfg.LogPath)),
		CheckpointPath:     paths.Expand(string(cfg.CheckpointPath)),
		CheckpointInterval: time.Duration(cfg.CheckpointInterval),
	}

	mode := strings.ToLower(strings.TrimSpace(string(cfg.IntegrityMode)))

	switch mode {
	case "", "none":
		return opts, nil, nil
	case "hmac-sha256":
		if strings.TrimSpace(string(cfg.HMACKeyFile)) == "" {
			return AuditLoggerOptions{}, nil, errors.New("hmac-sha256 integrity mode requires hmac_key_file")
		}
		keyFile := paths.Expand(string(cfg.HMACKeyFile))
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return AuditLoggerOptions{}, nil, fmt.Errorf("reading hmac key file: %w", err)
		}
		key, err := normalizeKeyFile(keyBytes)
		if err != nil {
			return AuditLoggerOptions{}, nil, err
		}
		if len(key) == 0 {
			return AuditLoggerOptions{}, nil, errors.New("hmac key file is empty")
		}
		keyID := strings.TrimSpace(string(cfg.KeyID))
		if keyID == "" {
			sum := sha256.Sum256(key)
			keyID = hex.EncodeToString(sum[:8])
		}
		signer := NewHMACSigner(key, keyID)
		opts.Signer = signer
		return opts, NewHMACVerifier(key, keyID), nil
	case "ed25519":
		if strings.TrimSpace(string(cfg.Ed25519PrivateKey)) == "" {
			return AuditLoggerOptions{}, nil, errors.New("ed25519 integrity mode requires ed25519_private_key_file")
		}
		keyFile := paths.Expand(string(cfg.Ed25519PrivateKey))
		priv, err := os.ReadFile(keyFile)
		if err != nil {
			return AuditLoggerOptions{}, nil, fmt.Errorf("reading ed25519 private key: %w", err)
		}
		priv, err = normalizeEd25519PrivateKey(priv)
		if err != nil {
			return AuditLoggerOptions{}, nil, err
		}
		keyID := strings.TrimSpace(string(cfg.KeyID))
		if keyID == "" {
			pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
			keyID = hex.EncodeToString(pub[:8])
		}
		signer := NewEd25519Signer(ed25519.PrivateKey(priv), keyID)
		opts.Signer = signer
		return opts, NewEd25519Verifier(signer.PublicKey, keyID), nil
	default:
		return AuditLoggerOptions{}, nil, fmt.Errorf("unsupported audit integrity mode: %s", mode)
	}
}

func normalizeEd25519PrivateKey(raw []byte) ([]byte, error) {
	// Accept raw binary private key (keygen output) or hex-encoded key material.
	if len(raw) == ed25519.PrivateKeySize {
		out := make([]byte, ed25519.PrivateKeySize)
		copy(out, raw)
		return out, nil
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}

	trimmed := strings.TrimSpace(string(raw))
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("ed25519 private key must be %d bytes, %d-byte seed, or hex encoded: %w", ed25519.PrivateKeySize, ed25519.SeedSize, err)
	}
	switch len(decoded) {
	case ed25519.PrivateKeySize:
		return decoded, nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	default:
		return nil, fmt.Errorf("ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
}

func normalizeKeyFile(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(trimmed)
	if err == nil && len(decoded) > 0 {
		return decoded, nil
	}
	return []byte(trimmed), nil
}

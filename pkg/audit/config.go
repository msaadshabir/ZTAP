package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"ztap/pkg/paths"

	yaml "gopkg.in/yaml.v3"
)

// AuditConfig holds parsed audit configuration.
type AuditConfig struct {
	LogPath            string
	IntegrityMode      string
	KeyID              string
	HMACKeyFile        string
	Ed25519PrivateKey  string
	CheckpointPath     string
	CheckpointInterval time.Duration
}

// auditConfigFile represents the YAML structure for audit settings.
type auditConfigFile struct {
	Audit struct {
		LogPath            string `yaml:"log_path"`
		IntegrityMode      string `yaml:"integrity_mode"`
		KeyID              string `yaml:"key_id"`
		HMACKeyFile        string `yaml:"hmac_key_file"`
		Ed25519PrivateKey  string `yaml:"ed25519_private_key_file"`
		CheckpointPath     string `yaml:"checkpoint_path"`
		CheckpointInterval string `yaml:"checkpoint_interval"`
	} `yaml:"audit"`
}

// LoadConfigFromFile loads audit configuration from a YAML file path and applies environment overrides.
func LoadConfigFromFile(path string) (AuditLoggerOptions, Verifier, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return AuditLoggerOptions{}, nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	cfg := AuditConfig{
		LogPath:            filepath.Join(homeDir, ".ztap", "audit.log"),
		IntegrityMode:      "none",
		CheckpointInterval: 0, // Will use logger's default
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return buildOptions(applyEnvOverrides(cfg))
		}
		return AuditLoggerOptions{}, nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg auditConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return AuditLoggerOptions{}, nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if v := strings.TrimSpace(fileCfg.Audit.LogPath); v != "" {
		cfg.LogPath = v
	}
	if v := strings.TrimSpace(fileCfg.Audit.IntegrityMode); v != "" {
		cfg.IntegrityMode = v
	}
	if v := strings.TrimSpace(fileCfg.Audit.KeyID); v != "" {
		cfg.KeyID = v
	}
	if v := strings.TrimSpace(fileCfg.Audit.HMACKeyFile); v != "" {
		cfg.HMACKeyFile = v
	}
	if v := strings.TrimSpace(fileCfg.Audit.Ed25519PrivateKey); v != "" {
		cfg.Ed25519PrivateKey = v
	}
	if v := strings.TrimSpace(fileCfg.Audit.CheckpointPath); v != "" {
		cfg.CheckpointPath = v
	}
	if v := strings.TrimSpace(fileCfg.Audit.CheckpointInterval); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return AuditLoggerOptions{}, nil, fmt.Errorf("parsing audit.checkpoint_interval: %w", err)
		}
		cfg.CheckpointInterval = parsed
	}

	cfg = applyEnvOverrides(cfg)
	return buildOptions(cfg)
}

// LoadConfig loads audit configuration using the standard config file path.
func LoadConfig() (AuditLoggerOptions, Verifier, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}
	return LoadConfigFromFile(path)
}

func applyEnvOverrides(cfg AuditConfig) AuditConfig {
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_LOG_PATH")); v != "" {
		cfg.LogPath = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_INTEGRITY_MODE")); v != "" {
		cfg.IntegrityMode = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_KEY_ID")); v != "" {
		cfg.KeyID = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_HMAC_KEY_FILE")); v != "" {
		cfg.HMACKeyFile = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_ED25519_PRIVATE_KEY_FILE")); v != "" {
		cfg.Ed25519PrivateKey = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_CHECKPOINT_PATH")); v != "" {
		cfg.CheckpointPath = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_CHECKPOINT_INTERVAL")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			cfg.CheckpointInterval = parsed
		}
	}
	return cfg
}

func buildOptions(cfg AuditConfig) (AuditLoggerOptions, Verifier, error) {
	opts := AuditLoggerOptions{
		LogPath:            paths.Expand(cfg.LogPath),
		CheckpointPath:     paths.Expand(cfg.CheckpointPath),
		CheckpointInterval: cfg.CheckpointInterval,
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.IntegrityMode))

	switch mode {
	case "", "none":
		return opts, nil, nil
	case "hmac-sha256":
		if strings.TrimSpace(cfg.HMACKeyFile) == "" {
			return AuditLoggerOptions{}, nil, errors.New("hmac-sha256 integrity mode requires hmac_key_file")
		}
		keyFile := paths.Expand(cfg.HMACKeyFile)
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
		keyID := strings.TrimSpace(cfg.KeyID)
		if keyID == "" {
			sum := sha256.Sum256(key)
			keyID = hex.EncodeToString(sum[:8])
		}
		signer := NewHMACSigner(key, keyID)
		opts.Signer = signer
		return opts, NewHMACVerifier(key, keyID), nil
	case "ed25519":
		if strings.TrimSpace(cfg.Ed25519PrivateKey) == "" {
			return AuditLoggerOptions{}, nil, errors.New("ed25519 integrity mode requires ed25519_private_key_file")
		}
		keyFile := paths.Expand(cfg.Ed25519PrivateKey)
		priv, err := os.ReadFile(keyFile)
		if err != nil {
			return AuditLoggerOptions{}, nil, fmt.Errorf("reading ed25519 private key: %w", err)
		}
		priv, err = normalizeEd25519PrivateKey(priv)
		if err != nil {
			return AuditLoggerOptions{}, nil, err
		}
		keyID := strings.TrimSpace(cfg.KeyID)
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

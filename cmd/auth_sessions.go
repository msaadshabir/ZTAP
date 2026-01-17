package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ztap/pkg/auth"

	yaml "gopkg.in/yaml.v3"
)

type authSessionsConfig struct {
	Backend    string
	TTL        time.Duration
	SQLitePath string
}

func resolvedSessionsSQLitePath() (string, error) {
	cfg, err := loadAuthSessionsConfig()
	if err != nil {
		return "", err
	}
	if strings.ToLower(strings.TrimSpace(cfg.Backend)) != "sqlite" && strings.TrimSpace(cfg.Backend) != "" {
		return "", nil
	}
	return cfg.SQLitePath, nil
}

type authSessionsConfigFile struct {
	Auth struct {
		Sessions struct {
			Backend string `yaml:"backend"`
			TTL     string `yaml:"ttl"`
			SQLite  struct {
				Path string `yaml:"path"`
			} `yaml:"sqlite"`
		} `yaml:"sessions"`
	} `yaml:"auth"`
}

func loadAuthSessionsConfig() (authSessionsConfig, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return authSessionsConfig{}, fmt.Errorf("failed to get home directory: %w", err)
	}
	cfg := authSessionsConfig{
		Backend:    "sqlite",
		TTL:        24 * time.Hour,
		SQLitePath: filepath.Join(homeDir, ".ztap", "sessions.db"),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg, err = applyAuthSessionsEnv(cfg)
			if err != nil {
				return authSessionsConfig{}, err
			}
			cfg.SQLitePath, err = expandUserPath(cfg.SQLitePath)
			if err != nil {
				return authSessionsConfig{}, err
			}
			return cfg, nil
		}
		return authSessionsConfig{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg authSessionsConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return authSessionsConfig{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if v := strings.TrimSpace(fileCfg.Auth.Sessions.Backend); v != "" {
		cfg.Backend = v
	}
	if v := strings.TrimSpace(fileCfg.Auth.Sessions.TTL); v != "" {
		d, parseErr := time.ParseDuration(v)
		if parseErr != nil {
			return authSessionsConfig{}, fmt.Errorf("parsing auth.sessions.ttl: %w", parseErr)
		}
		cfg.TTL = d
	}
	if v := strings.TrimSpace(fileCfg.Auth.Sessions.SQLite.Path); v != "" {
		cfg.SQLitePath = v
	}

	cfg, err = applyAuthSessionsEnv(cfg)
	if err != nil {
		return authSessionsConfig{}, err
	}
	cfg.SQLitePath, err = expandUserPath(cfg.SQLitePath)
	if err != nil {
		return authSessionsConfig{}, err
	}
	return cfg, nil
}

func applyAuthSessionsEnv(cfg authSessionsConfig) (authSessionsConfig, error) {
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUTH_SESSIONS_BACKEND")); v != "" {
		cfg.Backend = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUTH_SESSIONS_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return authSessionsConfig{}, fmt.Errorf("parsing ZTAP_AUTH_SESSIONS_TTL: %w", err)
		}
		cfg.TTL = d
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUTH_SESSIONS_SQLITE_PATH")); v != "" {
		cfg.SQLitePath = v
	}
	return cfg, nil
}

func expandUserPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return p, nil
	}
	if p == "~" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expanding ~ in sqlite path: %w", err)
		}
		return h, nil
	}
	if strings.HasPrefix(p, "~/") {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expanding ~ in sqlite path: %w", err)
		}
		return filepath.Join(h, p[2:]), nil
	}
	return p, nil
}

func newSessionStoreFromConfig(cfg authSessionsConfig) (auth.SessionStore, time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "sqlite":
		store, err := auth.NewSQLiteSessionStore(auth.SQLiteSessionStoreOptions{Path: cfg.SQLitePath})
		if err != nil {
			return nil, 0, err
		}
		return store, cfg.TTL, nil
	case "memory", "inmemory", "in-memory":
		return auth.NewInMemorySessionStore(), cfg.TTL, nil
	default:
		return nil, 0, fmt.Errorf("unsupported auth sessions backend: %s", cfg.Backend)
	}
}

func getAuthManagerFromConfig() (*auth.AuthManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	usersPath := filepath.Join(homeDir, ".ztap", "users.json")

	sessCfg, err := loadAuthSessionsConfig()
	if err != nil {
		return nil, err
	}
	store, ttl, err := newSessionStoreFromConfig(sessCfg)
	if err != nil {
		return nil, err
	}

	am, err := auth.NewAuthManagerWithOptions(auth.AuthManagerOptions{DBPath: usersPath, Store: store, SessionTTL: ttl})
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return am, nil
}

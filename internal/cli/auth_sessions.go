package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ztap/internal/auth"
	"ztap/internal/config"
)

type authSessionsConfig struct {
	Backend    string
	TTL        time.Duration
	SQLitePath string
}

func resolvedSessionsSQLitePath(cfg *config.Config) (string, error) {
	sessCfg, err := loadAuthSessionsConfig(cfg)
	if err != nil {
		return "", err
	}
	if strings.ToLower(strings.TrimSpace(sessCfg.Backend)) != "sqlite" && strings.TrimSpace(sessCfg.Backend) != "" {
		return "", nil
	}
	return sessCfg.SQLitePath, nil
}

// loadAuthSessionsConfig derives the auth sessions settings from the central
// config (file + ZTAP_AUTH_SESSIONS_* env overrides already applied).
func loadAuthSessionsConfig(cfg *config.Config) (authSessionsConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return authSessionsConfig{}, fmt.Errorf("failed to get home directory: %w", err)
	}

	c := cfg.Auth.Sessions
	out := authSessionsConfig{
		Backend:    string(c.Backend),
		TTL:        time.Duration(c.TTL),
		SQLitePath: string(c.SQLite.Path),
	}
	if strings.TrimSpace(out.SQLitePath) == "" {
		out.SQLitePath = filepath.Join(homeDir, ".ztap", "sessions.db")
	}
	out.SQLitePath, err = expandUserPath(out.SQLitePath)
	if err != nil {
		return authSessionsConfig{}, err
	}
	return out, nil
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

func getAuthManagerFromConfig(cfg *config.Config) (*auth.AuthManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	usersPath := filepath.Join(homeDir, ".ztap", "users.json")

	sessCfg, err := loadAuthSessionsConfig(cfg)
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

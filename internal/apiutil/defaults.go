// Package apiutil provides helpers shared by the HTTP and gRPC API servers.
package apiutil

import (
	"fmt"
	"os"
	"path/filepath"

	"ztap/internal/audit"
	"ztap/internal/auth"
	"ztap/internal/config"
)

// DefaultAuthManager returns an AuthManager backed by the per-user store
// at ~/.ztap/users.json.
func DefaultAuthManager() (*auth.AuthManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	return auth.NewAuthManager(filepath.Join(homeDir, ".ztap", "users.json"))
}

// DefaultAuditLogger returns an AuditLogger configured from the central
// configuration. A missing config file is handled by config.Load using the
// documented defaults; malformed or invalid audit settings are returned to
// the caller so the server cannot silently run with unsigned audit logging.
// CLI commands pass an explicit logger after parsing config once, so this
// loader is only used by direct server constructors and library callers.
func DefaultAuditLogger() (*audit.AuditLogger, error) {
	cfg, err := config.Load("")
	if err != nil {
		return nil, fmt.Errorf("load audit configuration: %w", err)
	}
	opts, _, err := audit.OptionsFromSection(cfg.Audit)
	if err != nil {
		return nil, fmt.Errorf("configure audit logger: %w", err)
	}
	return audit.NewAuditLoggerWithOptions(opts)
}

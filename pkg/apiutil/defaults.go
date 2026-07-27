// Package apiutil provides helpers shared by the HTTP and gRPC API servers.
package apiutil

import (
	"fmt"
	"os"
	"path/filepath"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
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

// DefaultAuditLogger returns an AuditLogger configured from the audit
// section of the config file, falling back to ~/.ztap/audit.log when no
// config is present.
func DefaultAuditLogger() (*audit.AuditLogger, error) {
	if opts, _, err := audit.LoadConfig(); err == nil {
		return audit.NewAuditLoggerWithOptions(opts)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	logPath := filepath.Join(homeDir, ".ztap", "audit.log")
	return audit.NewAuditLogger(logPath)
}

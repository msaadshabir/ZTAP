package cmd

import (
	"ztap/internal/audit"
)

// loadAuditConfig loads audit configuration using the shared audit package.
func loadAuditConfig() (audit.AuditLoggerOptions, audit.Verifier, error) {
	return audit.LoadConfig()
}

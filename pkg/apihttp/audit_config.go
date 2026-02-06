package apihttp

import (
	"ztap/pkg/audit"
)

// loadAuditOptions loads audit configuration using the shared audit package.
func loadAuditOptions() (audit.AuditLoggerOptions, audit.Verifier, error) {
	return audit.LoadConfig()
}

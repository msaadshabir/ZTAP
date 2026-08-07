package cli

import (
	"ztap/internal/audit"
	"ztap/internal/config"
)

// loadAuditConfig builds audit logger options from the central config's audit
// section (file + ZTAP_AUDIT_* env overrides already applied).
func loadAuditConfig(cfg *config.Config) (audit.AuditLoggerOptions, audit.Verifier, error) {
	return audit.OptionsFromSection(cfg.Audit)
}

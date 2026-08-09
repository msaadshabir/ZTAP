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

// auditLoggerFromConfig builds an AuditLogger from the central config's audit
// section. A misconfigured integrity mode (e.g. hmac-sha256 without a key
// file) is a hard error rather than a silent fallback to an unsigned logger,
// so callers can fail loudly instead of running without audit integrity.
func auditLoggerFromConfig(cfg *config.Config) (*audit.AuditLogger, error) {
	opts, _, err := loadAuditConfig(cfg)
	if err != nil {
		return nil, err
	}
	return audit.NewAuditLoggerWithOptions(opts)
}

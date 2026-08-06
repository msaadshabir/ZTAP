package configbackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"ztap/internal/auth"
)

var ErrForceRequired = errors.New("restore requires force")

type APIProvider struct {
	Auth *auth.AuthManager

	// If provided, used to locate the sqlite db on disk.
	SessionsSQLitePath string

	// Optional: current policy YAML snapshot. If empty, policy is skipped.
	PolicyCurrentYAML []byte

	// Optional: if PolicyCurrentYAML is empty, include this warning detail.
	PolicyCurrentWarning string
}

func (p *APIProvider) Export(ctx context.Context, w *Writer, opts BackupOptions) (FeatureFlags, []string, error) {
	_ = ctx
	features := FeatureFlags{}
	warnings := []string{}

	if opts.IncludeUsers {
		if p.Auth == nil {
			warnings = append(warnings, "auth manager not available; skipping users")
		} else {
			path := p.Auth.UsersPath()
			if strings.TrimSpace(path) == "" {
				warnings = append(warnings, "users path not available; skipping users")
			} else {
				b, err := os.ReadFile(path)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("failed reading users file: %v", err))
				} else {
					if _, err := w.WriteFile("auth/users.json", "application/json", b, 0600); err != nil {
						return FeatureFlags{}, nil, err
					}
					features.AuthUsers = true
				}
			}
		}
	}

	if opts.IncludeSessions {
		if strings.TrimSpace(p.SessionsSQLitePath) == "" {
			// Best-effort: cannot reliably infer from SessionStore interface.
			warnings = append(warnings, "sessions sqlite path not configured; skipping sessions")
		} else {
			b, err := os.ReadFile(p.SessionsSQLitePath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					warnings = append(warnings, "sessions db not found; skipping sessions")
				} else {
					warnings = append(warnings, fmt.Sprintf("failed reading sessions db: %v", err))
				}
			} else {
				if _, err := w.WriteFile("auth/sessions.db", "application/x-sqlite3", b, 0600); err != nil {
					return FeatureFlags{}, nil, err
				}
				features.AuthSessions = true
			}
		}
	}

	if opts.IncludePolicyCurrent {
		if len(p.PolicyCurrentYAML) == 0 {
			if strings.TrimSpace(p.PolicyCurrentWarning) != "" {
				warnings = append(warnings, p.PolicyCurrentWarning)
			} else {
				warnings = append(warnings, "policy current yaml not available; skipping policy")
			}
		} else {
			if _, err := w.WriteFile("policy/current.yaml", "text/yaml", p.PolicyCurrentYAML, 0600); err != nil {
				return FeatureFlags{}, nil, err
			}
			features.PolicyCurrent = true
		}
	}

	if opts.IncludeDiscovery {
		warnings = append(warnings, "discovery snapshot export not implemented yet; skipping")
	}

	if opts.IncludeConfig {
		cfg := map[string]any{
			"os":   runtime.GOOS,
			"arch": runtime.GOARCH,
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if _, err := w.WriteFile("config/effective.json", "application/json", b, 0600); err != nil {
			return FeatureFlags{}, nil, err
		}
		features.ConfigEffective = true
	}

	return features, warnings, nil
}

func (p *APIProvider) PlanRestore(ctx context.Context, extractedDir string) (RestorePlan, error) {
	_ = ctx
	plan := RestorePlan{}

	usersTarget := ""
	if p.Auth != nil {
		usersTarget = p.Auth.UsersPath()
	}
	if usersTarget != "" {
		src := filepath.Join(extractedDir, "auth", "users.json")
		if _, err := os.Stat(src); err == nil {
			if _, err := os.Stat(usersTarget); err == nil {
				plan.WouldOverwrite = append(plan.WouldOverwrite, "auth/users.json")
				plan.RequiresForce = true
			} else {
				plan.WouldCreate = append(plan.WouldCreate, "auth/users.json")
				plan.RequiresForce = true
			}
		}
	}

	if strings.TrimSpace(p.SessionsSQLitePath) != "" {
		src := filepath.Join(extractedDir, "auth", "sessions.db")
		if _, err := os.Stat(src); err == nil {
			if _, err := os.Stat(p.SessionsSQLitePath); err == nil {
				plan.WouldOverwrite = append(plan.WouldOverwrite, "auth/sessions.db")
				plan.RequiresForce = true
			} else {
				plan.WouldCreate = append(plan.WouldCreate, "auth/sessions.db")
				plan.RequiresForce = true
			}
		}
	}

	// Detect non-restorable items present in the bundle so operators understand
	// why certain bundle contents won't be applied.
	if _, err := os.Stat(filepath.Join(extractedDir, "policy", "current.yaml")); err == nil {
		plan.Warnings = append(plan.Warnings, "policy restore not implemented yet; skipping policy/current.yaml")
	}
	if _, err := os.Stat(filepath.Join(extractedDir, "config", "effective.json")); err == nil {
		plan.Warnings = append(plan.Warnings, "config restore not implemented yet; skipping config/effective.json")
	}
	if _, err := os.Stat(filepath.Join(extractedDir, "discovery", "snapshot.json")); err == nil {
		plan.Warnings = append(plan.Warnings, "discovery snapshot restore not implemented yet; skipping discovery/snapshot.json")
	}
	if _, err := os.Stat(filepath.Join(extractedDir, "policy", "revisions.json")); err == nil {
		plan.Warnings = append(plan.Warnings, "policy revisions restore not implemented yet; skipping policy/revisions.json")
	}

	// Policy/discovery/config restore is backend-dependent; report best-effort.
	return plan, nil
}

func (p *APIProvider) ApplyRestore(ctx context.Context, extractedDir string, force bool) (RestoreReport, error) {
	_ = ctx
	plan, err := p.PlanRestore(ctx, extractedDir)
	if err != nil {
		return RestoreReport{}, err
	}
	if plan.RequiresForce && !force {
		return RestoreReport{}, ErrForceRequired
	}

	warnings := []string{}
	if p.Auth != nil {
		usersTarget := p.Auth.UsersPath()
		if usersTarget != "" {
			src := filepath.Join(extractedDir, "auth", "users.json")
			if _, err := os.Stat(src); err == nil {
				if err := atomicReplaceFile(usersTarget, src, 0600); err != nil {
					return RestoreReport{}, err
				}
			}
		}
	}

	if strings.TrimSpace(p.SessionsSQLitePath) != "" {
		src := filepath.Join(extractedDir, "auth", "sessions.db")
		if _, err := os.Stat(src); err == nil {
			if err := atomicReplaceFile(p.SessionsSQLitePath, src, 0600); err != nil {
				return RestoreReport{}, err
			}
		}
	}

	warnings = append(warnings, "restart required")

	return RestoreReport{Applied: true, DryRun: false, RestartRequired: true, Warnings: warnings}, nil
}

func atomicReplaceFile(dstPath, srcPath string, mode os.FileMode) error {
	dir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	b, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dstPath); err != nil {
		return err
	}
	return nil
}

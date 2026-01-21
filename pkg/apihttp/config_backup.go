package apihttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"runtime"

	"ztap/pkg/configbackup"
)

type backupRequest struct {
	IncludeUsers           *bool `json:"include_users"`
	IncludeSessions        *bool `json:"include_sessions"`
	IncludePolicyCurrent   *bool `json:"include_policy_current"`
	IncludePolicyRevisions *bool `json:"include_policy_revisions"`
	IncludeDiscovery       *bool `json:"include_discovery"`
	IncludeConfig          *bool `json:"include_config"`
}

type restoreResponse struct {
	Manifest configbackup.Manifest      `json:"manifest"`
	Plan     configbackup.RestorePlan   `json:"plan"`
	Report   configbackup.RestoreReport `json:"report"`
}

func (s *Server) handleConfigBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	opts := configbackup.DefaultBackupOptions()
	if r.Body != nil {
		// options are optional
		var req backupRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.IncludeUsers != nil {
			opts.IncludeUsers = *req.IncludeUsers
		}
		if req.IncludeSessions != nil {
			opts.IncludeSessions = *req.IncludeSessions
		}
		if req.IncludePolicyCurrent != nil {
			opts.IncludePolicyCurrent = *req.IncludePolicyCurrent
		}
		if req.IncludePolicyRevisions != nil {
			opts.IncludePolicyRevisions = *req.IncludePolicyRevisions
		}
		if req.IncludeDiscovery != nil {
			opts.IncludeDiscovery = *req.IncludeDiscovery
		}
		if req.IncludeConfig != nil {
			opts.IncludeConfig = *req.IncludeConfig
		}
	}

	provider := &configbackup.APIProvider{Auth: s.auth, SessionsSQLitePath: s.sessionsSQLitePath}
	if opts.IncludePolicyCurrent && s.policyCurrentYAML != nil {
		yamlBytes, err := s.policyCurrentYAML(r.Context())
		if err != nil {
			provider.PolicyCurrentWarning = "failed to snapshot current policy; skipping: " + err.Error()
		} else {
			provider.PolicyCurrentYAML = yamlBytes
		}
	}
	svc := configbackup.NewService(provider)

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=ztap-backup.tar.gz")

	_, err := svc.Backup(r.Context(), w, opts, configbackup.HostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
}

func (s *Server) handleConfigRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	dryRun := r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"

	provider := &configbackup.APIProvider{Auth: s.auth, SessionsSQLitePath: s.sessionsSQLitePath}
	svc := configbackup.NewService(provider)

	tmpDir, err := os.MkdirTemp("", "ztap-restore-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxRestoreBytes)
	manifest, plan, report, err := svc.Restore(r.Context(), body, tmpDir, configbackup.RestoreOptions{DryRun: dryRun, Force: force})
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, errors.New("bundle too large"))
			return
		}
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err)
			return
		}
		if errors.Is(err, configbackup.ErrForceRequired) {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, restoreResponse{Manifest: manifest, Plan: plan, Report: report})
}

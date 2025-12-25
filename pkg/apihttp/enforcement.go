package apihttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"ztap/pkg/alert"
	"ztap/pkg/audit"
	"ztap/pkg/enforcer"
	"ztap/pkg/policy"
)

type enforcementStartRequest struct {
	PolicyYAML string `json:"policy_yaml"`
	PolicyName string `json:"policy_name"`
	CgroupPath string `json:"cgroup"`
	BPFObject  string `json:"bpf_object"`
	DebugEBPF  bool   `json:"debug_ebpf"`
}

type enforcementStartResponse struct {
	Enforced bool   `json:"enforced"`
	Platform string `json:"platform"`
}

func (s *Server) handleEnforcementStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req enforcementStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	if strings.TrimSpace(req.PolicyYAML) == "" {
		writeError(w, http.StatusBadRequest, errors.New("policy_yaml is required"))
		return
	}
	policyName := strings.TrimSpace(req.PolicyName)
	if policyName == "" {
		policyName = "api"
	}

	policies, err := policy.LoadFromBytes([]byte(req.PolicyYAML))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("failed to parse policy yaml: %w", err))
		return
	}
	if len(policies) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("no policies found"))
		return
	}

	named := make([]policy.NamedPolicy, 0, len(policies))
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		named = append(named, policy.NamedPolicy{PolicyName: policyName, Policy: p})
	}
	for i, np := range named {
		if err := policy.CheckConflicts(named[:i], np); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("policy conflict: %w", err))
			return
		}
	}

	if enforcer.IsLinux() {
		if os.Geteuid() != 0 {
			writeError(w, http.StatusForbidden, errors.New("eBPF enforcement requires root privileges"))
			return
		}
		const defaultCgroupPath = "/sys/fs/cgroup"
		rawCgroupPath := strings.TrimSpace(req.CgroupPath)
		var cgroupPath string
		if rawCgroupPath == "" {
			cgroupPath = defaultCgroupPath
		} else {
			if filepath.IsAbs(rawCgroupPath) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid cgroup path %s", rawCgroupPath))
				return
			}
			cleaned := filepath.Clean(rawCgroupPath)
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid cgroup path %s", rawCgroupPath))
				return
			}
			joined := filepath.Join(defaultCgroupPath, cleaned)
			absCgroupPath, err := filepath.Abs(joined)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid cgroup path %s", rawCgroupPath))
				return
			}
			rel, err := filepath.Rel(defaultCgroupPath, absCgroupPath)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid cgroup path %s", rawCgroupPath))
				return
			}
			cgroupPath = absCgroupPath
		}
		if _, err := os.Stat(cgroupPath); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid cgroup path %s: %w", cgroupPath, err))
			return
		}
		if req.BPFObject != "" {
			const safeBPFDir = "/usr/lib/ztap/bpf"
			trimmedObj := strings.TrimSpace(req.BPFObject)
			if trimmedObj == "" {
				writeError(w, http.StatusBadRequest, errors.New("bpf_object must not be empty"))
				return
			}
			if filepath.IsAbs(trimmedObj) {
				writeError(w, http.StatusBadRequest, errors.New("bpf_object must be a relative path"))
				return
			}
			cleaned := filepath.Clean(trimmedObj)
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
				writeError(w, http.StatusBadRequest, errors.New("bpf_object contains an invalid path"))
				return
			}
			baseDirAbs, err := filepath.Abs(safeBPFDir)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to resolve bpf directory: %w", err))
				return
			}
			joinedPath := filepath.Join(baseDirAbs, cleaned)
			absPath, err := filepath.Abs(joinedPath)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid bpf_object %s: %w", trimmedObj, err))
				return
			}
			rel, err := filepath.Rel(baseDirAbs, absPath)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("bpf_object must be within %s", baseDirAbs))
				return
			}
			if _, err := os.Stat(absPath); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid bpf_object %s: %w", trimmedObj, err))
				return
			}
			_ = os.Setenv("ZTAP_BPF_OBJECT", absPath)
		}
		if req.DebugEBPF {
			_ = os.Setenv("ZTAP_DEBUG_EBPF", "1")
		}
		if err := enforcer.ValidatePoliciesForEBPF(policies); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("policy is not supported by eBPF enforcer yet: %w", err))
			return
		}

		platform := "linux"
		if err := enforcer.EnforceWithEBPFIfAvailable(policies, cgroupPath); err != nil {
			s.emitAlert(alert.Alert{
				Source:   "api-http",
				Severity: alert.SeverityError,
				Title:    "policy enforcement failed",
				Message:  err.Error(),
				DedupKey: fmt.Sprintf("%s:%s:error", policyName, platform),
				Details:  map[string]any{"platform": platform, "count": len(policies)},
			})
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to enforce via eBPF: %w", err))
			return
		}

		_ = s.audit.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", map[string]any{"platform": platform, "count": len(policies)})
		s.emitAlert(alert.Alert{
			Source:   "api-http",
			Severity: alert.SeverityInfo,
			Title:    "policy enforced",
			Message:  fmt.Sprintf("%s enforced on %s", policyName, platform),
			DedupKey: fmt.Sprintf("%s:%s:success", policyName, platform),
			Details:  map[string]any{"platform": platform, "count": len(policies)},
		})
		writeJSON(w, http.StatusOK, enforcementStartResponse{Enforced: true, Platform: platform})
		return
	}

	if enforcer.IsWindows() {
		platform := "windows"
		if err := enforcer.EnforceWithWFP(policies); err != nil {
			s.emitAlert(alert.Alert{
				Source:   "api-http",
				Severity: alert.SeverityError,
				Title:    "policy enforcement failed",
				Message:  err.Error(),
				DedupKey: fmt.Sprintf("%s:%s:error", policyName, platform),
				Details:  map[string]any{"platform": platform, "count": len(policies)},
			})
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to enforce via WFP: %w", err))
			return
		}

		_ = s.audit.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", map[string]any{"platform": platform, "count": len(policies)})
		s.emitAlert(alert.Alert{
			Source:   "api-http",
			Severity: alert.SeverityInfo,
			Title:    "policy enforced",
			Message:  fmt.Sprintf("%s enforced on %s", policyName, platform),
			DedupKey: fmt.Sprintf("%s:%s:success", policyName, platform),
			Details:  map[string]any{"platform": platform, "count": len(policies)},
		})
		writeJSON(w, http.StatusOK, enforcementStartResponse{Enforced: true, Platform: platform})
		return
	}

	platform := runtime.GOOS
	enforcer.EnforceWithPF(policies)
	_ = s.audit.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", map[string]any{"platform": platform, "count": len(policies)})
	s.emitAlert(alert.Alert{
		Source:   "api-http",
		Severity: alert.SeverityInfo,
		Title:    "policy enforced",
		Message:  fmt.Sprintf("%s enforced on %s", policyName, platform),
		DedupKey: fmt.Sprintf("%s:%s:success", policyName, platform),
		Details:  map[string]any{"platform": platform, "count": len(policies)},
	})
	writeJSON(w, http.StatusOK, enforcementStartResponse{Enforced: true, Platform: platform})
}

func (s *Server) handleEnforcementStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if enforcer.IsLinux() {
		if os.Geteuid() != 0 {
			writeError(w, http.StatusForbidden, errors.New("eBPF enforcement requires root privileges"))
			return
		}
		if err := enforcer.StopEBPFEnforcement(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to stop eBPF enforcement: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
		return
	}
	if enforcer.IsWindows() {
		if err := enforcer.StopWFPEnforcement(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to stop WFP enforcement: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
		return
	}
	writeError(w, http.StatusNotImplemented, errors.New("stop is only supported for eBPF on linux or WFP on windows"))
}

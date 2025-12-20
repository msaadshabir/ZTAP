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
		cgroupPath := strings.TrimSpace(req.CgroupPath)
		if cgroupPath == "" {
			cgroupPath = "/sys/fs/cgroup"
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
			baseDirAbs, err := filepath.Abs(safeBPFDir)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to resolve bpf directory: %w", err))
				return
			}
			joinedPath := filepath.Join(baseDirAbs, trimmedObj)
			absPath, err := filepath.Abs(joinedPath)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid bpf_object %s: %w", trimmedObj, err))
				return
			}
			baseWithSep := baseDirAbs
			if !strings.HasSuffix(baseWithSep, string(os.PathSeparator)) {
				baseWithSep += string(os.PathSeparator)
			}
			if absPath != baseDirAbs && !strings.HasPrefix(absPath, baseWithSep) {
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

		if err := enforcer.EnforceWithEBPFIfAvailable(policies, cgroupPath); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to enforce via eBPF: %w", err))
			return
		}

		_ = s.audit.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", map[string]any{"platform": "linux", "count": len(policies)})
		writeJSON(w, http.StatusOK, enforcementStartResponse{Enforced: true, Platform: "linux"})
		return
	}

	enforcer.EnforceWithPF(policies)
	_ = s.audit.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", map[string]any{"platform": runtime.GOOS, "count": len(policies)})
	writeJSON(w, http.StatusOK, enforcementStartResponse{Enforced: true, Platform: runtime.GOOS})
}

func (s *Server) handleEnforcementStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !enforcer.IsLinux() {
		writeError(w, http.StatusNotImplemented, errors.New("stop is only supported for eBPF enforcement on linux"))
		return
	}
	if os.Geteuid() != 0 {
		writeError(w, http.StatusForbidden, errors.New("eBPF enforcement requires root privileges"))
		return
	}
	if err := enforcer.StopEBPFEnforcement(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to stop eBPF enforcement: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
}

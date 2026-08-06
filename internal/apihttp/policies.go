package apihttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"ztap/internal/audit"
	"ztap/internal/auth"
	"ztap/internal/cluster"
)

type policyUpsertRequest struct {
	PolicyYAML      string `json:"policy_yaml"`
	Reason          string `json:"reason"`
	ExpectedVersion *int64 `json:"expected_version,omitempty"`
}

type policyDeleteRequest struct {
	Reason string `json:"reason"`
}

type policyInfo struct {
	Tenant     string `json:"tenant"`
	Name       string `json:"name"`
	Version    int64  `json:"version"`
	Source     string `json:"source"`
	UpdatedAt  string `json:"updated_at"`
	PolicyYAML string `json:"policy_yaml,omitempty"`
}

type policyRevisionInfo struct {
	Tenant              string `json:"tenant"`
	Name                string `json:"name"`
	Version             int64  `json:"version"`
	Source              string `json:"source"`
	CreatedAt           string `json:"created_at"`
	Reason              string `json:"reason,omitempty"`
	Deleted             bool   `json:"deleted"`
	RollbackFromVersion *int64 `json:"rollback_from_version,omitempty"`
	PolicyYAML          string `json:"policy_yaml,omitempty"`
}

func (s *Server) handlePoliciesRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/policies" {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := s.authorize(w, r, auth.PermViewPolicies); !ok {
		return
	}
	if s.policyManager == nil {
		writeError(w, http.StatusNotImplemented, errors.New("policy manager not configured"))
		return
	}

	tenantFilter := strings.TrimSpace(r.URL.Query().Get("tenant"))
	items := s.policyManager.ListPolicies()
	resp := make([]policyInfo, 0, len(items))
	for _, item := range items {
		if tenantFilter != "" && item.Tenant != tenantFilter {
			continue
		}
		resp = append(resp, policyInfo{
			Tenant:    item.Tenant,
			Name:      item.Name,
			Version:   item.Version,
			Source:    item.Source,
			UpdatedAt: item.Timestamp.UTC().Format(timeFormat),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": resp})
}

func (s *Server) handlePoliciesRoutes(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/policies/") {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if s.policyManager == nil {
		writeError(w, http.StatusNotImplemented, errors.New("policy manager not configured"))
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/policies/"), "/")
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, errors.New("invalid policy path"))
		return
	}
	tenant := strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])
	if tenant == "" || name == "" {
		writeError(w, http.StatusBadRequest, errors.New("policy tenant and name are required"))
		return
	}
	policyKey := tenant + "/" + name

	// /v1/policies/{tenant}/{name}
	if len(parts) == 2 {
		switch r.Method {
		case http.MethodGet:
			if _, ok := s.authorize(w, r, auth.PermViewPolicies); !ok {
				return
			}
			state, err := s.policyManager.GetPolicy(policyKey)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if state == nil {
				writeError(w, http.StatusNotFound, errors.New("policy not found"))
				return
			}
			writeJSON(w, http.StatusOK, policyInfo{
				Tenant:     state.Tenant,
				Name:       state.Name,
				Version:    state.Version,
				Source:     state.Source,
				UpdatedAt:  state.Timestamp.UTC().Format(timeFormat),
				PolicyYAML: string(state.YAML),
			})
		case http.MethodPut:
			sess, ok := s.authorize(w, r, auth.PermManagePolicies)
			if !ok {
				return
			}
			var req policyUpsertRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
				return
			}
			if strings.TrimSpace(req.PolicyYAML) == "" {
				writeError(w, http.StatusBadRequest, errors.New("policy_yaml is required"))
				return
			}
			if req.ExpectedVersion != nil {
				if *req.ExpectedVersion < 0 {
					writeError(w, http.StatusBadRequest, errors.New("expected_version must be >= 0"))
					return
				}
				current, err := s.policyManager.GetPolicyVersion(policyKey)
				if err != nil {
					writeError(w, http.StatusInternalServerError, err)
					return
				}
				if current != *req.ExpectedVersion {
					writeError(w, http.StatusConflict, fmt.Errorf("expected version %d, got %d", *req.ExpectedVersion, current))
					return
				}
			}
			rev, err := s.policyManager.UpsertPolicy(r.Context(), policyKey, []byte(req.PolicyYAML), strings.TrimSpace(req.Reason))
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			if s.audit != nil {
				actor := "system"
				if sess != nil {
					actor = sess.Username
				}
				event := audit.EventPolicyUpdated
				if rev.Version == 1 {
					event = audit.EventPolicyCreated
				}
				_ = s.audit.Log(event, actor, policyKey, "upsert", map[string]any{"version": rev.Version})
			}
			writeJSON(w, http.StatusOK, map[string]any{"version": rev.Version})
		case http.MethodDelete:
			sess, ok := s.authorize(w, r, auth.PermManagePolicies)
			if !ok {
				return
			}
			var req policyDeleteRequest
			if r.Body != nil {
				dec := json.NewDecoder(r.Body)
				err := dec.Decode(&req)
				if err != nil && !errors.Is(err, io.EOF) {
					writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
					return
				}
			}
			reason := strings.TrimSpace(req.Reason)
			rev, err := s.policyManager.DeletePolicy(r.Context(), policyKey, reason)
			if err != nil {
				if errors.Is(err, cluster.ErrPolicyNotFound) {
					writeError(w, http.StatusNotFound, err)
					return
				}
				writeError(w, http.StatusBadRequest, err)
				return
			}
			if s.audit != nil {
				actor := "system"
				if sess != nil {
					actor = sess.Username
				}
				_ = s.audit.Log(audit.EventPolicyDeleted, actor, policyKey, "delete", map[string]any{"version": rev.Version, "reason": reason})
			}
			writeJSON(w, http.StatusOK, map[string]any{"version": rev.Version, "deleted": true})
		default:
			writeMethodNotAllowed(w)
		}
		return
	}

	// /v1/policies/{tenant}/{name}/revisions
	if len(parts) == 3 && parts[2] == "revisions" {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		if _, ok := s.authorize(w, r, auth.PermViewPolicies); !ok {
			return
		}
		limit := 0
		if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
			parsed, err := strconv.Atoi(v)
			if err != nil {
				writeError(w, http.StatusBadRequest, errors.New("invalid limit"))
				return
			}
			limit = parsed
		}
		includeYAML := r.URL.Query().Get("include_yaml") == "1" || r.URL.Query().Get("include_yaml") == "true"
		revs, err := s.policyManager.ListPolicyRevisions(policyKey, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		resp := make([]policyRevisionInfo, 0, len(revs))
		for _, rev := range revs {
			info := policyRevisionInfo{
				Tenant:              rev.Tenant,
				Name:                rev.PolicyName,
				Version:             rev.Version,
				Source:              rev.Source,
				CreatedAt:           rev.Timestamp.UTC().Format(timeFormat),
				Reason:              rev.Reason,
				Deleted:             rev.Deleted,
				RollbackFromVersion: rev.RollbackFromVersion,
			}
			if includeYAML {
				info.PolicyYAML = string(rev.YAML)
			}
			resp = append(resp, info)
		}
		writeJSON(w, http.StatusOK, map[string]any{"revisions": resp})
		return
	}

	// /v1/policies/{tenant}/{name}/revisions/{version}
	if len(parts) == 4 && parts[2] == "revisions" {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		if _, ok := s.authorize(w, r, auth.PermViewPolicies); !ok {
			return
		}
		version, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil || version <= 0 {
			writeError(w, http.StatusBadRequest, errors.New("invalid version"))
			return
		}
		rev, err := s.policyManager.GetPolicyRevision(policyKey, version)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if rev == nil {
			writeError(w, http.StatusNotFound, errors.New("revision not found"))
			return
		}
		writeJSON(w, http.StatusOK, policyRevisionInfo{
			Tenant:              rev.Tenant,
			Name:                rev.PolicyName,
			Version:             rev.Version,
			Source:              rev.Source,
			CreatedAt:           rev.Timestamp.UTC().Format(timeFormat),
			Reason:              rev.Reason,
			Deleted:             rev.Deleted,
			RollbackFromVersion: rev.RollbackFromVersion,
			PolicyYAML:          string(rev.YAML),
		})
		return
	}

	// /v1/policies/{tenant}/{name}/rollback
	if len(parts) == 3 && parts[2] == "rollback" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		sess, ok := s.authorize(w, r, auth.PermManagePolicies)
		if !ok {
			return
		}
		var req struct {
			ToVersion int64  `json:"to_version"`
			Reason    string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
			return
		}
		if req.ToVersion <= 0 {
			writeError(w, http.StatusBadRequest, errors.New("to_version must be positive"))
			return
		}
		reason := strings.TrimSpace(req.Reason)
		rev, err := s.policyManager.RollbackPolicy(r.Context(), policyKey, req.ToVersion, reason)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if s.audit != nil {
			actor := "system"
			if sess != nil {
				actor = sess.Username
			}
			_ = s.audit.Log(audit.EventPolicyUpdated, actor, policyKey, "rollback", map[string]any{"version": rev.Version, "rollback_from": req.ToVersion, "reason": reason})
		}
		writeJSON(w, http.StatusOK, map[string]any{"version": rev.Version})
		return
	}

	writeError(w, http.StatusNotFound, errors.New("not found"))
}

const timeFormat = "2006-01-02T15:04:05Z07:00"

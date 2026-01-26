package apihttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ztap/pkg/compliance"
	"ztap/pkg/policy"
)

type complianceReportRequest struct {
	PolicyYAML     string   `json:"policy_yaml"`
	PolicyName     string   `json:"policy_name"`
	Frameworks     []string `json:"frameworks"`
	MappingYAML    string   `json:"mapping_yaml"`
	EvidenceWindow string   `json:"evidence_window"`
	Strict         bool     `json:"strict"`
}

func parseEvidenceWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 90 * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "d") {
		n := strings.TrimSpace(strings.TrimSuffix(s, "d"))
		if n == "" {
			return 0, errors.New("invalid evidence_window")
		}
		v, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid evidence_window %q: %w", s, err)
		}
		return time.Duration(v * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(s)
}

func (s *Server) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var req complianceReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.PolicyYAML) == "" {
		writeError(w, http.StatusBadRequest, errors.New("policy_yaml is required"))
		return
	}

	policies, err := policy.LoadFromBytes([]byte(req.PolicyYAML))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(policies) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("no policies found"))
		return
	}
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	frameworkIDs := make([]compliance.FrameworkID, 0, len(req.Frameworks))
	for _, fw := range req.Frameworks {
		id, ok := compliance.ParseFrameworkID(fw)
		if !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown framework: "+fw))
			return
		}
		frameworkIDs = append(frameworkIDs, id)
	}

	window, err := parseEvidenceWindow(req.EvidenceWindow)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	auditPath := ""
	if s.audit != nil {
		if stats, err := s.audit.GetStats(); err == nil {
			if p, ok := stats["path"].(string); ok {
				auditPath = p
			}
		}
	}

	report, err := compliance.BuildReport(r.Context(), policies, compliance.BuildOptions{
		PolicyName:      req.PolicyName,
		Frameworks:      frameworkIDs,
		MappingFileYAML: []byte(req.MappingYAML),
		Strict:          req.Strict,
		AuditLogPath:    auditPath,
		EvidenceWindow:  window,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, report)
}

type complianceExportRequest struct {
	complianceReportRequest
	Format string `json:"format"`
}

func (s *Server) handleComplianceExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var req complianceExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if strings.TrimSpace(req.PolicyYAML) == "" {
		writeError(w, http.StatusBadRequest, errors.New("policy_yaml is required"))
		return
	}

	policies, err := policy.LoadFromBytes([]byte(req.PolicyYAML))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(policies) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("no policies found"))
		return
	}
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	frameworkIDs := make([]compliance.FrameworkID, 0, len(req.Frameworks))
	for _, fw := range req.Frameworks {
		id, ok := compliance.ParseFrameworkID(fw)
		if !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown framework: "+fw))
			return
		}
		frameworkIDs = append(frameworkIDs, id)
	}

	window, err := parseEvidenceWindow(req.EvidenceWindow)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	auditPath := ""
	if s.audit != nil {
		if stats, err := s.audit.GetStats(); err == nil {
			if p, ok := stats["path"].(string); ok {
				auditPath = p
			}
		}
	}

	report, err := compliance.BuildReport(r.Context(), policies, compliance.BuildOptions{
		PolicyName:      req.PolicyName,
		Frameworks:      frameworkIDs,
		MappingFileYAML: []byte(req.MappingYAML),
		Strict:          req.Strict,
		AuditLogPath:    auditPath,
		EvidenceWindow:  window,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	switch strings.ToLower(strings.TrimSpace(req.Format)) {
	case "", "json":
		writeJSON(w, http.StatusOK, report)
		return
	case "csv":
		var buf bytes.Buffer
		if err := compliance.WriteCSV(&buf, report); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
		return
	default:
		writeError(w, http.StatusBadRequest, errors.New("unsupported format"))
		return
	}
}

package apihttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
)

func TestComplianceReportRequiresAuth(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	body := []byte(`{"policy_yaml":"apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p\nspec:\n  podSelector:\n    matchLabels:\n      app: a\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/compliance/report", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestComplianceReportOK(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin2", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Login.
	loginBody, _ := json.Marshal(map[string]string{"username": "admin2", "password": "pw"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(loginBody))
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", loginRR.Code, loginRR.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatalf("expected token")
	}

	body := []byte(`{"policy_yaml":"apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p\n  annotations:\n    ztap.io/compliance.pci-dss: '10.2.1'\nspec:\n  podSelector:\n    matchLabels:\n      app: a\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/compliance/report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestComplianceReportForbiddenForViewer(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("viewer1", "pw", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "viewer1", "password": "pw"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(loginBody))
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", loginRR.Code, loginRR.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatalf("expected token")
	}

	body := []byte(`{"policy_yaml":"apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p\nspec:\n  podSelector:\n    matchLabels:\n      app: a\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/compliance/report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestComplianceExportCSVContentType(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin2", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "admin2", "password": "pw"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(loginBody))
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", loginRR.Code, loginRR.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatalf("expected token")
	}

	body := []byte(`{"format":"csv","policy_yaml":"apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p\n  annotations:\n    ztap.io/compliance.pci-dss: '10.2.1'\nspec:\n  podSelector:\n    matchLabels:\n      app: a\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/compliance/export", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/csv" {
		t.Fatalf("expected text/csv, got %q", ct)
	}
	if !strings.HasPrefix(rr.Body.String(), "framework_id,framework_version") {
		t.Fatalf("unexpected csv body: %s", rr.Body.String())
	}
}

func TestComplianceReportInvalidYAMLReturns400(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin2", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "admin2", "password": "pw"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(loginBody))
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", loginRR.Code, loginRR.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatalf("expected token")
	}

	body := []byte(`{"policy_yaml":"not: [valid: yaml"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/compliance/report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestComplianceReportResponseHasMetadata(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin2", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "admin2", "password": "pw"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(loginBody))
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", loginRR.Code, loginRR.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatalf("expected token")
	}

	body := []byte(`{"policy_yaml":"apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p\n  annotations:\n    ztap.io/compliance.pci-dss: '10.2.1'\nspec:\n  podSelector:\n    matchLabels:\n      app: a\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/compliance/report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if _, ok := decoded["metadata"]; !ok {
		t.Fatalf("expected metadata")
	}
	if _, ok := decoded["controls"]; !ok {
		t.Fatalf("expected controls")
	}
}

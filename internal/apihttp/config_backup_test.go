package apihttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ztap/internal/auth"
	"ztap/internal/configbackup"
)

func TestConfigBackupRequiresAuth(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/config/backup", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestConfigBackupAndRestoreDryRun(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin2", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Login to get token.
	token := loginToken(t, srv, "admin2", "pw")

	// Backup.
	backupReq := httptest.NewRequest(http.MethodPost, "/v1/config/backup", bytes.NewReader([]byte(`{}`)))
	backupReq.Header.Set("Authorization", "Bearer "+token)
	backupRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backupRR, backupReq)
	if backupRR.Code != http.StatusOK {
		t.Fatalf("backup expected 200, got %d: %s", backupRR.Code, backupRR.Body.String())
	}
	if ct := backupRR.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Fatalf("expected application/gzip, got %s", ct)
	}
	bundle := backupRR.Body.Bytes()
	if len(bundle) == 0 {
		t.Fatalf("expected non-empty bundle")
	}

	// Restore dry-run.
	restoreReq := httptest.NewRequest(http.MethodPost, "/v1/config/restore?dry_run=1", bytes.NewReader(bundle))
	restoreReq.Header.Set("Authorization", "Bearer "+token)
	restoreReq.Header.Set("Content-Type", "application/gzip")
	restoreRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(restoreRR, restoreReq)
	if restoreRR.Code != http.StatusOK {
		t.Fatalf("restore expected 200, got %d: %s", restoreRR.Code, restoreRR.Body.String())
	}

	b, _ := io.ReadAll(restoreRR.Body)
	if !bytes.Contains(b, []byte("\"restart_required\":true")) {
		t.Fatalf("expected restart_required true, got: %s", string(b))
	}
}

func TestConfigBackupMethodNotAllowed(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin_mna_backup", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin_mna_backup", "pw")

	req := httptest.NewRequest(http.MethodGet, "/v1/config/backup", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestConfigRestoreMethodNotAllowed(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin_mna_restore", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin_mna_restore", "pw")

	req := httptest.NewRequest(http.MethodGet, "/v1/config/restore", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestConfigRestoreInvalidGzip(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin_invalid_gz", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin_invalid_gz", "pw")

	restoreReq := httptest.NewRequest(http.MethodPost, "/v1/config/restore?dry_run=1", bytes.NewReader([]byte("not-gzip")))
	restoreReq.Header.Set("Authorization", "Bearer "+token)
	restoreRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(restoreRR, restoreReq)
	if restoreRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", restoreRR.Code, restoreRR.Body.String())
	}
}

func TestConfigRestoreBodyTooLarge(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin_too_large", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true, MaxRestoreBytes: 1}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin_too_large", "pw")

	restoreReq := httptest.NewRequest(http.MethodPost, "/v1/config/restore?dry_run=1", bytes.NewReader([]byte("aa")))
	restoreReq.Header.Set("Authorization", "Bearer "+token)
	restoreRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(restoreRR, restoreReq)
	if restoreRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", restoreRR.Code, restoreRR.Body.String())
	}
}

func TestConfigBackupIncludesPolicyCurrentWhenProvided(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin_policy", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	policyYAML := []byte("apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: example\nspec:\n  podSelector:\n    matchLabels:\n      app: demo\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.1/32\n    ports:\n    - protocol: TCP\n      port: 443\n")

	srv, err := NewServer(ServerOptions{
		Config:      Config{Listen: "127.0.0.1:0", AuthEnabled: true},
		AuthManager: am,
		PolicyCurrentYAMLFunc: func(ctx context.Context) ([]byte, error) {
			return policyYAML, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin_policy", "pw")

	backupReq := httptest.NewRequest(http.MethodPost, "/v1/config/backup", bytes.NewReader([]byte(`{"include_policy_current":true}`)))
	backupReq.Header.Set("Authorization", "Bearer "+token)
	backupRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backupRR, backupReq)
	if backupRR.Code != http.StatusOK {
		t.Fatalf("backup expected 200, got %d: %s", backupRR.Code, backupRR.Body.String())
	}
	bundle := backupRR.Body.Bytes()

	validator := configbackup.NewService(&configbackup.APIProvider{})
	manifest, err := validator.Validate(t.Context(), bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !manifest.Features.PolicyCurrent {
		t.Fatalf("expected policy_current feature true")
	}
	found := false
	for _, it := range manifest.Items {
		if it.Path == "policy/current.yaml" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected policy/current.yaml in manifest items")
	}
}

func TestConfigBackupPermissionDenied(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("viewer1", "pw", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "viewer1", "pw")

	backupReq := httptest.NewRequest(http.MethodPost, "/v1/config/backup", bytes.NewReader([]byte(`{}`)))
	backupReq.Header.Set("Authorization", "Bearer "+token)
	backupRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backupRR, backupReq)
	if backupRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", backupRR.Code, backupRR.Body.String())
	}
}

func TestConfigRestoreRequiresForce(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin3", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin3", "pw")

	backupReq := httptest.NewRequest(http.MethodPost, "/v1/config/backup", bytes.NewReader([]byte(`{}`)))
	backupReq.Header.Set("Authorization", "Bearer "+token)
	backupRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backupRR, backupReq)
	if backupRR.Code != http.StatusOK {
		t.Fatalf("backup expected 200, got %d: %s", backupRR.Code, backupRR.Body.String())
	}
	bundle := backupRR.Body.Bytes()

	restoreReq := httptest.NewRequest(http.MethodPost, "/v1/config/restore", bytes.NewReader(bundle))
	restoreReq.Header.Set("Authorization", "Bearer "+token)
	restoreReq.Header.Set("Content-Type", "application/gzip")
	restoreRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(restoreRR, restoreReq)
	if restoreRR.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", restoreRR.Code, restoreRR.Body.String())
	}
}

func TestConfigRestoreForceApply(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin4", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin4", "pw")

	backupReq := httptest.NewRequest(http.MethodPost, "/v1/config/backup", bytes.NewReader([]byte(`{}`)))
	backupReq.Header.Set("Authorization", "Bearer "+token)
	backupRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(backupRR, backupReq)
	if backupRR.Code != http.StatusOK {
		t.Fatalf("backup expected 200, got %d: %s", backupRR.Code, backupRR.Body.String())
	}
	bundle := backupRR.Body.Bytes()

	restoreReq := httptest.NewRequest(http.MethodPost, "/v1/config/restore?force=1", bytes.NewReader(bundle))
	restoreReq.Header.Set("Authorization", "Bearer "+token)
	restoreReq.Header.Set("Content-Type", "application/gzip")
	restoreRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(restoreRR, restoreReq)
	if restoreRR.Code != http.StatusOK {
		t.Fatalf("restore expected 200, got %d: %s", restoreRR.Code, restoreRR.Body.String())
	}

	var resp struct {
		Report struct {
			Applied         bool `json:"applied"`
			DryRun          bool `json:"dry_run"`
			RestartRequired bool `json:"restart_required"`
		} `json:"report"`
	}
	_ = json.Unmarshal(restoreRR.Body.Bytes(), &resp)
	if !resp.Report.Applied || resp.Report.DryRun || !resp.Report.RestartRequired {
		t.Fatalf("unexpected restore report: %+v", resp.Report)
	}
}

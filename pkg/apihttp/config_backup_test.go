package apihttp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ztap/pkg/auth"
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

	// Backup.
	backupReq := httptest.NewRequest(http.MethodPost, "/v1/config/backup", bytes.NewReader([]byte(`{}`)))
	backupReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
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
	restoreReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
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

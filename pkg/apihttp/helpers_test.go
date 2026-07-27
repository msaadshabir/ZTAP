package apihttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
)

// newTestServer builds a Server with a throwaway auth manager and audit
// logger rooted in t.TempDir.
func newTestServer(t *testing.T, authEnabled bool) *Server {
	t.Helper()

	dir := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	server, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: authEnabled}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() {
		_ = am.Close()
		_ = al.Close()
	})
	return server
}

// loginToken performs a login against the test server and returns the
// bearer token.
func loginToken(t *testing.T, srv *Server, username, password string) string {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if resp.Token == "" {
		t.Fatalf("expected token")
	}
	return resp.Token
}

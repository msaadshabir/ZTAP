package apihttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ztap/pkg/auth"
)

func TestRateLimit_Login_PerIP(t *testing.T) {
	dir := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("alice", "password123", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true, RateLimit: RateLimitConfig{
		Enabled:         true,
		PerIP:           RateLimitBucketConfig{RPS: 0.1, Burst: 1},
		PerToken:        RateLimitBucketConfig{RPS: 1000, Burst: 1000},
		Unauthenticated: RateLimitBucketConfig{RPS: 1000, Burst: 1000},
		ExemptPaths: []string{
			"/healthz",
			"/readyz",
			"/metrics",
		},
	}}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "alice", "password": "password123"})

	req1 := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(loginBody))
	req1.RemoteAddr = "203.0.113.10:1234"
	rr1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr1.Code, rr1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(loginBody))
	req2.RemoteAddr = "203.0.113.10:1234"
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", rr2.Code, rr2.Body.String())
	}
	if rr2.Header().Get("X-RateLimit-Limit") == "" {
		t.Fatalf("expected X-RateLimit-Limit")
	}
	if rr2.Header().Get("X-RateLimit-Burst") == "" {
		t.Fatalf("expected X-RateLimit-Burst")
	}
}

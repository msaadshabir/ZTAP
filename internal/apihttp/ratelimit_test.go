package apihttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimit_Disabled_Allows(t *testing.T) {
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestRateLimit_Enabled_PerIP_BlocksSecond(t *testing.T) {
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false, RateLimit: RateLimitConfig{
		Enabled:         true,
		PerIP:           RateLimitBucketConfig{RPS: 0.1, Burst: 1},
		Unauthenticated: RateLimitBucketConfig{RPS: 0.1, Burst: 1},
		ExemptPaths: []string{
			"/healthz",
			"/readyz",
		},
	}}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req1.RemoteAddr = "203.0.113.10:1234"
	rr1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first 200, got %d: %s", rr1.Code, rr1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req2.RemoteAddr = "203.0.113.10:1234"
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", rr2.Code, rr2.Body.String())
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header")
	}
}

func TestRateLimit_Enabled_ExemptPath_Allows(t *testing.T) {
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false, RateLimit: RateLimitConfig{
		Enabled:     true,
		PerIP:       RateLimitBucketConfig{RPS: 0.1, Burst: 1},
		ExemptPaths: []string{"/healthz"},
	}}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req1.RemoteAddr = "203.0.113.10:1234"
	rr1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req2.RemoteAddr = "203.0.113.10:1234"
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr2.Code)
	}
}

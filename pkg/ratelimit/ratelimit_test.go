package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStore_SameKeyReused(t *testing.T) {
	s := NewStore(Config{Enabled: true, PerIP: BucketConfig{RPS: 1, Burst: 1}, Unauthenticated: BucketConfig{RPS: 1, Burst: 1}, PerToken: BucketConfig{RPS: 1, Burst: 1}})
	defer s.Close()

	r := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	r.RemoteAddr = "192.0.2.10:123"

	d1, err := s.DecisionForHTTPRequest(r)
	if err != nil {
		t.Fatalf("DecisionForHTTPRequest: %v", err)
	}
	if !d1.Allowed {
		t.Fatalf("expected allowed")
	}

	d2, err := s.DecisionForHTTPRequest(r)
	if err != nil {
		t.Fatalf("DecisionForHTTPRequest: %v", err)
	}
	if d2.Allowed {
		t.Fatalf("expected limited")
	}
}

func TestStore_ExemptPath(t *testing.T) {
	s := NewStore(Config{Enabled: true, ExemptPaths: []string{"/healthz"}, PerIP: BucketConfig{RPS: 0.1, Burst: 1}, Unauthenticated: BucketConfig{RPS: 0.1, Burst: 1}, PerToken: BucketConfig{RPS: 0.1, Burst: 1}})
	defer s.Close()

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "192.0.2.10:123"

	d, err := s.DecisionForHTTPRequest(r)
	if err != nil {
		t.Fatalf("DecisionForHTTPRequest: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("expected allowed")
	}
	if d.Bucket != "exempt" {
		t.Fatalf("expected exempt bucket, got %s", d.Bucket)
	}
}

func TestStore_GCRemovesExpired(t *testing.T) {
	cfg := Config{Enabled: true, EntryTTL: 10 * time.Millisecond, PerIP: BucketConfig{RPS: 1, Burst: 1}, Unauthenticated: BucketConfig{RPS: 1, Burst: 1}, PerToken: BucketConfig{RPS: 1, Burst: 1}}
	s := NewStore(cfg)
	defer s.Close()

	r := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	r.RemoteAddr = "192.0.2.10:123"
	_, _ = s.DecisionForHTTPRequest(r)

	time.Sleep(20 * time.Millisecond)
	s.evictExpired()

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) != 0 {
		t.Fatalf("expected entries to be evicted")
	}
}

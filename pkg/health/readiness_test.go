package health

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
)

func TestCheckerAuthDisabledSkipsAuth(t *testing.T) {
	dir := t.TempDir()
	al, err := audit.NewAuditLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })

	c := &Checker{AuthEnabled: false, Audit: al}
	res := c.Check(context.Background())
	if !res.Ready {
		t.Fatalf("expected ready, got error: %s", res.Error)
	}
	if res.Checks["auth"] != "skipped" {
		t.Fatalf("expected auth skipped, got %q", res.Checks["auth"])
	}
	if res.Checks["audit"] != "ok" {
		t.Fatalf("expected audit ok, got %q", res.Checks["audit"])
	}
}

func TestCheckerFailsWhenAuthEnabledAndNil(t *testing.T) {
	dir := t.TempDir()
	al, err := audit.NewAuditLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })

	c := &Checker{AuthEnabled: true, Auth: nil, Audit: al}
	res := c.Check(context.Background())
	if res.Ready {
		t.Fatalf("expected not ready")
	}
	if res.Checks["auth"] == "" {
		t.Fatalf("expected auth error")
	}
	if _, ok := res.Checks["audit"]; ok {
		t.Fatalf("expected audit not checked when auth fails")
	}
}

func TestCheckerFailsWhenAuditNil(t *testing.T) {
	c := &Checker{AuthEnabled: false, Audit: nil}
	res := c.Check(context.Background())
	if res.Ready {
		t.Fatalf("expected not ready")
	}
	if res.Checks["audit"] == "" {
		t.Fatalf("expected audit error")
	}
}

func TestCheckerAuditNilFailsAfterAuthOK(t *testing.T) {
	dir := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	t.Cleanup(func() { _ = am.Close() })

	c := &Checker{AuthEnabled: true, Auth: am, Audit: nil}
	res := c.Check(context.Background())
	if res.Ready {
		t.Fatalf("expected not ready")
	}
	if res.Checks["auth"] != "ok" {
		t.Fatalf("expected auth ok, got %q", res.Checks["auth"])
	}
	if res.Checks["audit"] == "" {
		t.Fatalf("expected audit error")
	}
}

type failingPinger struct{ err error }

func (f *failingPinger) Put(ctx context.Context, token string, sess *auth.Session) error {
	_ = ctx
	_ = token
	_ = sess
	return nil
}

func (f *failingPinger) Get(ctx context.Context, token string) (*auth.Session, error) {
	_ = ctx
	_ = token
	return nil, auth.ErrSessionNotFound
}

func (f *failingPinger) Delete(ctx context.Context, token string) error {
	_ = ctx
	_ = token
	return nil
}

func (f *failingPinger) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	_ = ctx
	_ = now
	return 0, nil
}

func (f *failingPinger) Close() error { return nil }

func (f *failingPinger) Ping(ctx context.Context) error {
	_ = ctx
	return f.err
}

func TestCheckerAuthReadyError(t *testing.T) {
	dir := t.TempDir()
	al, err := audit.NewAuditLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })

	am, err := auth.NewAuthManagerWithStore(filepath.Join(dir, "users.json"), &failingPinger{err: errors.New("auth down")})
	if err != nil {
		t.Fatalf("NewAuthManagerWithStore: %v", err)
	}
	t.Cleanup(func() { _ = am.Close() })

	c := &Checker{AuthEnabled: true, Auth: am, Audit: al}
	res := c.Check(context.Background())
	if res.Ready {
		t.Fatalf("expected not ready")
	}
	if res.Checks["auth"] == "ok" {
		t.Fatalf("expected auth error")
	}
	if _, ok := res.Checks["audit"]; ok {
		t.Fatalf("expected audit not checked when auth fails")
	}
}

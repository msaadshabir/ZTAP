package configbackup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"ztap/pkg/auth"
)

type testProvider struct {
	auth       *auth.AuthManager
	sessionsDB string
}

func (p *testProvider) Export(ctx context.Context, w *Writer, opts BackupOptions) (FeatureFlags, []string, error) {
	provider := &APIProvider{Auth: p.auth, SessionsSQLitePath: p.sessionsDB}
	return provider.Export(ctx, w, opts)
}

func (p *testProvider) PlanRestore(ctx context.Context, extractedDir string) (RestorePlan, error) {
	provider := &APIProvider{Auth: p.auth, SessionsSQLitePath: p.sessionsDB}
	return provider.PlanRestore(ctx, extractedDir)
}

func (p *testProvider) ApplyRestore(ctx context.Context, extractedDir string, force bool) (RestoreReport, error) {
	provider := &APIProvider{Auth: p.auth, SessionsSQLitePath: p.sessionsDB}
	return provider.ApplyRestore(ctx, extractedDir, force)
}

func TestBundleBuildValidateAndRestorePlan(t *testing.T) {
	tmp := t.TempDir()
	usersPath := filepath.Join(tmp, "users.json")

	am, err := auth.NewAuthManager(usersPath)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("alice", "password123", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	p := &testProvider{auth: am, sessionsDB: filepath.Join(tmp, "sessions.db")}
	svc := NewService(p)

	var buf bytes.Buffer
	manifest, err := svc.Backup(context.Background(), &buf, DefaultBackupOptions(), HostInfo{OS: "test", Arch: "test"})
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if manifest.BundleVersion != 1 {
		t.Fatalf("expected bundle version 1")
	}

	if _, err := svc.Validate(context.Background(), bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	extractDir := filepath.Join(tmp, "extract")
	if err := os.MkdirAll(extractDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, plan, err := svc.ExtractAndPlan(context.Background(), bytes.NewReader(buf.Bytes()), extractDir)
	if err != nil {
		t.Fatalf("ExtractAndPlan: %v", err)
	}
	if !plan.RequiresForce {
		t.Fatalf("expected requires force")
	}
}

func TestRestoreForceGate(t *testing.T) {
	tmp := t.TempDir()
	usersPath := filepath.Join(tmp, "users.json")

	am, err := auth.NewAuthManager(usersPath)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("alice", "password123", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	p := &testProvider{auth: am}
	svc := NewService(p)

	var buf bytes.Buffer
	_, err = svc.Backup(context.Background(), &buf, DefaultBackupOptions(), HostInfo{OS: "test", Arch: "test"})
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}

	extractDir := filepath.Join(tmp, "extract")
	_ = os.MkdirAll(extractDir, 0700)
	_, _, _, err = svc.Restore(context.Background(), bytes.NewReader(buf.Bytes()), extractDir, RestoreOptions{DryRun: false, Force: false})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRejectsUnexpectedFileBeforeManifest(t *testing.T) {
	// Create a deliberately invalid tar.gz where a file appears before manifest.json.
	invalid := buildTarGz(t, []tarEntry{{Path: "auth/users.json", Data: []byte("{}")}, {Path: "manifest.json", Data: []byte(`{"bundle_version":1,"created_at":"x","host":{"os":"x","arch":"x"},"features":{},"items":[]}`)}})

	svc := NewService(&testProvider{})
	if _, err := svc.Validate(context.Background(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

type tarEntry struct {
	Path string
	Data []byte
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.Path, Mode: 0600, Size: int64(len(e.Data))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write(e.Data); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

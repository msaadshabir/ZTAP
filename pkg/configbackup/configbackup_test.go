package configbackup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	manifest, err := svc.Backup(t.Context(), &buf, DefaultBackupOptions(), HostInfo{OS: "test", Arch: "test"})
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if manifest.BundleVersion != 1 {
		t.Fatalf("expected bundle version 1")
	}

	if _, err := svc.Validate(t.Context(), bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	extractDir := filepath.Join(tmp, "extract")
	if err := os.MkdirAll(extractDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, plan, err := svc.ExtractAndPlan(t.Context(), bytes.NewReader(buf.Bytes()), extractDir)
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
	_, err = svc.Backup(t.Context(), &buf, DefaultBackupOptions(), HostInfo{OS: "test", Arch: "test"})
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}

	extractDir := filepath.Join(tmp, "extract")
	_ = os.MkdirAll(extractDir, 0700)
	_, _, _, err = svc.Restore(t.Context(), bytes.NewReader(buf.Bytes()), extractDir, RestoreOptions{DryRun: false, Force: false})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateRejectsUnexpectedFileBeforeManifest(t *testing.T) {
	// Create a deliberately invalid tar.gz where a file appears before manifest.json.
	invalid := buildTarGz(t, []tarEntry{{Path: "auth/users.json", Data: []byte("{}")}, {Path: "manifest.json", Data: []byte(`{"bundle_version":1,"created_at":"x","host":{"os":"x","arch":"x"},"features":{},"items":[]}`)}})

	svc := NewService(&testProvider{})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestBackupIncludesManifestWarnings(t *testing.T) {
	svc := NewService(&testProvider{})

	t.Run("discovery not implemented", func(t *testing.T) {
		var buf bytes.Buffer
		m, err := svc.Backup(t.Context(), &buf, BackupOptions{IncludeDiscovery: true}, HostInfo{OS: "test", Arch: "test"})
		if err != nil {
			t.Fatalf("Backup: %v", err)
		}
		joined := strings.Join(m.Warnings, "\n")
		if !strings.Contains(joined, "discovery snapshot export not implemented") {
			t.Fatalf("expected discovery warning, got: %v", m.Warnings)
		}
	})

	t.Run("policy current missing", func(t *testing.T) {
		var buf bytes.Buffer
		m, err := svc.Backup(t.Context(), &buf, BackupOptions{IncludePolicyCurrent: true}, HostInfo{OS: "test", Arch: "test"})
		if err != nil {
			t.Fatalf("Backup: %v", err)
		}
		joined := strings.Join(m.Warnings, "\n")
		if !strings.Contains(joined, "policy current yaml not available") {
			t.Fatalf("expected policy current warning, got: %v", m.Warnings)
		}
	})
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

type tarEntryWithHeader struct {
	Header tar.Header
	Data   []byte
}

func buildTarGzWithHeaders(t *testing.T, entries []tarEntryWithHeader) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := e.Header
		if h.Mode == 0 {
			h.Mode = 0600
		}
		// If caller didn't set Size, infer for regular files.
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg && h.Size == 0 {
			h.Size = int64(len(e.Data))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(e.Data); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func mustManifestJSON(t *testing.T, items []ManifestItem) []byte {
	t.Helper()
	m := Manifest{BundleVersion: BundleVersion, CreatedAt: "x", Host: HostInfo{OS: "x", Arch: "x"}, Features: FeatureFlags{}, Items: items}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	return b
}

func itemForData(path string, data []byte) ManifestItem {
	sum := sha256.Sum256(data)
	return ManifestItem{Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func TestValidateRejectsPathTraversal(t *testing.T) {
	svc := NewService(&testProvider{})

	data := []byte("{}")
	items := []ManifestItem{itemForData("../evil", data)}
	invalid := buildTarGz(t, []tarEntry{{Path: "manifest.json", Data: mustManifestJSON(t, items)}, {Path: "../evil", Data: data}})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestValidateRejectsAbsolutePath(t *testing.T) {
	svc := NewService(&testProvider{})

	data := []byte("{}")
	items := []ManifestItem{itemForData("/abs", data)}
	invalid := buildTarGz(t, []tarEntry{{Path: "manifest.json", Data: mustManifestJSON(t, items)}, {Path: "/abs", Data: data}})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestValidateRejectsBackslashPath(t *testing.T) {
	svc := NewService(&testProvider{})

	data := []byte("{}")
	items := []ManifestItem{itemForData("a\\b", data)}
	invalid := buildTarGz(t, []tarEntry{{Path: "manifest.json", Data: mustManifestJSON(t, items)}, {Path: "a\\b", Data: data}})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestValidateRejectsUnexpectedFile(t *testing.T) {
	svc := NewService(&testProvider{})

	invalid := buildTarGz(t, []tarEntry{{Path: "manifest.json", Data: mustManifestJSON(t, nil)}, {Path: "auth/users.json", Data: []byte("{}")}})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestValidateRejectsChecksumMismatch(t *testing.T) {
	svc := NewService(&testProvider{})

	data := []byte("{}")
	it := itemForData("auth/users.json", data)
	it.SHA256 = strings.Repeat("0", 64)
	invalid := buildTarGz(t, []tarEntry{{Path: "manifest.json", Data: mustManifestJSON(t, []ManifestItem{it})}, {Path: "auth/users.json", Data: data}})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestValidateRejectsSizeMismatch(t *testing.T) {
	svc := NewService(&testProvider{})

	data := []byte("{}")
	it := itemForData("auth/users.json", data)
	it.Size = int64(len(data) + 1)
	invalid := buildTarGz(t, []tarEntry{{Path: "manifest.json", Data: mustManifestJSON(t, []ManifestItem{it})}, {Path: "auth/users.json", Data: data}})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestValidateRejectsDuplicateEntry(t *testing.T) {
	svc := NewService(&testProvider{})

	data := []byte("{}")
	it := itemForData("auth/users.json", data)
	invalid := buildTarGz(t, []tarEntry{{Path: "manifest.json", Data: mustManifestJSON(t, []ManifestItem{it})}, {Path: "auth/users.json", Data: data}, {Path: "auth/users.json", Data: data}})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestValidateRejectsNonRegularFile(t *testing.T) {
	svc := NewService(&testProvider{})

	items := []ManifestItem{{Path: "auth/users.json", SHA256: strings.Repeat("0", 64), Size: 0}}
	invalid := buildTarGzWithHeaders(t, []tarEntryWithHeader{
		{Header: tar.Header{Name: "manifest.json", Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(mustManifestJSON(t, items)))}, Data: mustManifestJSON(t, items)},
		{Header: tar.Header{Name: "auth/users.json", Mode: 0600, Typeflag: tar.TypeSymlink, Linkname: "target", Size: 0}, Data: nil},
	})
	if _, err := svc.Validate(t.Context(), bytes.NewReader(invalid)); err == nil {
		t.Fatalf("expected validate error")
	}
}

func TestProviderExportBestEffortWarnings(t *testing.T) {
	t.Run("users skipped when auth nil", func(t *testing.T) {
		svc := NewService(&APIProvider{Auth: nil})
		var buf bytes.Buffer
		m, err := svc.Backup(t.Context(), &buf, BackupOptions{IncludeUsers: true}, HostInfo{OS: "test", Arch: "test"})
		if err != nil {
			t.Fatalf("Backup: %v", err)
		}
		if m.Features.AuthUsers {
			t.Fatalf("expected auth_users feature false")
		}
		if !strings.Contains(strings.Join(m.Warnings, "\n"), "auth manager not available") {
			t.Fatalf("expected auth warning, got: %v", m.Warnings)
		}
	})

	t.Run("sessions skipped when sqlite path empty", func(t *testing.T) {
		svc := NewService(&APIProvider{SessionsSQLitePath: ""})
		var buf bytes.Buffer
		m, err := svc.Backup(t.Context(), &buf, BackupOptions{IncludeSessions: true}, HostInfo{OS: "test", Arch: "test"})
		if err != nil {
			t.Fatalf("Backup: %v", err)
		}
		if m.Features.AuthSessions {
			t.Fatalf("expected auth_sessions feature false")
		}
		if !strings.Contains(strings.Join(m.Warnings, "\n"), "sessions sqlite path not configured") {
			t.Fatalf("expected sessions warning, got: %v", m.Warnings)
		}
	})

	t.Run("sessions skipped when sqlite file missing", func(t *testing.T) {
		svc := NewService(&APIProvider{SessionsSQLitePath: filepath.Join(t.TempDir(), "missing.db")})
		var buf bytes.Buffer
		m, err := svc.Backup(t.Context(), &buf, BackupOptions{IncludeSessions: true}, HostInfo{OS: "test", Arch: "test"})
		if err != nil {
			t.Fatalf("Backup: %v", err)
		}
		if m.Features.AuthSessions {
			t.Fatalf("expected auth_sessions feature false")
		}
		if !strings.Contains(strings.Join(m.Warnings, "\n"), "sessions db not found") {
			t.Fatalf("expected sessions missing warning, got: %v", m.Warnings)
		}
	})

	t.Run("users skipped when users file missing", func(t *testing.T) {
		tmp := t.TempDir()
		am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
		if err != nil {
			t.Fatalf("NewAuthManager: %v", err)
		}
		_ = os.Remove(am.UsersPath())

		svc := NewService(&APIProvider{Auth: am})
		var buf bytes.Buffer
		m, err := svc.Backup(t.Context(), &buf, BackupOptions{IncludeUsers: true}, HostInfo{OS: "test", Arch: "test"})
		if err != nil {
			t.Fatalf("Backup: %v", err)
		}
		if m.Features.AuthUsers {
			t.Fatalf("expected auth_users feature false")
		}
		if !strings.Contains(strings.Join(m.Warnings, "\n"), "failed reading users file") {
			t.Fatalf("expected users read warning, got: %v", m.Warnings)
		}
	})
}

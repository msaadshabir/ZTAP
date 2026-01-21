package configbackup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

const BundleVersion int = 1

type BackupOptions struct {
	IncludeUsers    bool
	IncludeSessions bool

	IncludePolicyCurrent   bool
	IncludePolicyRevisions bool

	IncludeDiscovery bool
	IncludeConfig    bool
}

func DefaultBackupOptions() BackupOptions {
	return BackupOptions{
		// Option B defaults: only stable, implemented exports by default.
		IncludeUsers:           true,
		IncludeSessions:        true,
		IncludePolicyCurrent:   false,
		IncludePolicyRevisions: false,
		IncludeDiscovery:       false,
		IncludeConfig:          true,
	}
}

type RestoreOptions struct {
	DryRun bool
	Force  bool
}

type FeatureFlags struct {
	AuthUsers       bool `json:"auth_users"`
	AuthSessions    bool `json:"auth_sessions"`
	PolicyCurrent   bool `json:"policy_current"`
	PolicyRevisions bool `json:"policy_revisions"`
	DiscoverySnap   bool `json:"discovery_snapshot"`
	ConfigEffective bool `json:"config_effective"`
}

type ManifestItem struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type,omitempty"`
}

type Manifest struct {
	BundleVersion int            `json:"bundle_version"`
	CreatedAt     string         `json:"created_at"`
	Host          HostInfo       `json:"host"`
	Features      FeatureFlags   `json:"features"`
	Warnings      []string       `json:"warnings,omitempty"`
	Items         []ManifestItem `json:"items"`
}

type HostInfo struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type RestorePlan struct {
	RequiresForce  bool     `json:"requires_force"`
	WouldOverwrite []string `json:"would_overwrite"`
	WouldCreate    []string `json:"would_create"`
	Warnings       []string `json:"warnings"`
}

type RestoreReport struct {
	Applied         bool     `json:"applied"`
	DryRun          bool     `json:"dry_run"`
	RestartRequired bool     `json:"restart_required"`
	Warnings        []string `json:"warnings"`
}

type Provider interface {
	Export(ctx context.Context, w *Writer, opts BackupOptions) (FeatureFlags, []string, error)
	PlanRestore(ctx context.Context, extractedDir string) (RestorePlan, error)
	ApplyRestore(ctx context.Context, extractedDir string, force bool) (RestoreReport, error)
}

type Service struct {
	provider Provider
	mu       sync.Mutex
}

func NewService(p Provider) *Service {
	return &Service{provider: p}
}

func (s *Service) Backup(ctx context.Context, dst io.Writer, opts BackupOptions, host HostInfo) (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	gz := gzip.NewWriter(dst)
	defer func() { _ = gz.Close() }()
	tarw := tar.NewWriter(gz)
	defer func() { _ = tarw.Close() }()

	w := &Writer{tw: tarw, bufs: make(map[string][]byte)}
	features, warnings, err := s.provider.Export(ctx, w, opts)
	if err != nil {
		return Manifest{}, err
	}

	items := w.items()
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })

	m := Manifest{
		BundleVersion: BundleVersion,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Host:          host,
		Features:      features,
		Warnings:      append([]string(nil), warnings...),
		Items:         items,
	}

	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}

	// Ensure manifest is the first entry.
	if err := writeRawFile(tarw, "manifest.json", manifestBytes, 0600); err != nil {
		return Manifest{}, err
	}

	// Write all non-manifest files after manifest.
	for _, it := range items {
		b, err := w.FileBytes(it.Path)
		if err != nil {
			return Manifest{}, err
		}
		if err := writeRawFile(tarw, it.Path, b, 0600); err != nil {
			return Manifest{}, err
		}
	}

	return m, nil
}

func (s *Service) Validate(ctx context.Context, src io.Reader) (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	gzr, err := gzip.NewReader(src)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)

	var manifest Manifest
	seenManifest := false
	items := make(map[string]ManifestItem)
	seen := make(map[string]struct{})

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, err
		}

		if err := validateTarHeader(h); err != nil {
			return Manifest{}, err
		}

		name := path.Clean(h.Name)
		if name == "." {
			return Manifest{}, errors.New("invalid entry name")
		}
		if _, ok := seen[name]; ok {
			return Manifest{}, fmt.Errorf("duplicate entry %s", name)
		}
		seen[name] = struct{}{}

		data, err := io.ReadAll(tr)
		if err != nil {
			return Manifest{}, err
		}

		if name == "manifest.json" {
			if err := json.Unmarshal(data, &manifest); err != nil {
				return Manifest{}, fmt.Errorf("parsing manifest: %w", err)
			}
			if manifest.BundleVersion != BundleVersion {
				return Manifest{}, fmt.Errorf("unsupported bundle version %d", manifest.BundleVersion)
			}
			seenManifest = true
			for _, it := range manifest.Items {
				items[it.Path] = it
			}
			continue
		}

		if !seenManifest {
			return Manifest{}, errors.New("manifest.json must appear before other entries")
		}

		it, ok := items[name]
		if !ok {
			return Manifest{}, fmt.Errorf("unexpected file %s", name)
		}

		sum := sha256.Sum256(data)
		hexSum := hex.EncodeToString(sum[:])
		if it.SHA256 != hexSum {
			return Manifest{}, fmt.Errorf("checksum mismatch for %s", name)
		}
		if it.Size != int64(len(data)) {
			return Manifest{}, fmt.Errorf("size mismatch for %s", name)
		}
	}

	if !seenManifest {
		return Manifest{}, errors.New("missing manifest.json")
	}

	for _, it := range manifest.Items {
		if _, ok := seen[it.Path]; !ok {
			return Manifest{}, fmt.Errorf("missing file %s", it.Path)
		}
	}

	return manifest, nil
}

func validateTarHeader(h *tar.Header) error {
	name := h.Name
	if strings.Contains(name, "\\") {
		return errors.New("invalid path separator")
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return errors.New("invalid path")
	}
	if strings.HasPrefix(clean, "/") {
		return errors.New("absolute paths not allowed")
	}
	if h.Typeflag != tar.TypeReg {
		return errors.New("only regular files supported")
	}
	return nil
}

type Writer struct {
	tw    *tar.Writer
	mu    sync.Mutex
	files []ManifestItem
	bufs  map[string][]byte
}

func writeRawFile(tw *tar.Writer, p string, data []byte, mode int64) error {
	h := &tar.Header{Name: p, Mode: mode, Size: int64(len(data))}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	return nil
}

func (w *Writer) items() []ManifestItem {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]ManifestItem, len(w.files))
	copy(out, w.files)
	return out
}

func (w *Writer) WriteFile(p string, contentType string, data []byte, mode int64) (ManifestItem, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return ManifestItem{}, fmt.Errorf("invalid bundle path %s", p)
	}
	if strings.Contains(clean, "\\") {
		return ManifestItem{}, fmt.Errorf("invalid bundle path %s", p)
	}

	sum := sha256.Sum256(data)
	it := ManifestItem{Path: clean, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), ContentType: contentType}

	// The Service writes archive entries after building the manifest.
	// Buffer the file content here and only record it in the manifest list.

	// Do not include manifest.json in manifest.Items.
	if clean != "manifest.json" {
		w.files = append(w.files, it)
		w.bufs[clean] = append([]byte(nil), data...)
	}
	return it, nil
}

func (w *Writer) FileBytes(p string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, ok := w.bufs[p]
	if !ok {
		return nil, fmt.Errorf("missing buffered file %s", p)
	}
	return append([]byte(nil), b...), nil
}

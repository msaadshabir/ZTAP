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
	"os"
	"path"
	"path/filepath"
	"strings"
)

func (s *Service) ExtractAndPlan(ctx context.Context, src io.Reader, extractedDir string) (Manifest, RestorePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	manifest, _, err := readBundleIntoDir(src, extractedDir)
	if err != nil {
		return Manifest{}, RestorePlan{}, err
	}

	plan, err := s.provider.PlanRestore(ctx, extractedDir)
	if err != nil {
		return Manifest{}, RestorePlan{}, err
	}

	return manifest, plan, nil
}

func (s *Service) Restore(ctx context.Context, src io.Reader, extractedDir string, opts RestoreOptions) (Manifest, RestorePlan, RestoreReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	manifest, _, err := readBundleIntoDir(src, extractedDir)
	if err != nil {
		return Manifest{}, RestorePlan{}, RestoreReport{}, err
	}

	plan, err := s.provider.PlanRestore(ctx, extractedDir)
	if err != nil {
		return Manifest{}, RestorePlan{}, RestoreReport{}, err
	}

	if opts.DryRun {
		return manifest, plan, RestoreReport{Applied: false, DryRun: true, RestartRequired: true, Warnings: append([]string(nil), plan.Warnings...)}, nil
	}

	rep, err := s.provider.ApplyRestore(ctx, extractedDir, opts.Force)
	if err != nil {
		return Manifest{}, RestorePlan{}, RestoreReport{}, err
	}
	if len(plan.Warnings) > 0 {
		rep.Warnings = append(append([]string(nil), plan.Warnings...), rep.Warnings...)
	}
	rep.RestartRequired = true
	return manifest, plan, rep, nil
}

func readBundleIntoDir(src io.Reader, extractedDir string) (Manifest, []string, error) {
	gzr, err := gzip.NewReader(src)
	if err != nil {
		return Manifest{}, nil, err
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)

	var manifest Manifest
	manifestFound := false
	manifestItems := map[string]ManifestItem{}
	written := []string{}

	baseAbs, err := filepath.Abs(extractedDir)
	if err != nil {
		return Manifest{}, nil, err
	}

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, nil, err
		}
		if err := validateTarHeader(h); err != nil {
			return Manifest{}, nil, err
		}

		name := path.Clean(h.Name)
		data, err := io.ReadAll(tr)
		if err != nil {
			return Manifest{}, nil, err
		}

		if name == "manifest.json" {
			if err := json.Unmarshal(data, &manifest); err != nil {
				return Manifest{}, nil, fmt.Errorf("parsing manifest: %w", err)
			}
			if manifest.BundleVersion != BundleVersion {
				return Manifest{}, nil, fmt.Errorf("unsupported bundle version %d", manifest.BundleVersion)
			}
			for _, it := range manifest.Items {
				manifestItems[it.Path] = it
			}
			manifestFound = true
			continue
		}

		if !manifestFound {
			return Manifest{}, nil, errors.New("manifest.json must appear before other entries")
		}

		it, ok := manifestItems[name]
		if !ok {
			return Manifest{}, nil, fmt.Errorf("unexpected file %s", name)
		}
		sum := sha256.Sum256(data)
		if it.SHA256 != hex.EncodeToString(sum[:]) {
			return Manifest{}, nil, fmt.Errorf("checksum mismatch for %s", name)
		}
		if it.Size != int64(len(data)) {
			return Manifest{}, nil, fmt.Errorf("size mismatch for %s", name)
		}

		// Write extracted file.
		relDst, err := sanitizeManifestPath(name)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("invalid extraction path %s: %w", name, err)
		}
		dstAbs, err := filepath.Abs(filepath.Join(baseAbs, relDst))
		if err != nil {
			return Manifest{}, nil, err
		}
		rel, err := filepath.Rel(baseAbs, dstAbs)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return Manifest{}, nil, errors.New("invalid extraction path")
		}
		if err := os.MkdirAll(filepath.Dir(dstAbs), 0700); err != nil {
			return Manifest{}, nil, err
		}
		if err := os.WriteFile(dstAbs, data, 0600); err != nil {
			return Manifest{}, nil, err
		}

		written = append(written, name)
	}

	if !manifestFound {
		return Manifest{}, nil, errors.New("missing manifest.json")
	}

	for _, it := range manifest.Items {
		relPath, err := sanitizeManifestPath(it.Path)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("invalid manifest item path %s: %w", it.Path, err)
		}
		p := filepath.Join(baseAbs, relPath)
		absP, err := filepath.Abs(p)
		if err != nil {
			return Manifest{}, nil, err
		}
		rel, err := filepath.Rel(baseAbs, absP)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return Manifest{}, nil, fmt.Errorf("invalid manifest item path %s", it.Path)
		}

		if _, err := os.Stat(absP); err != nil {
			return Manifest{}, nil, fmt.Errorf("missing file %s", it.Path)
		}
	}

	return manifest, written, nil
}

// sanitizeManifestPath validates a manifest item path and returns a normalized
// relative path using OS-specific separators. It rejects absolute paths and any
// use of "." or ".." path components.
func sanitizeManifestPath(p string) (string, error) {
	relPath := filepath.FromSlash(p)
	if relPath == "" {
		return "", errors.New("empty path")
	}

	// Reject absolute paths (including drive letters or UNC paths on Windows).
	if filepath.IsAbs(relPath) {
		return "", errors.New("absolute paths are not allowed")
	}

	sep := string(os.PathSeparator)
	parts := strings.SplitSeq(relPath, sep)
	for part := range parts {
		if part == "" {
			return "", errors.New("empty path component")
		}
		if part == "." || part == ".." {
			return "", errors.New("dot or dot-dot path components are not allowed")
		}
	}

	return relPath, nil
}

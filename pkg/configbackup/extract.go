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

	manifest, files, err := readBundleIntoDir(src, extractedDir)
	if err != nil {
		return Manifest{}, RestorePlan{}, err
	}

	plan, err := s.provider.PlanRestore(ctx, extractedDir)
	if err != nil {
		return Manifest{}, RestorePlan{}, err
	}

	// Ensure membership checks: no extras.
	_ = files
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
		dst := filepath.Join(extractedDir, filepath.FromSlash(name))
		if !strings.HasPrefix(dst, extractedDir+string(os.PathSeparator)) && dst != extractedDir {
			return Manifest{}, nil, errors.New("invalid extraction path")
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return Manifest{}, nil, err
		}
		if err := os.WriteFile(dst, data, 0600); err != nil {
			return Manifest{}, nil, err
		}

		written = append(written, name)
	}

	if !manifestFound {
		return Manifest{}, nil, errors.New("missing manifest.json")
	}

	for _, it := range manifest.Items {
		relPath := filepath.FromSlash(it.Path)
		p := filepath.Join(extractedDir, relPath)

		absBase, err := filepath.Abs(extractedDir)
		if err != nil {
			return Manifest{}, nil, err
		}
		absP, err := filepath.Abs(p)
		if err != nil {
			return Manifest{}, nil, err
		}
		if !strings.HasPrefix(absP, absBase+string(os.PathSeparator)) && absP != absBase {
			return Manifest{}, nil, fmt.Errorf("invalid manifest item path %s", it.Path)
		}

		if _, err := os.Stat(absP); err != nil {
			return Manifest{}, nil, fmt.Errorf("missing file %s", it.Path)
		}
	}

	return manifest, written, nil
}

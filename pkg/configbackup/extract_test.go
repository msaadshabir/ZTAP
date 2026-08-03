package configbackup

import (
	"bytes"
	"strings"
	"testing"
)

func TestExtractAndPlanRejectsDotDotArchivePath(t *testing.T) {
	svc := NewService(&testProvider{})

	invalid := buildTarGz(t, []tarEntry{
		{Path: "manifest.json", Data: mustManifestJSON(t, nil)},
		{Path: "auth..x/users.json", Data: []byte("{}")},
	})
	if _, _, err := svc.ExtractAndPlan(t.Context(), bytes.NewReader(invalid), t.TempDir()); err == nil {
		t.Fatalf("expected extraction error for archive path containing ..")
	}
}

func TestExtractAndPlanRejectsDotDotManifestPath(t *testing.T) {
	svc := NewService(&testProvider{})

	items := []ManifestItem{{Path: "auth..x/users.json", SHA256: strings.Repeat("0", 64), Size: 0}}
	invalid := buildTarGz(t, []tarEntry{
		{Path: "manifest.json", Data: mustManifestJSON(t, items)},
	})
	if _, _, err := svc.ExtractAndPlan(t.Context(), bytes.NewReader(invalid), t.TempDir()); err == nil {
		t.Fatalf("expected extraction error for manifest path containing ..")
	}
}

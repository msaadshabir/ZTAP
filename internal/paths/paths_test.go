package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHomePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	if got, want := Expand(" ~/ztap.log "), filepath.Join(home, "ztap.log"); got != want {
		t.Fatalf("Expand home path = %q, want %q", got, want)
	}
}

func TestExpandLeavesTildeUserPathUnchanged(t *testing.T) {
	const path = "~other/ztap.log"
	if got := Expand(path); got != path {
		t.Fatalf("Expand(%q) = %q, want unchanged", path, got)
	}
}

//go:build linux

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeBootstrapRejectsUnsafeOrStaleRecordsBeforeRuntimeUse(t *testing.T) {
	boot, err := nodeBootID()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name         string
		mutate       func(*nodeBootstrap)
		mode         os.FileMode
		suffix, want string
	}{
		{name: "foreign boot", mutate: func(r *nodeBootstrap) { r.Boot = "foreign" }, mode: 0o600, want: "another node, boot, or schema"},
		{name: "foreign node", mutate: func(r *nodeBootstrap) { r.Node = "node-b" }, mode: 0o600, want: "another node, boot, or schema"},
		{name: "schema", mutate: func(r *nodeBootstrap) { r.Schema = 99 }, mode: 0o600, want: "another node, boot, or schema"},
		{name: "unsafe mode", mode: 0o640, want: "unsafe node bootstrap"},
		{name: "trailing record", mode: 0o600, suffix: "{}", want: "trailing data"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runDir := t.TempDir()
			record := nodeBootstrap{Schema: 1, Boot: boot, Node: "node-a", NodeUID: "node-uid", HostNetnsCookie: 1}
			if test.mutate != nil {
				test.mutate(&record)
			}
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, test.suffix...)
			if err := os.WriteFile(filepath.Join(runDir, nodeBootstrapFile), data, test.mode); err != nil {
				t.Fatal(err)
			}
			_, err = loadNodeGuardBootstrap(runDir, t.TempDir(), "node-a", "11111111-2222-3333-4444-555555555555")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe record error=%v; want %s", err, test.want)
			}
		})
	}
}

func TestNodeBootstrapRejectsSymlinkAndHardlink(t *testing.T) {
	for _, hard := range []bool{false, true} {
		t.Run(map[bool]string{false: "symlink", true: "hardlink"}[hard], func(t *testing.T) {
			runDir := t.TempDir()
			target := filepath.Join(t.TempDir(), "foreign-record")
			if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			if hard {
				err = os.Link(target, filepath.Join(runDir, nodeBootstrapFile))
			} else {
				err = os.Symlink(target, filepath.Join(runDir, nodeBootstrapFile))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loadNodeGuardBootstrap(runDir, t.TempDir(), "node-a", "11111111-2222-3333-4444-555555555555"); err == nil {
				t.Fatal("accepted a redirected bootstrap record")
			}
		})
	}
}

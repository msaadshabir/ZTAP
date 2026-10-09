//go:build linux && integration

package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLinuxExplicitCleanupRetriesAndPreservesForeignObjects(t *testing.T) {
	requireLinuxEBPFRoot(t)
	cgroup := createTestCgroup(t)
	id := mustCgroupID(t, cgroup)
	root := createEngineTestBPFFSRoot(t)
	options := LinuxEngineOptions{BPFFSRoot: root, ResolveCgroupPath: func(context.Context, uint64) (string, error) { return cgroup, nil }}
	engine, err := NewLinuxEngine(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(context.Background(), restartProofPolicy(id, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	foreign, err := ebpf.NewMap(&ebpf.MapSpec{Name: "foreign", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()
	foreignPath := filepath.Join(root, "ztap", "unrelated")
	if err := foreign.Pin(foreignPath); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(foreignPath) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	removed := ""
	err = removeEnforcement(ctx, root, func(name string) { removed = name; cancel() })
	if !errors.Is(err, context.Canceled) || removed != subjectPinName(id, 0) {
		t.Fatalf("partial cleanup checkpoint: removed=%q err=%v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(root, "ztap", subjectPinName(id, 1))); err != nil {
		t.Fatalf("partial cleanup lost surviving ingress: %v", err)
	}
	if _, err := NewLinuxEngine(context.Background(), options); err == nil {
		t.Fatal("startup adopted an incomplete intentional uninstall")
	}
	if _, err := os.Stat(filepath.Join(root, "ztap", subjectPinName(id, 1))); err != nil {
		t.Fatalf("rejected startup removed ingress: %v", err)
	}
	if err := RemoveEnforcement(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "ztap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "unrelated" {
		t.Fatalf("cleanup left owned objects or removed unrelated pins: %+v", entries)
	}
	probe, err := ebpf.LoadPinnedMap(foreignPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := probe.Info()
	_ = probe.Close()
	if err != nil {
		t.Fatal(err)
	}
	original, err := foreign.Info()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := info.ID()
	want, _ := original.ID()
	if got != want {
		t.Fatal("cleanup replaced the unrelated object")
	}
}

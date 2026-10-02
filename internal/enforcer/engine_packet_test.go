package enforcer

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Run the real packet program with deterministic userspace BPF helpers. This
// covers TCP flags and clock transitions without pretending to validate Linux
// attachment or the kernel verifier; integration tests cover those separately.
func TestPacketConnectionLifecycle(t *testing.T) {
	compiler, err := exec.LookPath("clang")
	if err != nil {
		compiler, err = exec.LookPath("cc")
	}
	if err != nil {
		t.Skip("packet decision test requires a host C compiler")
	}
	binary := filepath.Join(t.TempDir(), "connection-state")
	source, err := filepath.Abs(filepath.Join("..", "..", "bpf", "tests", "connection_state.c"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(t.Context(), compiler, "-std=gnu11", "-O2", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile packet test: %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(t.Context(), binary).CombinedOutput(); err != nil {
		t.Fatalf("packet decisions: %v\n%s", err, output)
	}
}

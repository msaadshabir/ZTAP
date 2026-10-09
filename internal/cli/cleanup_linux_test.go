//go:build linux

package cli

import (
	"context"
	"strings"
	"testing"
)

func TestCleanupRefusesCompetingNodeAgent(t *testing.T) {
	runDir := t.TempDir()
	unlock, err := acquireNativeAgentLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	// An invalid bpffs path establishes that lock contention is checked before
	// the cleanup command can inspect or mutate enforcement pins.
	if err := cleanupNativeEnforcement(context.Background(), "/not-a-bpffs-root", runDir); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("cleanup did not refuse a competing agent before opening bpffs: %v", err)
	}
}

//go:build linux && integration

package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/policy"
)

func TestFlowReaderDetectsRecoveredAgentEpochOnSamePinnedMap(t *testing.T) {
	root := filepath.Join("/sys/fs/bpf", fmt.Sprintf("ztap-flow-recovery-%d", time.Now().UnixNano()))
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := enforcer.RemoveEnforcement(context.Background(), root); err != nil {
			t.Error(err)
			return
		}
		if err := os.Remove(filepath.Join(root, "ztap")); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
		if err := os.Remove(root); err != nil {
			t.Error(err)
		}
	})
	options := enforcer.LinuxEngineOptions{BPFFSRoot: root, AgentEpoch: 101, ResolveCgroupPath: func(_ context.Context, id uint64) (string, error) { return "", fmt.Errorf("unexpected subject %d", id) }}
	first, err := enforcer.NewLinuxEngine(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	set := policy.PolicySet{NodeIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	if err := first.Apply(t.Context(), set); err != nil {
		t.Fatal(err)
	}
	statusMap, err := ebpf.LoadPinnedMap(filepath.Join(root, "ztap", "agent_status"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = statusMap.Close() }()
	before, err := readPinnedAgentStatus(statusMap)
	if err != nil {
		t.Fatal(err)
	}
	now, err := monotonicNowNS()
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := validatePinnedAgentStatus(before, 0, false, now)
	if err != nil || epoch != 101 {
		t.Fatalf("original reader status: %d %v", epoch, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	options.AgentEpoch = 102
	replacement, err := enforcer.NewLinuxEngine(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	if err := replacement.Apply(t.Context(), set); err != nil {
		t.Fatal(err)
	}
	after, err := readPinnedAgentStatus(statusMap)
	if err != nil {
		t.Fatal(err)
	}
	now, err = monotonicNowNS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePinnedAgentStatus(after, epoch, true, now); err == nil || !strings.Contains(err.Error(), "agent epoch changed") {
		t.Fatalf("old reader accepted recovered controller: %v", err)
	}
	if epoch, err := validatePinnedAgentStatus(after, 0, false, now); err != nil || epoch != 102 {
		t.Fatalf("reconnected reader status: %d %v", epoch, err)
	}
	metrics, err := replacement.MetricsSnapshot(t.Context())
	if err != nil || metrics.ActivePolicyEpoch != 1 {
		t.Fatalf("recovery changed the policy epoch: %+v %v", metrics, err)
	}
}

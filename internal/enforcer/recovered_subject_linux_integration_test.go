//go:build linux && integration

package enforcer

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/saadshabir/ZTAP/internal/policy"
)

func TestLinuxRecoveryPreservesLiveSubjectDuringIdentityUncertainty(t *testing.T) {
	requireLinuxEBPFRoot(t)
	cgroup := createTestCgroup(t)
	id := mustCgroupID(t, cgroup)
	root := createEngineTestBPFFSRoot(t)
	opts := LinuxEngineOptions{BPFFSRoot: root, ResolveCgroupPath: func(context.Context, uint64) (string, error) { return cgroup, nil }}
	engine, err := NewLinuxEngine(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	listener := listenEngineTestUDP(t)
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
	set := restartProofPolicy(id, port, port)
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	key := bpfConnectionKey{CgroupID: id, PolicyEpoch: 1, SourcePort: 12345, DestinationPort: port, Protocol: policy.ProtocolUDP}
	value := bpfConnectionValue{ExpiresAtNS: ^uint64(0)}
	if err := engine.store.maps["conn_state"].Put(&key, &value); err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	uncertain := true
	opts.ValidateIdentity = func(context.Context, WorkloadIdentity) error {
		if uncertain {
			return errors.New("live subject status unavailable")
		}
		return nil
	}
	replacement, err := NewLinuxEngine(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	unisolated := policy.PolicySet{NodeIPs: set.NodeIPs}
	for _, state := range []string{"id-missing", "pending", "pod-missing"} {
		if err := replacement.Apply(context.Background(), unisolated); err == nil {
			t.Fatalf("%s accepted unresolved live ownership", state)
		}
		if replacement.active.PolicyEpoch != 1 {
			t.Fatal("identity uncertainty advanced epoch")
		}
		var recovered bpfConnectionValue
		if err := replacement.store.maps["conn_state"].Lookup(&key, &recovered); err != nil || recovered != value {
			t.Fatalf("lost reply state: %+v %v", recovered, err)
		}
		for direction := range 2 {
			handle, err := link.LoadPinnedLink(filepath.Join(root, "ztap", subjectPinName(id, direction)), nil)
			if err != nil {
				t.Fatal(err)
			}
			info, err := handle.Info()
			_ = handle.Close()
			if err != nil || info.Cgroup() == nil || info.Cgroup().CgroupId != id {
				t.Fatalf("lost directional protection: %+v %v", info, err)
			}
		}
	}
	uncertain = false
	if err := replacement.Apply(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if replacement.active.PolicyEpoch != 1 {
		t.Fatal("unchanged resolved identity invalidated reply epoch")
	}
	if err := replacement.Apply(context.Background(), unisolated); err != nil {
		t.Fatal(err)
	}
	for direction := range 2 {
		if _, err := os.Lstat(filepath.Join(root, "ztap", subjectPinName(id, direction))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("verified unisolated subject retained link: %v", err)
		}
	}
}

func TestLinuxRecoveryRejectsForeignMapWithoutRemovingProtection(t *testing.T) {
	requireLinuxEBPFRoot(t)
	cgroup := createTestCgroup(t)
	id := mustCgroupID(t, cgroup)
	root := createEngineTestBPFFSRoot(t)
	opts := LinuxEngineOptions{BPFFSRoot: root, ResolveCgroupPath: func(context.Context, uint64) (string, error) { return cgroup, nil }}
	engine, err := NewLinuxEngine(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()
	allowed, denied := listenEngineTestUDP(t), listenEngineTestUDP(t)
	port := uint16(allowed.LocalAddr().(*net.UDPAddr).Port)
	if err := engine.Apply(context.Background(), restartProofPolicy(id, port, port)); err != nil {
		t.Fatal(err)
	}
	original, err := engine.store.maps["subject_state"].Clone()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	spec, err := loadEngine()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := ebpf.NewMap(spec.Maps["subject_state"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()
	path := filepath.Join(root, "ztap", "subject_state")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := foreign.Pin(path); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove(path)
		if err := original.Pin(path); err != nil {
			t.Error(err)
		}
	}()
	if replacement, err := NewLinuxEngine(context.Background(), opts); err == nil {
		_ = replacement.Close()
		t.Fatal("adopted a same-layout foreign map")
	}
	runUDPSendHelperInCgroup(t, cgroup, allowed.LocalAddr().String())
	assertEngineUDPDelivery(t, allowed, true)
	runUDPSendHelperInCgroup(t, cgroup, denied.LocalAddr().String())
	assertEngineUDPDelivery(t, denied, false)
}

func TestLinuxRecoveryAllowsConfirmedCgroupReplacement(t *testing.T) {
	requireLinuxEBPFRoot(t)
	cgroup := createTestCgroup(t)
	oldID := mustCgroupID(t, cgroup)
	root := createEngineTestBPFFSRoot(t)
	options := LinuxEngineOptions{BPFFSRoot: root, ResolveCgroupPath: func(context.Context, uint64) (string, error) { return cgroup, nil }}
	engine, err := NewLinuxEngine(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	set := restartProofPolicy(oldID, 1, 1)
	if err := engine.Apply(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cgroup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	newID := mustCgroupID(t, cgroup)
	if newID == oldID {
		t.Fatal("replacement inherited the old kernel cgroup ID")
	}
	options.ValidateIdentity = func(context.Context, WorkloadIdentity) error {
		return errors.New("old Pod omitted from informer cache")
	}
	replacement, err := NewLinuxEngine(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	set = restartProofPolicy(newID, 1, 1)
	if err := replacement.Apply(context.Background(), set); err != nil {
		t.Fatalf("kernel-confirmed disappearance prevented replacement: %v", err)
	}
	if replacement.active.PolicyEpoch != 2 {
		t.Fatal("replacement did not commit a new identity epoch")
	}
	for direction := range 2 {
		if _, err := os.Stat(filepath.Join(root, "ztap", subjectPinName(oldID, direction))); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("dead cgroup retained an authorization pin")
		}
		handle, err := link.LoadPinnedLink(filepath.Join(root, "ztap", subjectPinName(newID, direction)), nil)
		if err != nil {
			t.Fatal(err)
		}
		info, err := handle.Info()
		_ = handle.Close()
		if err != nil || info.Cgroup() == nil || info.Cgroup().CgroupId != newID {
			t.Fatal("new attachment targets a stale cgroup identity")
		}
	}
}

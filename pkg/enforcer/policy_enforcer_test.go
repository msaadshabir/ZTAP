//go:build !integration
// +build !integration

package enforcer

import (
	"context"
	"testing"
	"time"

	"ztap/pkg/cluster"
)

// mockPolicySync is a mock implementation of PolicySync for testing
type mockPolicySync struct {
	updates chan cluster.PolicyUpdate
}

func newMockPolicySync() *mockPolicySync {
	return &mockPolicySync{
		updates: make(chan cluster.PolicyUpdate, 10),
	}
}

func (m *mockPolicySync) SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error {
	return nil
}

func (m *mockPolicySync) GetPolicyVersion(policyName string) (int64, error) {
	return 1, nil
}

func (m *mockPolicySync) SubscribePolicies(ctx context.Context) <-chan cluster.PolicyUpdate {
	return m.updates
}

func (m *mockPolicySync) sendUpdate(update cluster.PolicyUpdate) {
	m.updates <- update
}

func TestNewPolicyEnforcer(t *testing.T) {
	mockSync := newMockPolicySync()

	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: mockSync,
		Discovery:  nil,
		CgroupPath: "/sys/fs/cgroup/test",
	})

	if enforcer == nil {
		t.Fatal("NewPolicyEnforcer returned nil")
	}
	if enforcer.policySync != mockSync {
		t.Error("PolicySync not set correctly")
	}
	if enforcer.cgroupPath != "/sys/fs/cgroup/test" {
		t.Errorf("expected cgroup path /sys/fs/cgroup/test, got %s", enforcer.cgroupPath)
	}
}

func TestPolicyEnforcerStartStop(t *testing.T) {
	mockSync := newMockPolicySync()

	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: mockSync,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start should succeed
	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !enforcer.running {
		t.Error("enforcer should be running after Start()")
	}

	// Double start should be idempotent
	if err := enforcer.Start(ctx); err != nil {
		t.Error("second Start() should not fail")
	}

	// Stop should succeed
	if err := enforcer.Stop(); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	if enforcer.running {
		t.Error("enforcer should not be running after Stop()")
	}

	// Double stop should be idempotent
	if err := enforcer.Stop(); err != nil {
		t.Error("second Stop() should not fail")
	}
}

func TestPolicyEnforcerAppliesUpdates(t *testing.T) {
	mockSync := newMockPolicySync()

	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: mockSync,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = enforcer.Stop() }()

	// Send a policy update
	policyYAML := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      podSelector:
        matchLabels:
          app: db
    ports:
    - protocol: TCP
      port: 5432`)

	update := cluster.PolicyUpdate{
		PolicyName: "test-policy",
		YAML:       policyYAML,
		Version:    1,
		Source:     "node-1",
		Timestamp:  time.Now(),
	}

	mockSync.sendUpdate(update)

	// Wait for enforcement
	time.Sleep(200 * time.Millisecond)

	// Check that version was tracked
	version := enforcer.GetEnforcedVersion("test-policy")
	if version != 1 {
		t.Errorf("expected enforced version 1, got %d", version)
	}
}

func TestPolicyEnforcerSkipsOldVersions(t *testing.T) {
	mockSync := newMockPolicySync()

	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: mockSync,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = enforcer.Stop() }()

	policyYAML := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      ipBlock:
        cidr: 10.0.0.0/8
    ports:
    - protocol: TCP
      port: 80`)

	// Send version 2
	update2 := cluster.PolicyUpdate{
		PolicyName: "test-policy",
		YAML:       policyYAML,
		Version:    2,
		Source:     "node-1",
		Timestamp:  time.Now(),
	}
	mockSync.sendUpdate(update2)
	time.Sleep(200 * time.Millisecond)

	// Version should be 2
	if enforcer.GetEnforcedVersion("test-policy") != 2 {
		t.Error("expected version 2 to be enforced")
	}

	// Send version 1 (older)
	update1 := cluster.PolicyUpdate{
		PolicyName: "test-policy",
		YAML:       policyYAML,
		Version:    1,
		Source:     "node-1",
		Timestamp:  time.Now(),
	}
	mockSync.sendUpdate(update1)
	time.Sleep(200 * time.Millisecond)

	// Version should still be 2
	if enforcer.GetEnforcedVersion("test-policy") != 2 {
		t.Error("version should still be 2 (old version should be skipped)")
	}
}

func TestPolicyEnforcerGetEnforcedVersions(t *testing.T) {
	mockSync := newMockPolicySync()

	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: mockSync,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = enforcer.Stop() }()

	policyYAML := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: policy
spec:
  podSelector:
    matchLabels:
      app: test
  egress:
  - to:
      ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443`)

	// Send multiple policies
	for i := 1; i <= 3; i++ {
		update := cluster.PolicyUpdate{
			PolicyName: "policy-" + string(rune('0'+i)),
			YAML:       policyYAML,
			Version:    int64(i),
			Source:     "node-1",
			Timestamp:  time.Now(),
		}
		mockSync.sendUpdate(update)
	}

	time.Sleep(300 * time.Millisecond)

	versions := enforcer.GetEnforcedVersions()
	if len(versions) != 3 {
		t.Errorf("expected 3 enforced policies, got %d", len(versions))
	}
}

func TestPolicyEnforcerInvalidYAML(t *testing.T) {
	mockSync := newMockPolicySync()

	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: mockSync,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = enforcer.Stop() }()

	// Send invalid YAML
	update := cluster.PolicyUpdate{
		PolicyName: "invalid-policy",
		YAML:       []byte("not valid yaml: {{{"),
		Version:    1,
		Source:     "node-1",
		Timestamp:  time.Now(),
	}

	mockSync.sendUpdate(update)
	time.Sleep(200 * time.Millisecond)

	// Version should not be tracked (enforcement failed)
	if enforcer.GetEnforcedVersion("invalid-policy") != 0 {
		t.Error("invalid policy should not be enforced")
	}
}

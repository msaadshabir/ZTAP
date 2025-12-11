package cluster

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func makePolicyYAML(name, cidr string, port int) []byte {
	const tpl = "apiVersion: ztap/v1\n" +
		"kind: NetworkPolicy\n" +
		"metadata:\n" +
		"  name: %s\n" +
		"spec:\n" +
		"  podSelector:\n" +
		"    matchLabels:\n" +
		"      app: %s\n" +
		"  egress:\n" +
		"  - to:\n" +
		"      ipBlock:\n" +
		"        cidr: %s\n" +
		"    ports:\n" +
		"    - protocol: TCP\n" +
		"      port: %d\n"
	return []byte(fmt.Sprintf(tpl, name, name, cidr, port))
}

// mockElection is a simple mock for LeaderElection used in tests
type mockElection struct {
	isLeader  bool
	leader    *Node
	leaderCh  chan *Node
	clusterCh chan ClusterStateChange
}

func newMockElection(nodeID string, isLeader bool) *mockElection {
	var leader *Node
	if isLeader {
		leader = &Node{
			ID:      nodeID,
			Address: "127.0.0.1:9090",
			State:   StateHealthy,
			Role:    "leader",
		}
	}
	return &mockElection{
		isLeader:  isLeader,
		leader:    leader,
		leaderCh:  make(chan *Node, 10),
		clusterCh: make(chan ClusterStateChange, 10),
	}
}

func (m *mockElection) Start(ctx context.Context) error    { return nil }
func (m *mockElection) Stop() error                        { return nil }
func (m *mockElection) IsLeader() bool                     { return m.isLeader }
func (m *mockElection) GetLeader() *Node                   { return m.leader }
func (m *mockElection) RegisterNode(node *Node) error      { return nil }
func (m *mockElection) DeregisterNode(nodeID string) error { return nil }
func (m *mockElection) GetNodes() []*Node                  { return []*Node{m.leader} }
func (m *mockElection) GetNode(nodeID string) *Node        { return m.leader }
func (m *mockElection) Watch(ctx context.Context) <-chan ClusterStateChange {
	return m.clusterCh
}
func (m *mockElection) LeaderChanges(ctx context.Context) <-chan *Node {
	return m.leaderCh
}

func TestNewInMemoryPolicySync(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	if ps == nil {
		t.Fatal("NewInMemoryPolicySync returned nil")
	}
	if ps.nodeID != "node-1" {
		t.Errorf("expected nodeID node-1, got %s", ps.nodeID)
	}
	if ps.policies == nil {
		t.Error("policies map should be initialized")
	}
	if ps.election != election {
		t.Error("election backend not set correctly")
	}
}

func TestPolicySyncStartStop(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start should succeed
	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !ps.running {
		t.Error("policy sync should be running after Start()")
	}

	// Double start should fail
	if err := ps.Start(ctx); err == nil {
		t.Error("second Start() should have failed")
	}

	// Stop should succeed
	if err := ps.Stop(); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	if ps.running {
		t.Error("policy sync should not be running after Stop()")
	}

	// Double stop should fail
	if err := ps.Stop(); err == nil {
		t.Error("second Stop() should have failed")
	}
}

func TestSyncPolicyAsLeader(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

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

	// Sync policy should succeed
	if err := ps.SyncPolicy(ctx, "test-policy", policyYAML); err != nil {
		t.Fatalf("SyncPolicy() failed: %v", err)
	}

	// Verify policy was stored
	version, err := ps.GetPolicyVersion("test-policy")
	if err != nil {
		t.Fatalf("GetPolicyVersion() failed: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}

	// Verify policy content
	policyState, err := ps.GetPolicy("test-policy")
	if err != nil {
		t.Fatalf("GetPolicy() failed: %v", err)
	}
	if policyState == nil {
		t.Fatal("policy state should not be nil")
	}
	if policyState.Name != "test-policy" {
		t.Errorf("expected policy name test-policy, got %s", policyState.Name)
	}
	if string(policyState.YAML) != string(policyYAML) {
		t.Error("policy YAML does not match")
	}
	if policyState.Source != "node-1" {
		t.Errorf("expected source node-1, got %s", policyState.Source)
	}
}

func TestSyncPolicyAsFollower(t *testing.T) {
	election := newMockElection("node-2", false)
	election.leader = &Node{
		ID:      "node-1",
		Address: "127.0.0.1:9090",
		State:   StateHealthy,
		Role:    "leader",
	}
	ps := NewInMemoryPolicySync(election, "node-2")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	policyYAML := makePolicyYAML("test-policy", "10.1.0.0/24", 80)

	// Sync policy should fail (not leader)
	err := ps.SyncPolicy(ctx, "test-policy", policyYAML)
	if err == nil {
		t.Error("SyncPolicy() should fail when not leader")
	}
	if !strings.Contains(err.Error(), "only leader can sync policies") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSyncPolicyVersionIncrement(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	policyYAML1 := makePolicyYAML("test-policy", "10.0.0.0/24", 80)
	policyYAML2 := makePolicyYAML("test-policy", "10.0.1.0/24", 80)

	// First sync
	if err := ps.SyncPolicy(ctx, "test-policy", policyYAML1); err != nil {
		t.Fatalf("first SyncPolicy() failed: %v", err)
	}

	version1, _ := ps.GetPolicyVersion("test-policy")
	if version1 != 1 {
		t.Errorf("expected version 1, got %d", version1)
	}

	// Second sync (update)
	if err := ps.SyncPolicy(ctx, "test-policy", policyYAML2); err != nil {
		t.Fatalf("second SyncPolicy() failed: %v", err)
	}

	version2, _ := ps.GetPolicyVersion("test-policy")
	if version2 != 2 {
		t.Errorf("expected version 2, got %d", version2)
	}

	// Third sync (another update)
	if err := ps.SyncPolicy(ctx, "test-policy", policyYAML2); err != nil {
		t.Fatalf("third SyncPolicy() failed: %v", err)
	}

	version3, _ := ps.GetPolicyVersion("test-policy")
	if version3 != 3 {
		t.Errorf("expected version 3, got %d", version3)
	}
}

func TestSyncPolicyValidation(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	// Empty policy name
	err := ps.SyncPolicy(ctx, "", []byte("policy content"))
	if err == nil || !strings.Contains(err.Error(), "policy name cannot be empty") {
		t.Errorf("expected empty name error, got: %v", err)
	}

	// Empty policy YAML
	err = ps.SyncPolicy(ctx, "test-policy", []byte{})
	if err == nil || !strings.Contains(err.Error(), "policy YAML cannot be empty") {
		t.Errorf("expected empty YAML error, got: %v", err)
	}
}

func TestGetPolicyVersionNonExistent(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	version, err := ps.GetPolicyVersion("non-existent")
	if err != nil {
		t.Errorf("GetPolicyVersion() should not fail for non-existent policy: %v", err)
	}
	if version != 0 {
		t.Errorf("expected version 0 for non-existent policy, got %d", version)
	}

	// Empty name validation
	_, err = ps.GetPolicyVersion("")
	if err == nil || !strings.Contains(err.Error(), "policy name cannot be empty") {
		t.Errorf("expected empty name error, got: %v", err)
	}
}

func TestListPolicies(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	// Initially empty
	policies := ps.ListPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}

	// Add policies
	_ = ps.SyncPolicy(ctx, "policy-1", makePolicyYAML("policy-1", "10.0.1.0/24", 80))
	_ = ps.SyncPolicy(ctx, "policy-2", makePolicyYAML("policy-2", "10.0.2.0/24", 80))
	_ = ps.SyncPolicy(ctx, "policy-3", makePolicyYAML("policy-3", "10.0.3.0/24", 80))

	policies = ps.ListPolicies()
	if len(policies) != 3 {
		t.Errorf("expected 3 policies, got %d", len(policies))
	}

	// Verify all policies are present
	policyNames := make(map[string]bool)
	for _, p := range policies {
		policyNames[p.Name] = true
	}
	if !policyNames["policy-1"] || !policyNames["policy-2"] || !policyNames["policy-3"] {
		t.Error("not all policies found in list")
	}
}

func TestSubscribePolicies(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	// Subscribe to policy updates
	updateCh := ps.SubscribePolicies(ctx)

	// Sync a policy
	policyYAML := makePolicyYAML("test-policy", "10.0.4.0/24", 80)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = ps.SyncPolicy(ctx, "test-policy", policyYAML)
	}()

	// Wait for update notification
	select {
	case update := <-updateCh:
		if update.PolicyName != "test-policy" {
			t.Errorf("expected policy name test-policy, got %s", update.PolicyName)
		}
		if string(update.YAML) != string(policyYAML) {
			t.Error("policy YAML does not match")
		}
		if update.Version != 1 {
			t.Errorf("expected version 1, got %d", update.Version)
		}
		if update.Source != "node-1" {
			t.Errorf("expected source node-1, got %s", update.Source)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for policy update notification")
	}
}

func TestSubscribePoliciesMultipleSubscribers(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	// Create multiple subscribers
	sub1 := ps.SubscribePolicies(ctx)
	sub2 := ps.SubscribePolicies(ctx)
	sub3 := ps.SubscribePolicies(ctx)

	// Sync a policy
	policyYAML := makePolicyYAML("test-policy", "10.0.5.0/24", 80)
	if err := ps.SyncPolicy(ctx, "test-policy", policyYAML); err != nil {
		t.Fatalf("SyncPolicy() failed: %v", err)
	}

	// All subscribers should receive the update
	timeout := time.After(2 * time.Second)

	select {
	case update := <-sub1:
		if update.PolicyName != "test-policy" {
			t.Errorf("sub1: expected policy name test-policy, got %s", update.PolicyName)
		}
	case <-timeout:
		t.Fatal("timeout waiting for sub1 update")
	}

	select {
	case update := <-sub2:
		if update.PolicyName != "test-policy" {
			t.Errorf("sub2: expected policy name test-policy, got %s", update.PolicyName)
		}
	case <-timeout:
		t.Fatal("timeout waiting for sub2 update")
	}

	select {
	case update := <-sub3:
		if update.PolicyName != "test-policy" {
			t.Errorf("sub3: expected policy name test-policy, got %s", update.PolicyName)
		}
	case <-timeout:
		t.Fatal("timeout waiting for sub3 update")
	}
}

func TestApplyRemoteUpdate(t *testing.T) {
	election := newMockElection("node-2", false)
	ps := NewInMemoryPolicySync(election, "node-2")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	// Apply a remote update (simulating receiving from leader)
	update := PolicyUpdate{
		PolicyName: "remote-policy",
		YAML:       makePolicyYAML("remote-policy", "10.0.6.0/24", 80),
		Version:    1,
		Source:     "node-1",
		Timestamp:  time.Now(),
	}

	if err := ps.ApplyRemoteUpdate(ctx, update); err != nil {
		t.Fatalf("ApplyRemoteUpdate() failed: %v", err)
	}

	// Verify policy was stored
	version, err := ps.GetPolicyVersion("remote-policy")
	if err != nil {
		t.Fatalf("GetPolicyVersion() failed: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}

	policyState, _ := ps.GetPolicy("remote-policy")
	if policyState.Source != "node-1" {
		t.Errorf("expected source node-1, got %s", policyState.Source)
	}
}

func TestApplyRemoteUpdateVersionConflict(t *testing.T) {
	election := newMockElection("node-2", false)
	ps := NewInMemoryPolicySync(election, "node-2")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	// Apply initial update
	update1 := PolicyUpdate{
		PolicyName: "test-policy",
		YAML:       makePolicyYAML("test-policy", "10.0.7.0/24", 80),
		Version:    2,
		Source:     "node-1",
		Timestamp:  time.Now(),
	}
	_ = ps.ApplyRemoteUpdate(ctx, update1)

	// Try to apply older version (should be ignored)
	update2 := PolicyUpdate{
		PolicyName: "test-policy",
		YAML:       makePolicyYAML("test-policy", "10.0.7.0/24", 80),
		Version:    1,
		Source:     "node-1",
		Timestamp:  time.Now(),
	}
	_ = ps.ApplyRemoteUpdate(ctx, update2)

	// Should still have version 2
	version, _ := ps.GetPolicyVersion("test-policy")
	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}

	policyState, _ := ps.GetPolicy("test-policy")
	if string(policyState.YAML) != string(update1.YAML) {
		t.Error("policy was incorrectly updated with older version")
	}
}

func TestApplyRemoteUpdateValidation(t *testing.T) {
	election := newMockElection("node-2", false)
	ps := NewInMemoryPolicySync(election, "node-2")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Empty policy name
	err := ps.ApplyRemoteUpdate(ctx, PolicyUpdate{
		PolicyName: "",
		YAML:       []byte("content"),
		Version:    1,
	})
	if err == nil || !strings.Contains(err.Error(), "policy name cannot be empty") {
		t.Errorf("expected empty name error, got: %v", err)
	}

	// Empty YAML
	err = ps.ApplyRemoteUpdate(ctx, PolicyUpdate{
		PolicyName: "test",
		YAML:       []byte{},
		Version:    1,
	})
	if err == nil || !strings.Contains(err.Error(), "policy YAML cannot be empty") {
		t.Errorf("expected empty YAML error, got: %v", err)
	}
}

func TestConcurrentPolicySync(t *testing.T) {
	election := newMockElection("node-1", true)
	ps := NewInMemoryPolicySync(election, "node-1")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() { _ = ps.Stop() }()

	// Spawn multiple goroutines syncing different policies
	done := make(chan bool)
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			policyName := fmt.Sprintf("concurrent-policy-%d", id)
			policyYAML := makePolicyYAML(policyName, fmt.Sprintf("10.0.%d.0/24", id+10), 80)
			if err := ps.SyncPolicy(ctx, policyName, policyYAML); err != nil {
				t.Errorf("concurrent SyncPolicy() failed: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all policies were stored
	policies := ps.ListPolicies()
	if len(policies) != numGoroutines {
		t.Errorf("expected %d policies, got %d", numGoroutines, len(policies))
	}
}

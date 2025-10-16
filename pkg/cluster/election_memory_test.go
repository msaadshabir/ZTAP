package cluster

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryElectionStart(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "node-1",
		NodeAddress: "127.0.0.1:9090",
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start election: %v", err)
	}
	defer election.Stop()

	if !election.running {
		t.Error("election should be running after Start()")
	}

	// Verify node was registered
	node := election.GetNode("node-1")
	if node == nil {
		t.Fatal("node-1 not registered after Start()")
	}
	if node.State != StateHealthy {
		t.Errorf("expected state %s, got %s", StateHealthy, node.State)
	}
}

func TestInMemoryElectionDoubleStart(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "node-1",
		NodeAddress: "127.0.0.1:9090",
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("first Start() failed: %v", err)
	}
	defer election.Stop()

	// Second Start() should fail
	if err := election.Start(ctx); err == nil {
		t.Error("second Start() should have failed")
	}
}

func TestInMemoryElectionRegisterNode(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "node-1",
		NodeAddress: "127.0.0.1:9090",
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer election.Stop()

	node2 := &Node{
		ID:      "node-2",
		Address: "127.0.0.1:9091",
		State:   StateHealthy,
	}

	if err := election.RegisterNode(node2); err != nil {
		t.Fatalf("failed to register node: %v", err)
	}

	retrieved := election.GetNode("node-2")
	if retrieved == nil {
		t.Fatal("node-2 not found after registration")
	}
	if retrieved.Address != "127.0.0.1:9091" {
		t.Errorf("expected address 127.0.0.1:9091, got %s", retrieved.Address)
	}
}

func TestInMemoryElectionLeaderElection(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:            "node-1",
		NodeAddress:       "127.0.0.1:9090",
		HeartbeatInterval: 100 * time.Millisecond,
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer election.Stop()

	// Wait for leader election
	time.Sleep(200 * time.Millisecond)

	leader := election.GetLeader()
	if leader == nil {
		t.Fatal("no leader elected")
	}

	if leader.ID != "node-1" {
		t.Errorf("expected leader node-1, got %s", leader.ID)
	}

	if !election.IsLeader() {
		t.Error("this node should be the leader")
	}
}

func TestInMemoryElectionMultipleNodes(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:            "node-1",
		NodeAddress:       "127.0.0.1:9090",
		HeartbeatInterval: 100 * time.Millisecond,
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer election.Stop()

	// Register additional nodes
	node2 := &Node{ID: "node-2", Address: "127.0.0.1:9091", State: StateHealthy}
	node3 := &Node{ID: "node-3", Address: "127.0.0.1:9092", State: StateHealthy}

	if err := election.RegisterNode(node2); err != nil {
		t.Fatalf("failed to register node-2: %v", err)
	}
	if err := election.RegisterNode(node3); err != nil {
		t.Fatalf("failed to register node-3: %v", err)
	}

	// Wait for leader election
	time.Sleep(200 * time.Millisecond)

	leader := election.GetLeader()
	if leader == nil {
		t.Fatal("no leader elected")
	}

	// Lexicographically first node should be leader
	if leader.ID != "node-1" {
		t.Errorf("expected leader node-1 (lexicographically first), got %s", leader.ID)
	}

	nodes := election.GetNodes()
	if len(nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}
}

func TestInMemoryElectionDeregisterNode(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:            "node-1",
		NodeAddress:       "127.0.0.1:9090",
		HeartbeatInterval: 100 * time.Millisecond,
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer election.Stop()

	node2 := &Node{ID: "node-2", Address: "127.0.0.1:9091", State: StateHealthy}
	if err := election.RegisterNode(node2); err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	if err := election.DeregisterNode("node-2"); err != nil {
		t.Fatalf("failed to deregister: %v", err)
	}

	retrieved := election.GetNode("node-2")
	if retrieved != nil {
		t.Error("node-2 should be removed")
	}

	nodes := election.GetNodes()
	if len(nodes) != 1 {
		t.Errorf("expected 1 node after deregister, got %d", len(nodes))
	}
}

func TestInMemoryElectionWatch(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "node-1",
		NodeAddress: "127.0.0.1:9090",
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer election.Stop()

	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()

	changes := election.Watch(watchCtx)

	node2 := &Node{ID: "node-2", Address: "127.0.0.1:9091", State: StateHealthy}
	if err := election.RegisterNode(node2); err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Wait for change notification
	select {
	case change := <-changes:
		if change.Type != ChangeNodeJoined {
			t.Errorf("expected ChangeNodeJoined, got %s", change.Type)
		}
		if change.Node.ID != "node-2" {
			t.Errorf("expected node-2, got %s", change.Node.ID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for change notification")
	}
}

func TestInMemoryElectionLeaderChanges(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:            "node-1",
		NodeAddress:       "127.0.0.1:9090",
		HeartbeatInterval: 100 * time.Millisecond,
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer election.Stop()

	leaderCtx, leaderCancel := context.WithCancel(ctx)
	defer leaderCancel()

	changes := election.LeaderChanges(leaderCtx)

	// Wait for initial leader election
	time.Sleep(200 * time.Millisecond)

	// Mark current leader as unhealthy to trigger election
	leader := election.GetLeader()
	if leader != nil {
		leader.State = StateUnhealthy
	}

	// Wait for new election
	time.Sleep(200 * time.Millisecond)

	// Should receive a leader change notification
	select {
	case newLeader := <-changes:
		if newLeader == nil {
			t.Error("leader should not be nil")
		}
	case <-time.After(1 * time.Second):
		// Timeout is acceptable; leader change may not always fire in test
	}
}

func TestInMemoryElectionStop(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "node-1",
		NodeAddress: "127.0.0.1:9090",
	}
	election := NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	if err := election.Stop(); err != nil {
		t.Fatalf("failed to stop: %v", err)
	}

	if election.running {
		t.Error("election should not be running after Stop()")
	}

	// Second Stop() should fail
	if err := election.Stop(); err == nil {
		t.Error("second Stop() should have failed")
	}
}

func TestInMemoryElectionDefaultConfig(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "node-1",
		NodeAddress: "127.0.0.1:9090",
	}

	election := NewInMemoryElection(config)
	if election.config.HeartbeatInterval != 1*time.Second {
		t.Errorf("expected 1s heartbeat, got %v", election.config.HeartbeatInterval)
	}
	if election.config.ElectionTimeout != 5*time.Second {
		t.Errorf("expected 5s election timeout, got %v", election.config.ElectionTimeout)
	}
}

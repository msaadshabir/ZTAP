//go:build integration
// +build integration

package cluster

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.etcd.io/etcd/server/v3/embed"
)

// TestEtcdIntegration_SingleNode tests etcd election with a single node.
// This test requires a real etcd server and is marked with the "integration" build tag.
// Run with: go test -tags=integration -v ./pkg/cluster -run TestEtcdIntegration
func TestEtcdIntegration_SingleNode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start embedded etcd server
	etcdServer, cleanup := startEmbeddedEtcd(t)
	defer cleanup()

	// Create etcd config
	etcdConfig := &EtcdConfig{
		Endpoints:   []string{etcdServer.URL},
		DialTimeout: 5 * time.Second,
		KeyPrefix:   "/ztap-test",
		SessionTTL:  10 * time.Second,
	}

	// Create election config
	config := LeaderElectionConfig{
		NodeID:            "integration-node-1",
		NodeAddress:       "localhost:9090",
		HeartbeatInterval: 2 * time.Second,
		ElectionTimeout:   6 * time.Second,
	}

	// Create election
	election, err := NewEtcdElection(config, etcdConfig)
	if err != nil {
		t.Fatalf("Failed to create election: %v", err)
	}

	// Start election
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("Failed to start election: %v", err)
	}
	defer election.Stop()

	// Wait for leadership
	t.Log("Waiting for node to become leader...")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if election.IsLeader() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !election.IsLeader() {
		t.Fatal("Node did not become leader within timeout")
	}

	t.Log("Node became leader successfully")

	// Verify leader
	leader := election.GetLeader()
	if leader == nil {
		t.Fatal("GetLeader returned nil")
	}
	if leader.ID != config.NodeID {
		t.Errorf("Leader ID = %v, want %v", leader.ID, config.NodeID)
	}

	// Test node registration
	testNode := &Node{
		ID:       "test-node-2",
		Address:  "localhost:9091",
		State:    StateHealthy,
		JoinedAt: time.Now(),
		LastSeen: time.Now(),
		Metadata: make(map[string]string),
	}

	if err := election.RegisterNode(testNode); err != nil {
		t.Errorf("Failed to register node: %v", err)
	}

	// Give time for node registration to propagate
	time.Sleep(500 * time.Millisecond)

	// Verify node was registered
	node := election.GetNode(testNode.ID)
	if node == nil {
		t.Error("Registered node not found")
	} else if node.ID != testNode.ID {
		t.Errorf("Node ID = %v, want %v", node.ID, testNode.ID)
	}

	// Test deregistration
	if err := election.DeregisterNode(testNode.ID); err != nil {
		t.Errorf("Failed to deregister node: %v", err)
	}

	// Give time for deregistration to propagate
	time.Sleep(500 * time.Millisecond)

	// Verify node was removed
	node = election.GetNode(testNode.ID)
	if node != nil {
		t.Error("Node should have been deregistered")
	}
}

// TestEtcdIntegration_MultiNode tests etcd election with multiple nodes.
func TestEtcdIntegration_MultiNode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start embedded etcd server
	etcdServer, cleanup := startEmbeddedEtcd(t)
	defer cleanup()

	// Create etcd config
	etcdConfig := &EtcdConfig{
		Endpoints:   []string{etcdServer.URL},
		DialTimeout: 5 * time.Second,
		KeyPrefix:   "/ztap-test-multi",
		SessionTTL:  10 * time.Second,
	}

	// Create two nodes
	configs := []LeaderElectionConfig{
		{
			NodeID:            "node-1",
			NodeAddress:       "localhost:9090",
			HeartbeatInterval: 2 * time.Second,
			ElectionTimeout:   6 * time.Second,
		},
		{
			NodeID:            "node-2",
			NodeAddress:       "localhost:9091",
			HeartbeatInterval: 2 * time.Second,
			ElectionTimeout:   6 * time.Second,
		},
	}

	elections := make([]*EtcdElection, len(configs))
	for i, cfg := range configs {
		election, err := NewEtcdElection(cfg, etcdConfig)
		if err != nil {
			t.Fatalf("Failed to create election %d: %v", i, err)
		}
		elections[i] = election
	}

	// Start all elections
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i, election := range elections {
		if err := election.Start(ctx); err != nil {
			t.Fatalf("Failed to start election %d: %v", i, err)
		}
		defer election.Stop()
	}

	// Wait for a leader to be elected
	t.Log("Waiting for leader election...")
	deadline := time.Now().Add(10 * time.Second)
	var leaderCount int
	for time.Now().Before(deadline) {
		leaderCount = 0
		for _, election := range elections {
			if election.IsLeader() {
				leaderCount++
			}
		}
		if leaderCount == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if leaderCount != 1 {
		t.Fatalf("Expected exactly 1 leader, got %d", leaderCount)
	}

	t.Log("Leader elected successfully")

	// Verify both nodes see the same leader
	leader1 := elections[0].GetLeader()
	leader2 := elections[1].GetLeader()

	if leader1 == nil || leader2 == nil {
		t.Fatal("GetLeader returned nil")
	}

	if leader1.ID != leader2.ID {
		t.Errorf("Nodes see different leaders: %v vs %v", leader1.ID, leader2.ID)
	}

	t.Logf("All nodes agree on leader: %s", leader1.ID)
}

// TestEtcdIntegration_LeaderFailover tests leader failover when the leader stops.
func TestEtcdIntegration_LeaderFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start embedded etcd server
	etcdServer, cleanup := startEmbeddedEtcd(t)
	defer cleanup()

	// Create etcd config
	etcdConfig := &EtcdConfig{
		Endpoints:   []string{etcdServer.URL},
		DialTimeout: 5 * time.Second,
		KeyPrefix:   "/ztap-test-failover",
		SessionTTL:  5 * time.Second, // Short TTL for faster failover
	}

	// Create three nodes
	configs := []LeaderElectionConfig{
		{
			NodeID:            "node-1",
			NodeAddress:       "localhost:9090",
			HeartbeatInterval: 1 * time.Second,
			ElectionTimeout:   3 * time.Second,
		},
		{
			NodeID:            "node-2",
			NodeAddress:       "localhost:9091",
			HeartbeatInterval: 1 * time.Second,
			ElectionTimeout:   3 * time.Second,
		},
		{
			NodeID:            "node-3",
			NodeAddress:       "localhost:9092",
			HeartbeatInterval: 1 * time.Second,
			ElectionTimeout:   3 * time.Second,
		},
	}

	elections := make([]*EtcdElection, len(configs))
	for i, cfg := range configs {
		election, err := NewEtcdElection(cfg, etcdConfig)
		if err != nil {
			t.Fatalf("Failed to create election %d: %v", i, err)
		}
		elections[i] = election
	}

	// Start all elections
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i, election := range elections {
		if err := election.Start(ctx); err != nil {
			t.Fatalf("Failed to start election %d: %v", i, err)
		}
		defer election.Stop()
	}

	// Wait for initial leader
	t.Log("Waiting for initial leader...")
	time.Sleep(5 * time.Second)

	// Find the leader
	var leaderIdx int = -1
	for i, election := range elections {
		if election.IsLeader() {
			leaderIdx = i
			break
		}
	}

	if leaderIdx == -1 {
		t.Fatal("No leader elected")
	}

	initialLeader := elections[leaderIdx].GetLeader()
	t.Logf("Initial leader: %s", initialLeader.ID)

	// Stop the leader
	t.Log("Stopping current leader...")
	if err := elections[leaderIdx].Stop(); err != nil {
		t.Errorf("Error stopping leader: %v", err)
	}

	// Wait for new leader election
	t.Log("Waiting for new leader election...")
	deadline := time.Now().Add(15 * time.Second)
	var newLeaderElected bool
	for time.Now().Before(deadline) {
		for i, election := range elections {
			if i != leaderIdx && election.IsLeader() {
				newLeaderElected = true
				t.Logf("New leader elected: %s", election.GetLeader().ID)
				break
			}
		}
		if newLeaderElected {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !newLeaderElected {
		t.Fatal("New leader was not elected after old leader stopped")
	}

	t.Log("Leader failover successful")
}

// startEmbeddedEtcd starts an embedded etcd server for testing.
func startEmbeddedEtcd(t *testing.T) (*embed.Etcd, func()) {
	t.Helper()

	// Create temp directory for etcd data
	tmpDir, err := os.MkdirTemp("", "etcd-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Configure embedded etcd
	cfg := embed.NewConfig()
	cfg.Dir = tmpDir
	cfg.LogLevel = "error" // Reduce log noise
	cfg.Logger = "zap"

	// Start etcd
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to start embedded etcd: %v", err)
	}

	// Wait for etcd to be ready
	select {
	case <-e.Server.ReadyNotify():
		t.Log("Embedded etcd server is ready")
	case <-time.After(10 * time.Second):
		e.Close()
		os.RemoveAll(tmpDir)
		t.Fatal("Etcd server took too long to start")
	}

	cleanup := func() {
		e.Close()
		os.RemoveAll(tmpDir)
		t.Log("Cleaned up embedded etcd server")
	}

	return e, cleanup
}

// Helper to extract URL from embedded etcd
func (e *embed.Etcd) URL() string {
	if len(e.Clients) > 0 {
		return e.Clients[0].Addr().String()
	}
	return "http://localhost:2379"
}

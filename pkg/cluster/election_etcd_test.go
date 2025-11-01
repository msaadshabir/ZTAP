package cluster

import (
	"context"
	"testing"
	"time"
)

// TestNewEtcdElection tests creating a new etcd election instance.
func TestNewEtcdElection(t *testing.T) {
	tests := []struct {
		name        string
		config      LeaderElectionConfig
		etcdConfig  *EtcdConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config with defaults",
			config: LeaderElectionConfig{
				NodeID:      "test-node-1",
				NodeAddress: "localhost:9090",
			},
			etcdConfig: &EtcdConfig{
				Endpoints: []string{"localhost:2379"},
			},
			wantErr: false,
		},
		{
			name: "valid config with custom values",
			config: LeaderElectionConfig{
				NodeID:            "test-node-2",
				NodeAddress:       "10.0.1.2:9090",
				HeartbeatInterval: 3 * time.Second,
				ElectionTimeout:   10 * time.Second,
			},
			etcdConfig: &EtcdConfig{
				Endpoints:   []string{"localhost:2379", "localhost:2380"},
				DialTimeout: 10 * time.Second,
				KeyPrefix:   "/custom-prefix",
				SessionTTL:  30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty endpoints",
			config: LeaderElectionConfig{
				NodeID:      "test-node-3",
				NodeAddress: "localhost:9090",
			},
			etcdConfig: &EtcdConfig{
				Endpoints: []string{},
			},
			wantErr:     true,
			errContains: "endpoints cannot be empty",
		},
		{
			name: "nil etcd config",
			config: LeaderElectionConfig{
				NodeID:      "test-node-4",
				NodeAddress: "localhost:9090",
			},
			etcdConfig:  nil,
			wantErr:     true,
			errContains: "invalid etcd config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			election, err := NewEtcdElection(tt.config, tt.etcdConfig)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if election == nil {
				t.Fatal("expected non-nil election")
			}

			if election.config.NodeID != tt.config.NodeID {
				t.Errorf("NodeID = %v, want %v", election.config.NodeID, tt.config.NodeID)
			}

			// Check defaults were set
			if election.config.HeartbeatInterval == 0 {
				t.Error("HeartbeatInterval should have default value")
			}
			if election.config.ElectionTimeout == 0 {
				t.Error("ElectionTimeout should have default value")
			}
		})
	}
}

// TestEtcdConfig_Validate tests configuration validation.
func TestEtcdConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *EtcdConfig
		wantErr bool
		check   func(*EtcdConfig) error
	}{
		{
			name: "valid config",
			config: &EtcdConfig{
				Endpoints: []string{"localhost:2379"},
			},
			wantErr: false,
			check: func(c *EtcdConfig) error {
				if c.DialTimeout == 0 {
					t.Error("DialTimeout should have default value")
				}
				if c.KeyPrefix == "" {
					t.Error("KeyPrefix should have default value")
				}
				if c.LeaderElectionKey == "" {
					t.Error("LeaderElectionKey should have default value")
				}
				if c.SessionTTL == 0 {
					t.Error("SessionTTL should have default value")
				}
				return nil
			},
		},
		{
			name: "empty endpoints",
			config: &EtcdConfig{
				Endpoints: []string{},
			},
			wantErr: true,
		},
		{
			name: "nil endpoints",
			config: &EtcdConfig{
				Endpoints: nil,
			},
			wantErr: true,
		},
		{
			name: "custom values preserved",
			config: &EtcdConfig{
				Endpoints:         []string{"etcd1:2379", "etcd2:2379"},
				DialTimeout:       10 * time.Second,
				KeyPrefix:         "/custom",
				LeaderElectionKey: "/custom/leader",
				SessionTTL:        120 * time.Second,
			},
			wantErr: false,
			check: func(c *EtcdConfig) error {
				if c.DialTimeout != 10*time.Second {
					t.Errorf("DialTimeout = %v, want %v", c.DialTimeout, 10*time.Second)
				}
				if c.KeyPrefix != "/custom" {
					t.Errorf("KeyPrefix = %v, want /custom", c.KeyPrefix)
				}
				if c.LeaderElectionKey != "/custom/leader" {
					t.Errorf("LeaderElectionKey = %v, want /custom/leader", c.LeaderElectionKey)
				}
				if c.SessionTTL != 120*time.Second {
					t.Errorf("SessionTTL = %v, want %v", c.SessionTTL, 120*time.Second)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.check != nil {
				if err := tt.check(tt.config); err != nil {
					t.Fatalf("check failed: %v", err)
				}
			}
		})
	}
}

// TestEtcdElection_GetState tests getting cluster state without etcd connection.
func TestEtcdElection_GetState(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "localhost:9090",
	}
	etcdConfig := &EtcdConfig{
		Endpoints: []string{"localhost:2379"},
	}

	election, err := NewEtcdElection(config, etcdConfig)
	if err != nil {
		t.Fatalf("failed to create election: %v", err)
	}

	// Add some nodes to state manually
	election.mu.Lock()
	election.currentState.Nodes["node1"] = &Node{
		ID:       "node1",
		Address:  "10.0.1.1:9090",
		State:    StateHealthy,
		JoinedAt: time.Now(),
	}
	election.currentState.Nodes["node2"] = &Node{
		ID:       "node2",
		Address:  "10.0.1.2:9090",
		State:    StateHealthy,
		JoinedAt: time.Now(),
	}
	election.currentState.Leader = election.currentState.Nodes["node1"]
	election.currentState.Version = 5
	election.mu.Unlock()

	// Get state
	state := election.GetState()

	// Verify state
	if len(state.Nodes) != 2 {
		t.Errorf("Nodes count = %d, want 2", len(state.Nodes))
	}

	if state.Leader == nil {
		t.Fatal("Leader is nil")
	}
	if state.Leader.ID != "node1" {
		t.Errorf("Leader ID = %v, want node1", state.Leader.ID)
	}

	if state.Version != 5 {
		t.Errorf("Version = %d, want 5", state.Version)
	}

	// Verify state is a copy (mutation doesn't affect original)
	state.Nodes["node1"].State = StateStopped
	election.mu.RLock()
	if election.currentState.Nodes["node1"].State == StateStopped {
		t.Error("State mutation affected original")
	}
	election.mu.RUnlock()
}

// TestEtcdElection_GetNodes tests getting all nodes.
func TestEtcdElection_GetNodes(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "localhost:9090",
	}
	etcdConfig := &EtcdConfig{
		Endpoints: []string{"localhost:2379"},
	}

	election, err := NewEtcdElection(config, etcdConfig)
	if err != nil {
		t.Fatalf("failed to create election: %v", err)
	}

	// Initially empty
	nodes := election.GetNodes()
	if len(nodes) != 0 {
		t.Errorf("Initial nodes count = %d, want 0", len(nodes))
	}

	// Add nodes
	election.mu.Lock()
	election.currentState.Nodes["node1"] = &Node{ID: "node1", Address: "10.0.1.1:9090"}
	election.currentState.Nodes["node2"] = &Node{ID: "node2", Address: "10.0.1.2:9090"}
	election.currentState.Nodes["node3"] = &Node{ID: "node3", Address: "10.0.1.3:9090"}
	election.mu.Unlock()

	nodes = election.GetNodes()
	if len(nodes) != 3 {
		t.Errorf("Nodes count = %d, want 3", len(nodes))
	}

	// Verify returned nodes are copies
	nodes[0].State = StateStopped
	election.mu.RLock()
	if election.currentState.Nodes["node1"].State == StateStopped {
		t.Error("Node mutation affected original")
	}
	election.mu.RUnlock()
}

// TestEtcdElection_GetNode tests getting a specific node.
func TestEtcdElection_GetNode(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "localhost:9090",
	}
	etcdConfig := &EtcdConfig{
		Endpoints: []string{"localhost:2379"},
	}

	election, err := NewEtcdElection(config, etcdConfig)
	if err != nil {
		t.Fatalf("failed to create election: %v", err)
	}

	// Add a node
	election.mu.Lock()
	election.currentState.Nodes["node1"] = &Node{
		ID:      "node1",
		Address: "10.0.1.1:9090",
		State:   StateHealthy,
	}
	election.mu.Unlock()

	// Get existing node
	node := election.GetNode("node1")
	if node == nil {
		t.Fatal("GetNode returned nil for existing node")
	}
	if node.ID != "node1" {
		t.Errorf("Node ID = %v, want node1", node.ID)
	}

	// Get non-existent node
	node = election.GetNode("node999")
	if node != nil {
		t.Error("GetNode should return nil for non-existent node")
	}
}

// TestEtcdElection_IsLeader tests leadership status.
func TestEtcdElection_IsLeader(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "localhost:9090",
	}
	etcdConfig := &EtcdConfig{
		Endpoints: []string{"localhost:2379"},
	}

	election, err := NewEtcdElection(config, etcdConfig)
	if err != nil {
		t.Fatalf("failed to create election: %v", err)
	}

	// Initially not leader
	if election.IsLeader() {
		t.Error("Node should not be leader initially")
	}

	// Set as leader
	election.mu.Lock()
	election.isLeader = true
	election.mu.Unlock()

	if !election.IsLeader() {
		t.Error("Node should be leader after setting flag")
	}

	// Unset leader
	election.mu.Lock()
	election.isLeader = false
	election.mu.Unlock()

	if election.IsLeader() {
		t.Error("Node should not be leader after unsetting flag")
	}
}

// TestEtcdElection_WatchAndLeaderChanges tests watch channels.
func TestEtcdElection_WatchAndLeaderChanges(t *testing.T) {
	config := LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "localhost:9090",
	}
	etcdConfig := &EtcdConfig{
		Endpoints: []string{"localhost:2379"},
	}

	election, err := NewEtcdElection(config, etcdConfig)
	if err != nil {
		t.Fatalf("failed to create election: %v", err)
	}

	// Create watch channels
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stateChangeCh := election.Watch(ctx)
	leaderChangeCh := election.LeaderChanges(ctx)

	// Verify channels are created
	if stateChangeCh == nil {
		t.Fatal("Watch returned nil channel")
	}
	if leaderChangeCh == nil {
		t.Fatal("LeaderChanges returned nil channel")
	}

	// Trigger notifications
	testNode := &Node{
		ID:       "node1",
		Address:  "10.0.1.1:9090",
		State:    StateHealthy,
		JoinedAt: time.Now(),
		LastSeen: time.Now(),
	}

	// Send state change
	go election.notifyStateChange(ClusterStateChange{
		Type:      ChangeNodeJoined,
		Node:      testNode,
		Timestamp: time.Now(),
	})

	// Send leader change
	go election.notifyLeaderChange(testNode)

	// Receive notifications
	select {
	case change := <-stateChangeCh:
		if change.Type != ChangeNodeJoined {
			t.Errorf("Change type = %v, want %v", change.Type, ChangeNodeJoined)
		}
		if change.Node.ID != "node1" {
			t.Errorf("Node ID = %v, want node1", change.Node.ID)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for state change")
	}

	select {
	case leader := <-leaderChangeCh:
		if leader.ID != "node1" {
			t.Errorf("Leader ID = %v, want node1", leader.ID)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for leader change")
	}

	// Verify channels close when context is cancelled
	cancel()
	time.Sleep(100 * time.Millisecond)

	select {
	case _, ok := <-stateChangeCh:
		if ok {
			t.Error("State change channel should be closed")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("State change channel not closed after context cancellation")
	}

	select {
	case _, ok := <-leaderChangeCh:
		if ok {
			t.Error("Leader change channel should be closed")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Leader change channel not closed after context cancellation")
	}
}

// TestDefaultEtcdConfig tests the default configuration.
func TestDefaultEtcdConfig(t *testing.T) {
	config := DefaultEtcdConfig()

	if len(config.Endpoints) != 1 || config.Endpoints[0] != "localhost:2379" {
		t.Errorf("Endpoints = %v, want [localhost:2379]", config.Endpoints)
	}

	if config.DialTimeout != 5*time.Second {
		t.Errorf("DialTimeout = %v, want 5s", config.DialTimeout)
	}

	if config.KeyPrefix != "/ztap" {
		t.Errorf("KeyPrefix = %v, want /ztap", config.KeyPrefix)
	}

	if config.SessionTTL != 60*time.Second {
		t.Errorf("SessionTTL = %v, want 60s", config.SessionTTL)
	}
}

// Helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

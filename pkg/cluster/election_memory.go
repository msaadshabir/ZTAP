package cluster

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// InMemoryElection implements a simple in-memory leader election for development and testing.
// It is NOT suitable for production distributed deployments; use etcd or Raft for production.
type InMemoryElection struct {
	config       LeaderElectionConfig
	mu           sync.RWMutex
	state        ClusterState
	leader       *Node
	isLeader     bool
	running      bool
	stopCh       chan struct{}
	nodeUpdates  []chan ClusterStateChange
	leaderChs    []chan *Node
	ticker       *time.Ticker
	lastElection time.Time
}

// NewInMemoryElection creates a new in-memory leader election backend.
func NewInMemoryElection(config LeaderElectionConfig) *InMemoryElection {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 1 * time.Second
	}
	if config.ElectionTimeout == 0 {
		config.ElectionTimeout = 5 * time.Second
	}
	if config.InitialLeadership == 0 {
		config.InitialLeadership = 3 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	return &InMemoryElection{
		config:       config,
		state:        ClusterState{Nodes: make(map[string]*Node)},
		stopCh:       make(chan struct{}),
		nodeUpdates:  make([]chan ClusterStateChange, 0),
		leaderChs:    make([]chan *Node, 0),
		lastElection: time.Now(),
	}
}

// Start begins the leader election process.
func (e *InMemoryElection) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("leader election already running")
	}
	e.running = true

	// Register this node
	thisNode := &Node{
		ID:       e.config.NodeID,
		Address:  e.config.NodeAddress,
		State:    StateHealthy,
		JoinedAt: time.Now(),
		LastSeen: time.Now(),
		Metadata: make(map[string]string),
	}
	e.state.Nodes[thisNode.ID] = thisNode
	e.mu.Unlock()

	e.ticker = time.NewTicker(e.config.HeartbeatInterval)

	go e.runElectionLoop(ctx)
	log.Printf("In-memory leader election started for node %s", e.config.NodeID)

	return nil
}

// Stop gracefully shuts down the leader election.
func (e *InMemoryElection) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return fmt.Errorf("leader election not running")
	}
	e.running = false

	if e.ticker != nil {
		e.ticker.Stop()
	}

	close(e.stopCh)

	// Close all watcher channels
	for _, ch := range e.nodeUpdates {
		close(ch)
	}
	for _, ch := range e.leaderChs {
		close(ch)
	}
	e.nodeUpdates = make([]chan ClusterStateChange, 0)
	e.leaderChs = make([]chan *Node, 0)

	e.mu.Unlock()
	return nil
}

// IsLeader returns true if this node is the current leader.
func (e *InMemoryElection) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isLeader
}

// GetLeader returns the current leader node, or nil if no leader is elected.
func (e *InMemoryElection) GetLeader() *Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leader
}

// RegisterNode adds or updates a node in the cluster.
func (e *InMemoryElection) RegisterNode(node *Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if node.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}

	node.LastSeen = time.Now()
	e.state.Nodes[node.ID] = node
	e.state.Version++

	change := ClusterStateChange{
		Type:      ChangeNodeJoined,
		Node:      node,
		Timestamp: time.Now(),
	}
	e.broadcastChange(change)

	return nil
}

// DeregisterNode removes a node from the cluster.
func (e *InMemoryElection) DeregisterNode(nodeID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	node, exists := e.state.Nodes[nodeID]
	if !exists {
		return fmt.Errorf("node %s not found", nodeID)
	}

	delete(e.state.Nodes, nodeID)
	e.state.Version++

	change := ClusterStateChange{
		Type:      ChangeNodeLeft,
		Node:      node,
		Timestamp: time.Now(),
	}
	e.broadcastChange(change)

	// If leader left, trigger new election
	if e.leader != nil && e.leader.ID == nodeID {
		e.triggerElection()
	}

	return nil
}

// GetNodes returns all known nodes in the cluster.
func (e *InMemoryElection) GetNodes() []*Node {
	e.mu.RLock()
	defer e.mu.RUnlock()

	nodes := make([]*Node, 0, len(e.state.Nodes))
	for _, node := range e.state.Nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetNode returns a specific node by ID, or nil if not found.
func (e *InMemoryElection) GetNode(nodeID string) *Node {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.state.Nodes[nodeID]
}

// Watch returns a channel that receives notifications on cluster state changes.
func (e *InMemoryElection) Watch(ctx context.Context) <-chan ClusterStateChange {
	ch := make(chan ClusterStateChange, 10)

	go func() {
		<-ctx.Done()
		e.mu.Lock()
		// Remove this channel from watchers
		for i, watcher := range e.nodeUpdates {
			if watcher == ch {
				e.nodeUpdates = append(e.nodeUpdates[:i], e.nodeUpdates[i+1:]...)
				break
			}
		}
		e.mu.Unlock()
		// Close channel after removal to avoid double-close
		select {
		case <-ch:
			// Channel already closed
		default:
			close(ch)
		}
	}()

	e.mu.Lock()
	e.nodeUpdates = append(e.nodeUpdates, ch)
	e.mu.Unlock()

	return ch
}

// LeaderChanges returns a channel that receives notifications when leadership changes.
func (e *InMemoryElection) LeaderChanges(ctx context.Context) <-chan *Node {
	ch := make(chan *Node, 10)

	go func() {
		<-ctx.Done()
		e.mu.Lock()
		// Remove this channel from watchers
		for i, watcher := range e.leaderChs {
			if watcher == ch {
				e.leaderChs = append(e.leaderChs[:i], e.leaderChs[i+1:]...)
				break
			}
		}
		e.mu.Unlock()
		// Close channel after removal to avoid double-close
		select {
		case <-ch:
			// Channel already closed
		default:
			close(ch)
		}
	}()

	e.mu.Lock()
	e.leaderChs = append(e.leaderChs, ch)
	e.mu.Unlock()

	return ch
}

// runElectionLoop manages periodic leader election.
func (e *InMemoryElection) runElectionLoop(ctx context.Context) {
	for {
		select {
		case <-e.stopCh:
			return
		case <-ctx.Done():
			return
		case <-e.ticker.C:
			e.checkAndElect()
		}
	}
}

// checkAndElect periodically checks and performs leader election if needed.
func (e *InMemoryElection) checkAndElect() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If no leader or leader is unhealthy, trigger election
	if e.leader == nil || e.leader.State != StateHealthy {
		e.triggerElection()
		return
	}

	// Check for leader timeout
	if time.Since(e.leader.LastSeen) > e.config.ElectionTimeout {
		log.Printf("Leader %s timed out; triggering election", e.leader.ID)
		e.triggerElection()
	}
}

// triggerElection elects a new leader (requires holding mu lock).
func (e *InMemoryElection) triggerElection() {
	// Simple election: pick lexicographically first healthy node
	var newLeader *Node
	for _, node := range e.state.Nodes {
		if node.State == StateHealthy {
			if newLeader == nil || node.ID < newLeader.ID {
				newLeader = node
			}
		}
	}

	oldLeader := e.leader
	e.leader = newLeader
	if e.leader != nil {
		e.leader.Role = "leader"
		e.isLeader = (e.leader.ID == e.config.NodeID)
		e.state.Leader = e.leader
		e.state.Version++
		e.lastElection = time.Now()

		log.Printf("New leader elected: %s (this node leader=%v)", e.leader.ID, e.isLeader)

		// Notify leader change watchers
		e.broadcastLeaderChange(e.leader)

		// Mark old leader as follower if it still exists
		if oldLeader != nil && oldLeader.ID != e.leader.ID {
			oldLeader.Role = "follower"
		}
	}
}

// broadcastChange sends a change notification to all watchers (requires holding mu lock).
func (e *InMemoryElection) broadcastChange(change ClusterStateChange) {
	for _, ch := range e.nodeUpdates {
		select {
		case ch <- change:
		default:
			log.Printf("Warning: node change channel full, dropping event")
		}
	}
}

// broadcastLeaderChange sends a leader change notification to all watchers (requires holding mu lock).
func (e *InMemoryElection) broadcastLeaderChange(leader *Node) {
	for _, ch := range e.leaderChs {
		select {
		case ch <- leader:
		default:
			log.Printf("Warning: leader change channel full, dropping event")
		}
	}
}

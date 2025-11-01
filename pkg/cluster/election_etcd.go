package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// EtcdElection implements leader election using etcd for production deployments.
type EtcdElection struct {
	config       LeaderElectionConfig
	etcdConfig   *EtcdConfig
	client       *clientv3.Client
	session      *concurrency.Session
	election     *concurrency.Election
	mu           sync.RWMutex
	isLeader     bool
	currentState ClusterState
	running      bool
	stopCh       chan struct{}
	nodeUpdates  []chan ClusterStateChange
	leaderChs    []chan *Node
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewEtcdElection creates a new etcd-based leader election backend.
func NewEtcdElection(config LeaderElectionConfig, etcdConfig *EtcdConfig) (*EtcdElection, error) {
	// Check for nil etcd config
	if etcdConfig == nil {
		return nil, fmt.Errorf("invalid etcd config: etcd config cannot be nil")
	}

	// Validate etcd config
	if err := etcdConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid etcd config: %w", err)
	}

	// Set defaults for leader election config
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 5 * time.Second
	}
	if config.ElectionTimeout == 0 {
		config.ElectionTimeout = 15 * time.Second
	}

	return &EtcdElection{
		config:       config,
		etcdConfig:   etcdConfig,
		currentState: ClusterState{Nodes: make(map[string]*Node)},
		stopCh:       make(chan struct{}),
		nodeUpdates:  make([]chan ClusterStateChange, 0),
		leaderChs:    make([]chan *Node, 0),
	}, nil
}

// Start begins the leader election process.
func (e *EtcdElection) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("etcd election already running")
	}
	e.running = true
	e.mu.Unlock()

	// Create etcd client
	client, err := e.etcdConfig.NewEtcdClient()
	if err != nil {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
		return fmt.Errorf("failed to create etcd client: %w", err)
	}
	e.client = client

	// Create context for this election
	e.ctx, e.cancel = context.WithCancel(ctx)

	// Create session with TTL
	session, err := concurrency.NewSession(
		e.client,
		concurrency.WithTTL(int(e.etcdConfig.SessionTTL.Seconds())),
		concurrency.WithContext(e.ctx),
	)
	if err != nil {
		e.client.Close()
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
		return fmt.Errorf("failed to create etcd session: %w", err)
	}
	e.session = session

	// Create election object
	e.election = concurrency.NewElection(session, e.etcdConfig.LeaderElectionKey)

	// Register this node in cluster state
	if err := e.registerNode(); err != nil {
		log.Printf("Warning: failed to register node: %v", err)
	}

	// Start leader election in background
	go e.runElectionLoop()

	// Start node monitoring
	go e.monitorNodes()

	log.Printf("Etcd leader election started for node %s", e.config.NodeID)
	return nil
}

// Stop gracefully shuts down the leader election.
func (e *EtcdElection) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return fmt.Errorf("etcd election not running")
	}
	e.running = false
	e.mu.Unlock()

	// Cancel context
	if e.cancel != nil {
		e.cancel()
	}

	// Signal stop
	close(e.stopCh)

	// Resign if leader
	if e.isLeader && e.election != nil {
		if err := e.election.Resign(context.Background()); err != nil {
			log.Printf("Error resigning leadership: %v", err)
		}
	}

	// Close session
	if e.session != nil {
		if err := e.session.Close(); err != nil {
			log.Printf("Error closing etcd session: %v", err)
		}
	}

	// Deregister node
	if err := e.deregisterNode(); err != nil {
		log.Printf("Error deregistering node: %v", err)
	}

	// Close client
	if e.client != nil {
		if err := e.client.Close(); err != nil {
			log.Printf("Error closing etcd client: %v", err)
		}
	}

	log.Printf("Etcd leader election stopped for node %s", e.config.NodeID)
	return nil
}

// IsLeader returns true if this node is the current leader.
func (e *EtcdElection) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isLeader
}

// GetLeader returns the current leader node.
func (e *EtcdElection) GetLeader() *Node {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.currentState.Leader != nil {
		return e.currentState.Leader
	}

	// Query etcd for current leader
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := e.election.Leader(ctx)
	if err != nil {
		if err == concurrency.ErrElectionNoLeader {
			return nil
		}
		log.Printf("Error getting leader from etcd: %v", err)
		return nil
	}

	// Parse leader node from value
	var node Node
	if err := json.Unmarshal(resp.Kvs[0].Value, &node); err != nil {
		log.Printf("Error parsing leader node: %v", err)
		return nil
	}

	return &node
}

// GetState returns the current cluster state.
func (e *EtcdElection) GetState() ClusterState {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Create a copy of the state
	stateCopy := ClusterState{
		ID:      e.currentState.ID,
		Leader:  e.currentState.Leader,
		Nodes:   make(map[string]*Node),
		Version: e.currentState.Version,
	}

	for k, v := range e.currentState.Nodes {
		nodeCopy := *v
		stateCopy.Nodes[k] = &nodeCopy
	}

	return stateCopy
}

// RegisterNode adds or updates a node in the cluster.
func (e *EtcdElection) RegisterNode(node *Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	nodeData, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("failed to marshal node: %w", err)
	}

	key := fmt.Sprintf("%s/nodes/%s", e.etcdConfig.KeyPrefix, node.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Put with lease so node auto-expires
	lease, err := e.client.Grant(ctx, int64(e.etcdConfig.SessionTTL.Seconds()))
	if err != nil {
		return fmt.Errorf("failed to create lease: %w", err)
	}

	_, err = e.client.Put(ctx, key, string(nodeData), clientv3.WithLease(lease.ID))
	if err != nil {
		return fmt.Errorf("failed to register node: %w", err)
	}

	return nil
}

// DeregisterNode removes a node from the cluster.
func (e *EtcdElection) DeregisterNode(nodeID string) error {
	key := fmt.Sprintf("%s/nodes/%s", e.etcdConfig.KeyPrefix, nodeID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := e.client.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to deregister node: %w", err)
	}

	return nil
}

// GetNodes returns all known nodes in the cluster.
func (e *EtcdElection) GetNodes() []*Node {
	e.mu.RLock()
	defer e.mu.RUnlock()

	nodes := make([]*Node, 0, len(e.currentState.Nodes))
	for _, node := range e.currentState.Nodes {
		nodeCopy := *node
		nodes = append(nodes, &nodeCopy)
	}

	return nodes
}

// GetNode returns a specific node by ID, or nil if not found.
func (e *EtcdElection) GetNode(nodeID string) *Node {
	e.mu.RLock()
	defer e.mu.RUnlock()

	node := e.currentState.Nodes[nodeID]
	if node == nil {
		return nil
	}

	nodeCopy := *node
	return &nodeCopy
}

// Watch returns a channel that receives notifications on cluster state changes.
func (e *EtcdElection) Watch(ctx context.Context) <-chan ClusterStateChange {
	ch := make(chan ClusterStateChange, 10)

	e.mu.Lock()
	e.nodeUpdates = append(e.nodeUpdates, ch)
	e.mu.Unlock()

	// Close channel when context is cancelled
	go func() {
		<-ctx.Done()
		e.mu.Lock()
		// Remove channel from list
		for i, c := range e.nodeUpdates {
			if c == ch {
				e.nodeUpdates = append(e.nodeUpdates[:i], e.nodeUpdates[i+1:]...)
				break
			}
		}
		e.mu.Unlock()
		close(ch)
	}()

	return ch
}

// LeaderChanges returns a channel that receives notifications when leadership changes.
func (e *EtcdElection) LeaderChanges(ctx context.Context) <-chan *Node {
	ch := make(chan *Node, 10)

	e.mu.Lock()
	e.leaderChs = append(e.leaderChs, ch)
	e.mu.Unlock()

	// Close channel when context is cancelled
	go func() {
		<-ctx.Done()
		e.mu.Lock()
		// Remove channel from list
		for i, c := range e.leaderChs {
			if c == ch {
				e.leaderChs = append(e.leaderChs[:i], e.leaderChs[i+1:]...)
				break
			}
		}
		e.mu.Unlock()
		close(ch)
	}()

	return ch
}

// WatchLeader is a legacy method - use LeaderChanges instead.
// Deprecated: Use LeaderChanges(ctx) instead.
func (e *EtcdElection) WatchLeader() <-chan *Node {
	ch := make(chan *Node, 10)
	e.mu.Lock()
	e.leaderChs = append(e.leaderChs, ch)
	e.mu.Unlock()
	return ch
}

// WatchClusterState is a legacy method - use Watch instead.
// Deprecated: Use Watch(ctx) instead.
func (e *EtcdElection) WatchClusterState() <-chan ClusterStateChange {
	ch := make(chan ClusterStateChange, 10)
	e.mu.Lock()
	e.nodeUpdates = append(e.nodeUpdates, ch)
	e.mu.Unlock()
	return ch
}

// runElectionLoop runs the leader election campaign.
func (e *EtcdElection) runElectionLoop() {
	// Prepare node data for campaign
	thisNode := &Node{
		ID:       e.config.NodeID,
		Address:  e.config.NodeAddress,
		State:    StateHealthy,
		JoinedAt: time.Now(),
		LastSeen: time.Now(),
		Metadata: make(map[string]string),
	}

	nodeData, err := json.Marshal(thisNode)
	if err != nil {
		log.Printf("Error marshaling node data: %v", err)
		return
	}

	for {
		select {
		case <-e.stopCh:
			return
		case <-e.ctx.Done():
			return
		default:
		}

		// Campaign to become leader
		log.Printf("Node %s campaigning for leadership", e.config.NodeID)
		if err := e.election.Campaign(e.ctx, string(nodeData)); err != nil {
			if err == context.Canceled {
				return
			}
			log.Printf("Campaign error: %v, retrying...", err)
			time.Sleep(e.config.HeartbeatInterval)
			continue
		}

		// We became leader
		e.mu.Lock()
		e.isLeader = true
		e.currentState.Leader = thisNode
		e.mu.Unlock()

		log.Printf("Node %s became leader", e.config.NodeID)
		e.notifyLeaderChange(thisNode)

		// Keep the leadership by keeping the session alive
		// The session will automatically renew its lease
		select {
		case <-e.session.Done():
			log.Printf("Session expired, node %s lost leadership", e.config.NodeID)
			e.mu.Lock()
			e.isLeader = false
			e.currentState.Leader = nil
			e.mu.Unlock()
			e.notifyLeaderChange(nil)
		case <-e.stopCh:
			return
		case <-e.ctx.Done():
			return
		}
	}
}

// registerNode registers this node in etcd.
func (e *EtcdElection) registerNode() error {
	node := &Node{
		ID:       e.config.NodeID,
		Address:  e.config.NodeAddress,
		State:    StateHealthy,
		JoinedAt: time.Now(),
		LastSeen: time.Now(),
		Metadata: make(map[string]string),
	}

	nodeData, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("failed to marshal node: %w", err)
	}

	key := fmt.Sprintf("%s/nodes/%s", e.etcdConfig.KeyPrefix, e.config.NodeID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Put with lease so node auto-expires if we crash
	lease, err := e.client.Grant(ctx, int64(e.etcdConfig.SessionTTL.Seconds()))
	if err != nil {
		return fmt.Errorf("failed to create lease: %w", err)
	}

	_, err = e.client.Put(ctx, key, string(nodeData), clientv3.WithLease(lease.ID))
	if err != nil {
		return fmt.Errorf("failed to register node: %w", err)
	}

	// Update local state
	e.mu.Lock()
	e.currentState.Nodes[e.config.NodeID] = node
	e.mu.Unlock()

	return nil
}

// deregisterNode removes this node from etcd.
func (e *EtcdElection) deregisterNode() error {
	key := fmt.Sprintf("%s/nodes/%s", e.etcdConfig.KeyPrefix, e.config.NodeID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := e.client.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to deregister node: %w", err)
	}

	// Update local state
	e.mu.Lock()
	delete(e.currentState.Nodes, e.config.NodeID)
	e.mu.Unlock()

	return nil
}

// monitorNodes watches for node changes in etcd.
func (e *EtcdElection) monitorNodes() {
	prefix := fmt.Sprintf("%s/nodes/", e.etcdConfig.KeyPrefix)
	watchChan := e.client.Watch(e.ctx, prefix, clientv3.WithPrefix())

	for {
		select {
		case <-e.stopCh:
			return
		case <-e.ctx.Done():
			return
		case wresp := <-watchChan:
			if wresp.Err() != nil {
				log.Printf("Watch error: %v", wresp.Err())
				continue
			}

			for _, ev := range wresp.Events {
				e.handleNodeEvent(ev)
			}
		}
	}
}

// handleNodeEvent processes node change events.
func (e *EtcdElection) handleNodeEvent(ev *clientv3.Event) {
	var node Node
	if ev.Type == clientv3.EventTypePut {
		if err := json.Unmarshal(ev.Kv.Value, &node); err != nil {
			log.Printf("Error unmarshaling node: %v", err)
			return
		}

		e.mu.Lock()
		oldNode := e.currentState.Nodes[node.ID]
		e.currentState.Nodes[node.ID] = &node
		e.currentState.Version++
		e.mu.Unlock()

		changeType := ChangeNodeJoined
		if oldNode != nil {
			changeType = ChangeNodeHealthy
		}

		e.notifyStateChange(ClusterStateChange{
			Type:      changeType,
			Node:      &node,
			Timestamp: time.Now(),
		})
	} else if ev.Type == clientv3.EventTypeDelete {
		// Extract node ID from key
		key := string(ev.Kv.Key)
		prefix := fmt.Sprintf("%s/nodes/", e.etcdConfig.KeyPrefix)
		nodeID := key[len(prefix):]

		e.mu.Lock()
		oldNode := e.currentState.Nodes[nodeID]
		delete(e.currentState.Nodes, nodeID)
		e.currentState.Version++
		e.mu.Unlock()

		if oldNode != nil {
			e.notifyStateChange(ClusterStateChange{
				Type:      ChangeNodeLeft,
				Node:      oldNode,
				Timestamp: time.Now(),
			})
		}
	}
}

// notifyLeaderChange sends leader change notifications to all watchers.
func (e *EtcdElection) notifyLeaderChange(leader *Node) {
	e.mu.RLock()
	channels := make([]chan *Node, len(e.leaderChs))
	copy(channels, e.leaderChs)
	e.mu.RUnlock()

	for _, ch := range channels {
		select {
		case ch <- leader:
		default:
			// Channel full, skip
		}
	}
}

// notifyStateChange sends state change notifications to all watchers.
func (e *EtcdElection) notifyStateChange(change ClusterStateChange) {
	e.mu.RLock()
	channels := make([]chan ClusterStateChange, len(e.nodeUpdates))
	copy(channels, e.nodeUpdates)
	e.mu.RUnlock()

	for _, ch := range channels {
		select {
		case ch <- change:
		default:
			// Channel full, skip
		}
	}
}

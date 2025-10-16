package cluster

import (
	"context"
	"time"
)

// NodeState represents the operational state of a node in the cluster.
type NodeState string

const (
	StateHealthy   NodeState = "healthy"
	StateUnhealthy NodeState = "unhealthy"
	StateStopped   NodeState = "stopped"
)

// Node represents a cluster member.
type Node struct {
	ID       string            `json:"id"`        // Unique node identifier (e.g., hostname)
	Address  string            `json:"address"`   // Network address (e.g., 127.0.0.1:9090)
	State    NodeState         `json:"state"`     // Current operational state
	Role     string            `json:"role"`      // Role: "leader" or "follower"
	JoinedAt time.Time         `json:"joined_at"` // Cluster join timestamp
	LastSeen time.Time         `json:"last_seen"` // Last health check timestamp
	Metadata map[string]string `json:"metadata"`  // Custom metadata (e.g., version, capabilities)
}

// ClusterState represents the current state of the cluster.
type ClusterState struct {
	ID      string           `json:"id"`      // Cluster identifier
	Leader  *Node            `json:"leader"`  // Current leader node
	Nodes   map[string]*Node `json:"nodes"`   // All nodes keyed by ID
	Version int64            `json:"version"` // State version for ordering updates
}

// LeaderElectionConfig holds configuration for leader election.
type LeaderElectionConfig struct {
	NodeID            string        // Identifier for this node
	NodeAddress       string        // Network address of this node
	HeartbeatInterval time.Duration // Interval for heartbeats (default: 1s)
	ElectionTimeout   time.Duration // Timeout before triggering new election (default: 5s)
	InitialLeadership time.Duration // Time before initial node can become leader (default: 3s)
	MaxRetries        int           // Max retries for operations (default: 3)
}

// LeaderElection defines the interface for leader election backends.
type LeaderElection interface {
	// Start begins the leader election process. Returns an error if already started.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the leader election.
	Stop() error

	// IsLeader returns true if this node is the current leader.
	IsLeader() bool

	// GetLeader returns the current leader node, or nil if no leader is elected.
	GetLeader() *Node

	// RegisterNode adds or updates a node in the cluster.
	RegisterNode(node *Node) error

	// DeregisterNode removes a node from the cluster.
	DeregisterNode(nodeID string) error

	// GetNodes returns all known nodes in the cluster.
	GetNodes() []*Node

	// GetNode returns a specific node by ID, or nil if not found.
	GetNode(nodeID string) *Node

	// Watch returns a channel that receives notifications on cluster state changes.
	// The channel is closed when the context is cancelled.
	Watch(ctx context.Context) <-chan ClusterStateChange

	// LeaderChanges returns a channel that receives notifications when leadership changes.
	// The channel is closed when the context is cancelled.
	LeaderChanges(ctx context.Context) <-chan *Node
}

// ClusterStateChange represents a change in the cluster state.
type ClusterStateChange struct {
	Type      ChangeType // Type of change
	Node      *Node      // Node involved (may be nil for leader changes)
	Timestamp time.Time  // When the change occurred
	Error     error      // Error if change failed (may be nil)
}

// ChangeType defines the type of cluster state change.
type ChangeType string

const (
	ChangeNodeJoined    ChangeType = "node_joined"
	ChangeNodeLeft      ChangeType = "node_left"
	ChangeNodeHealthy   ChangeType = "node_healthy"
	ChangeNodeUnwell    ChangeType = "node_unwell"
	ChangeLeaderElected ChangeType = "leader_elected"
)

// PolicySync defines the interface for distributed policy synchronization.
type PolicySync interface {
	// SyncPolicy broadcasts a policy update to all nodes in the cluster.
	SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error

	// GetPolicyVersion returns the current version of a policy across the cluster.
	GetPolicyVersion(policyName string) (int64, error)

	// SubscribePolicies returns a channel for policy update notifications.
	SubscribePolicies(ctx context.Context) <-chan PolicyUpdate
}

// PolicyUpdate represents a distributed policy change.
type PolicyUpdate struct {
	PolicyName string    // Name of the policy
	YAML       []byte    // Policy YAML content
	Version    int64     // Version number for ordering
	Source     string    // Node ID that initiated the update
	Timestamp  time.Time // When the update occurred
}

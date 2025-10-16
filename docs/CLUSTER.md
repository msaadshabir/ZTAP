# Distributed Cluster Architecture

ZTAP supports multi-node cluster coordination for distributed policy synchronization and high-availability deployments.

## Overview

The cluster package provides:

- **Leader Election**: Automatic election of a cluster leader using simple consensus
- **Node Registration**: Track and manage cluster members
- **Health Monitoring**: Periodic heartbeats and node state tracking
- **Event Notifications**: Watch for cluster state changes and leader elections
- **Pluggable Backends**: Interface-based design supports multiple backends (in-memory, etcd, Raft)

## Architecture

```
Node 1                Node 2                Node 3
(Leader)             (Follower)            (Follower)
    |                    |                    |
    +-------- Heartbeat --------+
    |                    |                    |
    +-- Cluster State --+-- Cluster State ---+
    |                    |                    |
    +--- Leader Election Monitoring ---+
```

### Components

- **LeaderElection**: Interface defining the leader election contract
- **InMemoryElection**: Development/testing implementation using in-memory state
- **Node**: Represents a cluster member with ID, address, state, and metadata
- **ClusterState**: Current state of the cluster including leader and all nodes
- **ClusterStateChange**: Events fired on node joins, leaves, or state changes

## Usage

### Initialize Cluster

```bash
# Start a cluster node (automatic in daemon mode)
ztap cluster status
```

### Join a Cluster

```bash
# Add a new node to the cluster
ztap cluster join node-2 192.168.1.2:9090
ztap cluster join node-3 192.168.1.3:9090
```

### View Cluster Status

```bash
# Show current leader and all nodes
ztap cluster status

# List all nodes with details
ztap cluster list
```

### Remove a Node

```bash
# Remove a node from the cluster
ztap cluster leave node-2
```

## Configuration

Cluster coordination is configured via `LeaderElectionConfig`:

```go
config := cluster.LeaderElectionConfig{
    NodeID:             "node-1",
    NodeAddress:        "192.168.1.1:9090",
    HeartbeatInterval:  1 * time.Second,    // Default: 1s
    ElectionTimeout:    5 * time.Second,    // Default: 5s
    InitialLeadership:  3 * time.Second,    // Time before first node can lead
    MaxRetries:         3,                  // Default: 3
}
```

## In-Memory Implementation

The current implementation uses `InMemoryElection` for development and single-machine testing:

- **Lexicographic leader election**: First healthy node (by ID) becomes leader
- **No persistence**: Cluster state is lost on restart
- **Single-process**: Only works within one process or with IPC

### Features

- Node registration and deregistration
- Periodic health checks
- Leader election on timeout or health change
- Change notification channels
- Default configuration values

### Limitations

- Not suitable for production distributed deployments
- No data persistence
- No cross-node communication
- No automatic failover to persisted replicas

## Production Deployment

For production distributed deployments, implement alternative backends:

### etcd Backend

```go
type EtcdElection struct {
    // etcd client configuration
    client *clientv3.Client
    // ...
}

func (e *EtcdElection) Start(ctx context.Context) error {
    // Use etcd leader election API
    // Watch keys for cluster state changes
}
```

### Raft Backend

```go
type RaftElection struct {
    // Raft node configuration
    raftNode *raft.RawNode
    // ...
}

func (e *RaftElection) Start(ctx context.Context) error {
    // Use Raft consensus for leader election
    // Replicate state across nodes
}
```

## API Reference

### LeaderElection Interface

```go
type LeaderElection interface {
    Start(ctx context.Context) error
    Stop() error
    IsLeader() bool
    GetLeader() *Node
    RegisterNode(node *Node) error
    DeregisterNode(nodeID string) error
    GetNodes() []*Node
    GetNode(nodeID string) *Node
    Watch(ctx context.Context) <-chan ClusterStateChange
    LeaderChanges(ctx context.Context) <-chan *Node
}
```

### Node Structure

```go
type Node struct {
    ID       string            // Unique node identifier
    Address  string            // Network address (host:port)
    State    NodeState         // Operational state
    Role     string            // "leader" or "follower"
    JoinedAt time.Time         // Cluster join timestamp
    LastSeen time.Time         // Last heartbeat
    Metadata map[string]string // Custom metadata
}
```

### State Changes

```go
type ClusterStateChange struct {
    Type      ChangeType    // node_joined, node_left, node_healthy, etc.
    Node      *Node         // Node involved
    Timestamp time.Time     // Change time
    Error     error         // Optional error
}
```

## Future Extensions

### Distributed Policy Sync

Once cluster foundation is in place, add distributed policy synchronization:

```go
type PolicySync interface {
    SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error
    GetPolicyVersion(policyName string) (int64, error)
    SubscribePolicies(ctx context.Context) <-chan PolicyUpdate
}
```

### Multi-Region Deployments

Extend cluster support to coordinate across AWS regions:

- Regional leaders
- Cross-region policy sync
- Geographically distributed failover

### Monitoring & Observability

Add Prometheus metrics for cluster health:

- `ztap_cluster_nodes_total` - Number of nodes in cluster
- `ztap_cluster_leader_elections_total` - Leader election count
- `ztap_cluster_node_joins_total` - Node join count
- `ztap_cluster_heartbeat_latency_seconds` - Heartbeat latency histogram

## Testing

Run cluster tests:

```bash
go test ./pkg/cluster -v
```

Tests cover:

- Node registration and deregistration
- Leader election with multiple nodes
- Health state transitions
- Watcher notifications
- Configuration defaults
- Stop/start lifecycle

## See Also

- [Types and Interfaces](../pkg/cluster/types.go)
- [In-Memory Implementation](../pkg/cluster/election_memory.go)
- [CLI Commands](../cmd/cluster.go)
- [Tests](../pkg/cluster/election_memory_test.go)

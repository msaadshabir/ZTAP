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

## Distributed Policy Synchronization

ZTAP supports distributed policy synchronization across cluster nodes, ensuring all nodes enforce consistent security policies.

### Architecture

```
Leader Node                  Follower Node 1           Follower Node 2
(Node 1)                     (Node 2)                  (Node 3)
    |                             |                          |
    | SyncPolicy(policy.yaml)     |                          |
    +------ PolicyUpdate -------->|                          |
    +------ PolicyUpdate ---------------------------------->|
    |                             |                          |
    |                    [Apply Policy]             [Apply Policy]
    |                             |                          |
```

### Key Features

- **Leader-Initiated Sync**: Only the elected leader can initiate policy updates
- **Version Tracking**: Each policy has a monotonically increasing version number
- **Real-Time Notifications**: Followers receive instant notifications of policy changes
- **Consistency Guarantees**: Version-based conflict resolution prevents out-of-order updates
- **Subscribe Pattern**: Nodes can watch for policy updates via channels

### Usage

#### Sync a Policy to Cluster

```bash
# Only works on the leader node
ztap policy sync examples/web-to-db.yaml --name web-to-db
```

#### List All Policies

```bash
# View all policies synced across the cluster
ztap policy list
```

Output:

```
Cluster Policies
================

Name         Version  Source Node  Last Updated
----         -------  -----------  ------------
web-to-db    2        node-1       5s ago
api-policy   1        node-1       10m ago

Total: 2 policies
```

#### Watch for Policy Changes

```bash
# Monitor real-time policy updates
ztap policy watch
```

Output:

```
Watching for policy updates... (Ctrl+C to stop)

[10:15:30] Policy: web-to-db | Version: 1 | Source: node-1
[10:16:45] Policy: web-to-db | Version: 2 | Source: node-1
[10:20:12] Policy: api-policy | Version: 1 | Source: node-1
```

#### Show Policy Details

```bash
# Display full policy YAML and metadata
ztap policy show web-to-db
```

Output:

```
Policy: web-to-db
Version: 2
Source Node: node-1
Last Updated: 2025-10-22T10:16:45Z

YAML Content:
-------------
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

### Programmatic Usage

```go
package main

import (
    "context"
    "ztap/pkg/cluster"
)

func main() {
    // Initialize election and policy sync
    election := cluster.NewInMemoryElection(config)
    policySync := cluster.NewInMemoryPolicySync(election, "node-1")

    ctx := context.Background()
    election.Start(ctx)
    policySync.Start(ctx)

    // Sync a policy (leader only)
    policyYAML := []byte(`apiVersion: ztap/v1...`)
    if err := policySync.SyncPolicy(ctx, "web-to-db", policyYAML); err != nil {
        panic(err)
    }

    // Subscribe to policy updates
    updates := policySync.SubscribePolicies(ctx)
    for update := range updates {
        fmt.Printf("Policy %s updated to version %d\n",
            update.PolicyName, update.Version)
        // Apply enforcement here
    }
}
```

### PolicySync Interface

```go
type PolicySync interface {
    // SyncPolicy broadcasts a policy update to all nodes (leader only)
    SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error

    // GetPolicyVersion returns the current version of a policy
    GetPolicyVersion(policyName string) (int64, error)

    // SubscribePolicies returns a channel for policy update notifications
    SubscribePolicies(ctx context.Context) <-chan PolicyUpdate
}

type PolicyUpdate struct {
    PolicyName string    // Name of the policy
    YAML       []byte    // Policy YAML content
    Version    int64     // Version number (monotonically increasing)
    Source     string    // Node ID that initiated the update
    Timestamp  time.Time // When the update occurred
}
```

### InMemoryPolicySync Implementation

The current implementation uses `InMemoryPolicySync` for development and testing:

**Features:**

- Thread-safe policy storage with mutex protection
- Automatic version increment on updates
- Leader-only write restriction
- Broadcast notifications to all subscribers
- Version-based conflict resolution
- Integration with LeaderElection for cluster awareness

**Limitations:**

- No persistence (policies lost on restart)
- No cross-process communication
- Not suitable for production distributed deployments

**Production Alternative:**

For production, implement an etcd or Raft-based backend:

```go
type EtcdPolicySync struct {
    client *clientv3.Client
    election LeaderElection
}

func (e *EtcdPolicySync) SyncPolicy(ctx context.Context, name string, yaml []byte) error {
    // Store in etcd with version
    // Use etcd watch for notifications
}
```

### Integration with Enforcement

**✅ FULLY IMPLEMENTED**

Policy sync integrates with the `PolicyEnforcer` to automatically apply policies on all cluster nodes:

#### Automatic Enforcement Flow

```
1. Leader syncs policy → 2. PolicySync broadcasts → 3. Enforcers receive update
                                                   ↓
4. Parse YAML ← 5. Validate policy ← 6. Enforce with eBPF/pf ← 7. Track version
```

#### PolicyEnforcer Implementation

The `PolicyEnforcer` component automatically subscribes to policy updates and enforces them:

```go
// PolicyEnforcer is initialized on each node
enforcer := enforcer.NewPolicyEnforcer(enforcer.PolicyEnforcerConfig{
    PolicySync: policySync,
    Discovery:  discovery,
    CgroupPath: "/sys/fs/cgroup/unified",  // Linux eBPF
})

// Start enforcement (subscribes to updates automatically)
enforcer.Start(ctx)

// Enforcer automatically:
// 1. Subscribes to policy updates from PolicySync
// 2. Parses YAML when updates arrive
// 3. Validates policy structure
// 4. Enforces using eBPF (Linux) or pf (macOS)
// 5. Tracks enforced versions to skip old updates
// 6. Records Prometheus metrics
```

#### Platform-Specific Enforcement

The enforcer uses build tags for cross-platform support:

**Linux** (`//go:build linux`):

```go
func (pe *PolicyEnforcer) enforceLinux(policies []*policy.Policy) error {
    // Use eBPF for kernel-level enforcement
    return enforceWithEBPFIfAvailable(policies, pe.cgroupPath)
}
```

**macOS** (`//go:build !linux`):

```go
func (pe *PolicyEnforcer) enforceMacOS(policies []*policy.Policy) error {
    // Use pf for packet filter enforcement
    return EnforceWithPF(policies)
}
```

#### Version Tracking

The enforcer tracks which versions it has enforced to prevent duplicate work:

```go
// Skip old versions
if update.Version <= pe.enforcedVersion[update.PolicyName] {
    log.Printf("Skipping policy %s v%d (already enforced v%d)",
        update.PolicyName, update.Version, pe.enforcedVersion[update.PolicyName])
    return
}

// Apply new version
if err := pe.applyPolicy(update); err != nil {
    log.Printf("Failed to enforce: %v", err)
    return
}

// Update tracking
pe.enforcedVersion[update.PolicyName] = update.Version
```

#### Metrics

Enforcement is fully instrumented with Prometheus metrics:

- `ztap_policies_enforced_total{status, policy_name, node_id}` - Enforcement operations
- `ztap_policy_enforcement_duration_seconds{policy_name}` - Enforcement duration

#### Testing

**Unit Tests** (6 tests, all passing):

```bash
go test ./pkg/enforcer -v
```

**Integration Tests** (3 tests, all passing):

```bash
go test -tags=integration ./pkg/enforcer -v
```

Tests cover:

- Automatic enforcement on policy updates
- Version tracking (skip old versions)
- Multiple concurrent policies
- Invalid YAML handling
- Platform detection
- Metrics recording

#### Example

See the complete working example:

```bash
go run examples/policy_sync_example.go
```

This demonstrates a 3-node cluster with automatic enforcement:

1. Node 1 (leader) syncs a policy
2. All 3 nodes receive the update
3. All 3 nodes automatically enforce the policy
4. Metrics are recorded on all nodes

````

### Testing

**Policy Sync Tests:**
```bash
go test ./pkg/cluster -v -run PolicySync
````

Tests cover (24 test cases, all passing):

- Leader-only sync enforcement
- Version tracking and increment
- Subscriber notifications (single and multiple)
- Concurrent policy updates (10 goroutines)
- Remote update application
- Version conflict resolution
- Input validation

**Enforcer Tests:**

```bash
go test ./pkg/enforcer -v
```

Tests cover (6 test cases, all passing):

- Lifecycle management (Start/Stop)
- Automatic enforcement on updates
- Version tracking
- Invalid YAML handling

**Integration Tests:**

```bash
go test -tags=integration ./pkg/enforcer -v -run TestPolicyEnforcer
```

Tests cover (3 test cases, all passing):

- End-to-end cluster setup with leader election
- Multiple concurrent policies
- 10 concurrent sync operations
- Automatic enforcement verification

Example code:

```bash
go run examples/policy_sync_example.go
```

### Metrics

Policy sync and enforcement are fully instrumented:

**Policy Sync Metrics:**

- `ztap_policies_synced_total{status, policy_name}` - Total sync operations
- `ztap_policy_sync_errors_total{error_type, policy_name}` - Sync errors
- `ztap_policy_sync_duration_seconds{policy_name}` - Sync duration (histogram)
- `ztap_policy_version_current{policy_name}` - Current version (gauge)
- `ztap_policy_subscribers_active` - Active subscribers count

**Enforcement Metrics:**

- `ztap_policies_enforced_total{status, policy_name, node_id}` - Enforcement operations
- `ztap_policy_enforcement_duration_seconds{policy_name}` - Enforcement duration (histogram)

### See Also

- [Policy Sync Implementation](../pkg/cluster/policy_sync_memory.go)
- [Policy Sync Metrics](../pkg/cluster/policy_sync_metrics.go)
- [Policy Sync Tests](../pkg/cluster/policy_sync_memory_test.go)
- [Policy Enforcer](../pkg/enforcer/policy_enforcer.go)
- [Enforcer Tests](../pkg/enforcer/policy_enforcer_test.go)
- [Integration Tests](../pkg/enforcer/policy_enforcer_integration_test.go)
- [Policy CLI Commands](../cmd/policy.go)
- [Example Code](../examples/policy_sync_example.go)
- [Complete Feature Documentation](../POLICY_SYNC_COMPLETE.md)

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

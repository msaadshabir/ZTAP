# Distributed Cluster Architecture

ZTAP supports multi-node clusters for distributed policy synchronization and high-availability deployments.

## Overview

The cluster package provides:

- **Leader Election**: Automatic leader election with in-memory or etcd backends
- **Node Management**: Register, track, and monitor cluster members
- **Health Monitoring**: Periodic heartbeats and state tracking
- **Policy Sync**: Distributed policy synchronization across nodes

## Architecture

```
Node 1 (Leader)          Node 2 (Follower)        Node 3 (Follower)
      |                        |                        |
      +-------- Heartbeat --------+
      |                        |                        |
      +-- Policy Sync -------->+----------------------->+
      |                        |                        |
      +--- Leader Election Monitoring ---+
```

## Quick Start

```bash
# View cluster status
ztap cluster status

# Add nodes
ztap cluster join node-2 192.168.1.2:9090
ztap cluster join node-3 192.168.1.3:9090

# List nodes
ztap cluster list

# Remove a node
ztap cluster leave node-2
```

## Configuration

```go
config := cluster.LeaderElectionConfig{
    NodeID:             "node-1",
    NodeAddress:        "192.168.1.1:9090",
    HeartbeatInterval:  1 * time.Second,
    ElectionTimeout:    5 * time.Second,
}
```

## Backends

### In-Memory (Development)

Default backend for single-machine testing:

- Lexicographic leader election (first healthy node by ID)
- No persistence (state lost on restart)
- Single-process only

### etcd (Production)

For production deployments, use the etcd backend:

```go
etcdConfig := &cluster.EtcdConfig{
    Endpoints:   []string{"etcd1:2379", "etcd2:2379"},
    DialTimeout: 5 * time.Second,
    SessionTTL:  60 * time.Second,
}

election, err := cluster.NewEtcdElection(config, etcdConfig)
```

See [etcd Setup](etcd.md) for detailed configuration.

## Policy Synchronization

ZTAP synchronizes policies across all cluster nodes automatically.

### Sync a Policy

```bash
# Leader only
ztap policy sync examples/web-to-db.yaml --name web-to-db
```

### List Policies

```bash
ztap policy list

# Output:
# Name         Version  Source Node  Last Updated
# web-to-db    2        node-1       5s ago
# api-policy   1        node-1       10m ago
```

### Watch for Changes

```bash
ztap policy watch
```

### Show Policy Details

```bash
ztap policy show web-to-db
```

## Programmatic Usage

```go
// Initialize
election := cluster.NewInMemoryElection(config)
policySync := cluster.NewInMemoryPolicySync(election, "node-1")

ctx := context.Background()
election.Start(ctx)
policySync.Start(ctx)

// Sync a policy (leader only)
policyYAML := []byte(`apiVersion: ztap/v1...`)
policySync.SyncPolicy(ctx, "web-to-db", policyYAML)

// Subscribe to updates
updates := policySync.SubscribePolicies(ctx)
for update := range updates {
    fmt.Printf("Policy %s v%d updated\n", update.PolicyName, update.Version)
}
```

## Automatic Enforcement

The `PolicyEnforcer` subscribes to policy updates and enforces them automatically:

```go
enforcer := enforcer.NewPolicyEnforcer(enforcer.PolicyEnforcerConfig{
    PolicySync: policySync,
    Discovery:  discovery,
    CgroupPath: "/sys/fs/cgroup/unified",  // Linux eBPF
})
enforcer.Start(ctx)
```

Platform-specific enforcement:

- **Linux**: eBPF kernel-level enforcement
- **macOS**: pf packet filter

## Metrics

Policy sync and enforcement metrics:

| Metric                                     | Type      | Description            |
| ------------------------------------------ | --------- | ---------------------- |
| `ztap_policies_synced_total`               | Counter   | Sync operations        |
| `ztap_policy_sync_duration_seconds`        | Histogram | Sync duration          |
| `ztap_policy_version_current`              | Gauge     | Current version        |
| `ztap_policies_enforced_total`             | Counter   | Enforcement operations |
| `ztap_policy_enforcement_duration_seconds` | Histogram | Enforcement duration   |

## Testing

```bash
# Unit tests
go test ./pkg/cluster -v

# Integration tests
go test -tags=integration ./pkg/enforcer -v
```

## Related Documentation

- [etcd Setup](etcd.md) - Production backend configuration
- [Architecture](architecture.md) - System design overview
- [Testing](testing.md) - Test suite documentation

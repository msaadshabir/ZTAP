# etcd Backend Setup Guide

This guide explains how to configure and deploy ZTAP with etcd for production-grade distributed coordination.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Migration](#migration)

---

## Overview

ZTAP supports two cluster coordination backends:

| Backend       | Use Case             | Persistence | Multi-Node | Production Ready |
| ------------- | -------------------- | ----------- | ---------- | ---------------- |
| **In-Memory** | Development, Testing | No          | Single     | No               |
| **etcd**      | Production           | Yes         | Multi      | Yes              |

The etcd backend provides:

- **High Availability**: Automatic leader election with failover
- **Distributed Consensus**: Raft-based consistency across nodes
- **Persistent Storage**: Cluster state survives node restarts
- **Watch Mechanisms**: Real-time notifications of state changes
- **Production Grade**: Battle-tested in Kubernetes and other systems

---

## Prerequisites

### System Requirements

- Go 1.24+ (for building ZTAP)
- etcd 3.4+ cluster
- Network connectivity between ZTAP nodes and etcd cluster
- Sufficient disk space for etcd data (recommend 10GB+)

### etcd Installation

Choose one of the following installation methods:

#### Option 1: Docker (Recommended for Testing)

```bash
# Single-node etcd for development
docker run -d \
  --name etcd-test \
  -p 2379:2379 \
  -p 2380:2380 \
  quay.io/coreos/etcd:v3.5.17 \
  /usr/local/bin/etcd \
  --name etcd0 \
  --initial-advertise-peer-urls http://localhost:2380 \
  --listen-peer-urls http://0.0.0.0:2380 \
  --advertise-client-urls http://localhost:2379 \
  --listen-client-urls http://0.0.0.0:2379 \
  --initial-cluster etcd0=http://localhost:2380
```

#### Option 2: Docker Compose (Multi-Node)

Create `etcd-cluster.yml`:

```yaml
version: "3.8"
services:
  etcd1:
    image: quay.io/coreos/etcd:v3.5.17
    environment:
      - ETCD_NAME=etcd1
      - ETCD_INITIAL_CLUSTER=etcd1=http://etcd1:2380,etcd2=http://etcd2:2380,etcd3=http://etcd3:2380
      - ETCD_INITIAL_CLUSTER_STATE=new
      - ETCD_INITIAL_ADVERTISE_PEER_URLS=http://etcd1:2380
      - ETCD_ADVERTISE_CLIENT_URLS=http://etcd1:2379
      - ETCD_LISTEN_PEER_URLS=http://0.0.0.0:2380
      - ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379
    ports:
      - "2379:2379"
      - "2380:2380"

  etcd2:
    image: quay.io/coreos/etcd:v3.5.17
    environment:
      - ETCD_NAME=etcd2
      - ETCD_INITIAL_CLUSTER=etcd1=http://etcd1:2380,etcd2=http://etcd2:2380,etcd3=http://etcd3:2380
      - ETCD_INITIAL_CLUSTER_STATE=new
      - ETCD_INITIAL_ADVERTISE_PEER_URLS=http://etcd2:2380
      - ETCD_ADVERTISE_CLIENT_URLS=http://etcd2:2379
      - ETCD_LISTEN_PEER_URLS=http://0.0.0.0:2380
      - ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379
    ports:
      - "22379:2379"
      - "22380:2380"

  etcd3:
    image: quay.io/coreos/etcd:v3.5.17
    environment:
      - ETCD_NAME=etcd3
      - ETCD_INITIAL_CLUSTER=etcd1=http://etcd1:2380,etcd2=http://etcd2:2380,etcd3=http://etcd3:2380
      - ETCD_INITIAL_CLUSTER_STATE=new
      - ETCD_INITIAL_ADVERTISE_PEER_URLS=http://etcd3:2380
      - ETCD_ADVERTISE_CLIENT_URLS=http://etcd3:2379
      - ETCD_LISTEN_PEER_URLS=http://0.0.0.0:2380
      - ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379
    ports:
      - "32379:2379"
      - "32380:2380"
```

Start the cluster:

```bash
docker-compose -f etcd-cluster.yml up -d
```

#### Option 3: System Package Manager

**Ubuntu/Debian:**

```bash
sudo apt-get update
sudo apt-get install etcd
sudo systemctl start etcd
sudo systemctl enable etcd
```

**macOS (Homebrew):**

```bash
brew install etcd
brew services start etcd
```

**RHEL/CentOS:**

```bash
sudo yum install etcd
sudo systemctl start etcd
sudo systemctl enable etcd
```

---

## Quick Start

### 1. Verify etcd is Running

```bash
# Test etcd connectivity
./ztap cluster test-etcd

# Or use etcdctl
etcdctl endpoint health
```

Expected output:

```
Testing etcd connection to: [localhost:2379]

Connection successful!
Etcd cluster has 1 member(s)
  1. ID=8211f1d0f64f3269, Name=default, ClientURLs=[http://localhost:2379]
```

### 2. Configure ZTAP to Use etcd

Currently, ZTAP uses in-memory backend by default. To use etcd in your application:

```go
package main

import (
    "context"
    "log"
    "time"

    "ztap/pkg/cluster"
)

func main() {
    // Configure etcd
    etcdConfig := &cluster.EtcdConfig{
        Endpoints:   []string{"localhost:2379"},
        DialTimeout: 5 * time.Second,
        KeyPrefix:   "/ztap",
        SessionTTL:  60 * time.Second,
    }

    // Configure this node
    leaderConfig := cluster.LeaderElectionConfig{
        NodeID:            "node-1",
        NodeAddress:       "10.0.1.1:9090",
        HeartbeatInterval: 5 * time.Second,
        ElectionTimeout:   15 * time.Second,
    }

    // Create etcd election
    election, err := cluster.NewEtcdElection(leaderConfig, etcdConfig)
    if err != nil {
        log.Fatalf("Failed to create election: %v", err)
    }

    // Start election
    ctx := context.Background()
    if err := election.Start(ctx); err != nil {
        log.Fatalf("Failed to start election: %v", err)
    }
    defer election.Stop()

    // Use the election...
    if election.IsLeader() {
        log.Println("I am the leader!")
    }
}
```

### 3. Run Example

```bash
# Terminal 1
go run ./examples/etcd_election node1

# Terminal 2
go run ./examples/etcd_election node2

# Terminal 3
go run ./examples/etcd_election node3
```

Observe leader election and automatic failover.

---

## Production Deployment

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       etcd Cluster                          │
│  ┌────────┐         ┌────────┐         ┌────────┐         │
│  │ etcd-1 │ ◄─────► │ etcd-2 │ ◄─────► │ etcd-3 │         │
│  └───▲────┘         └───▲────┘         └───▲────┘         │
└──────┼──────────────────┼──────────────────┼───────────────┘
       │                  │                  │
       │                  │                  │
┌──────┼──────────────────┼──────────────────┼───────────────┐
│      │                  │                  │               │
│  ┌───▼────┐         ┌───▼────┐         ┌───▼────┐         │
│  │ ZTAP-1 │         │ ZTAP-2 │         │ ZTAP-3 │         │
│  │(Leader)│         │(Follow)│         │(Follow)│         │
│  └────────┘         └────────┘         └────────┘         │
│                                                             │
│                     ZTAP Cluster                            │
└─────────────────────────────────────────────────────────────┘
```

### Best Practices

#### 1. etcd Cluster Sizing

- **Development**: 1 node
- **Testing**: 3 nodes
- **Production**: 3 or 5 nodes (always odd number)
- **Large Scale**: 5 nodes maximum (more doesn't improve availability)

#### 2. Network Configuration

- **Latency**: Keep <10ms between etcd nodes
- **Bandwidth**: Minimum 1 Gbps for production
- **Firewall**: Open ports 2379 (client) and 2380 (peer)

#### 3. Hardware Recommendations

**Minimum (per etcd node):**

- CPU: 2 cores
- RAM: 4 GB
- Disk: 50 GB SSD
- Network: 1 Gbps

**Recommended (production):**

- CPU: 4 cores
- RAM: 8 GB
- Disk: 100 GB SSD (NVMe preferred)
- Network: 10 Gbps

#### 4. Disk Performance

etcd is **highly sensitive to disk latency**. Use SSD or NVMe drives.

Test disk performance:

```bash
# Should be <10ms for 99th percentile
fio --rw=write --ioengine=sync --fdatasync=1 \
    --directory=/var/lib/etcd --size=22m \
    --bs=2300 --name=mytest
```

### TLS Configuration

For production, always use TLS:

```go
import "crypto/tls"

etcdConfig := &cluster.EtcdConfig{
    Endpoints:   []string{"https://etcd1:2379", "https://etcd2:2379"},
    DialTimeout: 5 * time.Second,
    TLSConfig: &tls.Config{
        CertFile:      "/path/to/client.crt",
        KeyFile:       "/path/to/client.key",
        CAFile:        "/path/to/ca.crt",
        ServerName:    "etcd-cluster",
    },
}
```

Generate certificates:

```bash
# Using cfssl
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem \
    -config=ca-config.json -profile=client client.json | \
    cfssljson -bare client
```

### Authentication

Enable etcd authentication:

```bash
# Create root user
etcdctl user add root
etcdctl auth enable

# Create ZTAP user
etcdctl user add ztap --interactive
etcdctl role add ztap-role
etcdctl role grant-permission ztap-role readwrite /ztap/ --prefix
etcdctl user grant-role ztap ztap-role
```

Use credentials in ZTAP:

```go
etcdConfig := &cluster.EtcdConfig{
    Endpoints:   []string{"localhost:2379"},
    Username:    "ztap",
    Password:    "secure-password",
    // ... rest of config
}
```

---

## Configuration

### EtcdConfig Reference

```go
type EtcdConfig struct {
    // Endpoints is the list of etcd cluster endpoints
    // Example: []string{"etcd1:2379", "etcd2:2379", "etcd3:2379"}
    Endpoints []string

    // DialTimeout is the timeout for establishing initial connection
    // Default: 5 seconds
    DialTimeout time.Duration

    // Username for etcd authentication (optional)
    Username string

    // Password for etcd authentication (optional)
    Password string

    // TLSConfig for secure connections (optional but recommended for production)
    TLSConfig *tls.Config

    // KeyPrefix is the namespace for all ZTAP keys in etcd
    // Default: "/ztap"
    KeyPrefix string

    // LeaderElectionKey is the key used for leader election
    // Default: "{KeyPrefix}/election"
    LeaderElectionKey string

    // SessionTTL is the time-to-live for etcd session (lease)
    // Default: 60 seconds
    // Lower values = faster failover, higher load on etcd
    SessionTTL time.Duration
}
```

### LeaderElectionConfig Reference

```go
type LeaderElectionConfig struct {
    // NodeID: Unique identifier for this node
    // Should be stable across restarts (hostname, MAC address, etc.)
    NodeID string

    // NodeAddress: Network address for this node
    // Format: "host:port" (e.g., "10.0.1.1:9090")
    NodeAddress string

    // HeartbeatInterval: How often to send heartbeats
    // Default: 5 seconds
    // Recommendation: 2-10 seconds
    HeartbeatInterval time.Duration

    // ElectionTimeout: Time before triggering new election
    // Default: 15 seconds
    // Should be 3x HeartbeatInterval
    ElectionTimeout time.Duration
}
```

### Environment Variables

For containerized deployments:

```bash
export ZTAP_ETCD_ENDPOINTS=etcd1:2379,etcd2:2379,etcd3:2379
export ZTAP_ETCD_USERNAME=ztap
export ZTAP_ETCD_PASSWORD=secure-password
export ZTAP_NODE_ID=$(hostname)
export ZTAP_NODE_ADDRESS=$(hostname -i):9090
```

---

## Testing

### Unit Tests

```bash
# Run unit tests (no etcd required)
go test ./pkg/cluster -v -short

# Run with coverage
go test ./pkg/cluster -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Integration Tests

```bash
# Requires running etcd server
docker run -d -p 2379:2379 --name etcd-test \
    quay.io/coreos/etcd:v3.5.17

# Run integration tests
go test -tags=integration ./pkg/cluster -v

# Cleanup
docker stop etcd-test && docker rm etcd-test
```

### Load Testing

Test with multiple concurrent nodes:

```bash
# Start etcd
docker-compose -f etcd-cluster.yml up -d

# Run 10 concurrent ZTAP nodes
for i in {1..10}; do
    go run ./examples/etcd_election "node-$i" &
done

# Observe: Only one becomes leader
# Kill leader: watch automatic failover

# Cleanup
pkill -f examples/etcd_election
```

---

## Troubleshooting

### Common Issues

#### 1. Connection Refused

**Symptom:**

```
Error: Failed to connect to etcd: context deadline exceeded
```

**Solutions:**

- Verify etcd is running: `systemctl status etcd`
- Check firewall: `telnet localhost 2379`
- Verify endpoints: `etcdctl endpoint health`

#### 2. Leader Election Timeout

**Symptom:**

```
Node did not become leader within timeout
```

**Solutions:**

- Check SessionTTL is not too short
- Verify network connectivity between nodes
- Check etcd cluster health: `etcdctl endpoint status -w table`

#### 3. Split Brain

**Symptom:** Multiple nodes claim to be leader

**Solutions:**

- Verify nodes use same KeyPrefix
- Check etcd cluster has quorum
- Ensure network is stable (no partitions)

#### 4. Permission Denied

**Symptom:**

```
Error: rpc error: code = PermissionDenied
```

**Solutions:**

- Verify authentication credentials
- Check role permissions: `etcdctl role get ztap-role`
- Ensure user has correct role: `etcdctl user get ztap`

### Debugging Commands

```bash
# Check etcd cluster health
etcdctl endpoint health --cluster

# List all ZTAP keys
etcdctl get /ztap/ --prefix --keys-only

# Watch ZTAP changes in real-time
etcdctl watch /ztap/ --prefix

# Check current leader
etcdctl get /ztap/election --print-value-only | jq .

# View cluster members
etcdctl member list -w table

# Check metrics
curl http://localhost:2379/metrics
```

### Logging

Enable verbose logging:

```go
import "log"

// Set log level to debug
log.SetFlags(log.LstdFlags | log.Lshortfile)
```

---

## Migration

### From In-Memory to etcd

1. **Prepare etcd cluster** (see installation above)

2. **Update application code**:

```go
// Old (in-memory)
election := cluster.NewInMemoryElection(config)

// New (etcd)
etcdCfg := &cluster.EtcdConfig{
    Endpoints: []string{"etcd1:2379"},
}
election, err := cluster.NewEtcdElection(config, etcdCfg)
if err != nil {
    log.Fatal(err)
}
```

3. **Deploy changes with rolling update**:

```bash
# Update node 1
systemctl stop ztap-node1
# Deploy new binary
systemctl start ztap-node1

# Wait for node 1 to join cluster
# Repeat for remaining nodes
```

4. **Verify migration**:

```bash
# Check all nodes see same leader
for node in node1 node2 node3; do
    ssh $node "./ztap cluster status"
done
```

### Data Persistence

etcd automatically persists cluster state. No manual data migration needed.

**Backup etcd** (recommended before migration):

```bash
# Snapshot etcd data
etcdctl snapshot save backup.db

# Restore if needed
etcdctl snapshot restore backup.db
```

---

## Performance Tuning

### Optimizing for Latency

```go
// Faster failover (uses more resources)
etcdConfig := &cluster.EtcdConfig{
    SessionTTL: 10 * time.Second,  // Faster leader detection
}

leaderConfig := cluster.LeaderElectionConfig{
    HeartbeatInterval: 2 * time.Second,
    ElectionTimeout:   6 * time.Second,
}
```

### Optimizing for Stability

```go
// More stable (slower failover)
etcdConfig := &cluster.EtcdConfig{
    SessionTTL: 60 * time.Second,
}

leaderConfig := cluster.LeaderElectionConfig{
    HeartbeatInterval: 10 * time.Second,
    ElectionTimeout:   30 * time.Second,
}
```

### Monitoring

Recommended Prometheus metrics:

```
# etcd health
etcd_server_has_leader
etcd_server_leader_changes_seen_total
etcd_disk_backend_commit_duration_seconds

# ZTAP cluster
ztap_cluster_leader_elected_total
ztap_cluster_failover_duration_seconds
ztap_cluster_nodes_total
```

---

## References

- [etcd Official Documentation](https://etcd.io/docs/)
- [etcd Hardware Recommendations](https://etcd.io/docs/v3.5/op-guide/hardware/)
- [etcd Security Guide](https://etcd.io/docs/v3.5/op-guide/security/)
- [Raft Consensus Algorithm](https://raft.github.io/)
- [ZTAP Cluster Documentation](cluster.md)

---

## Support

For issues or questions:

1. Check [cluster.md](cluster.md) for general cluster documentation
2. Review [Troubleshooting](#troubleshooting) section above
3. Open an issue on GitHub with:
   - etcd version (`etcdctl version`)
   - ZTAP logs
   - Network topology diagram
   - Steps to reproduce

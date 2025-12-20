# ZTAP Architecture

## Overview

ZTAP (Zero Trust Access Platform) implements microsegmentation across hybrid environments using a modular, policy-driven architecture.

## Components

### 0. API Server (`pkg/apihttp`)

**Responsibility**: Expose a minimal REST API around core ZTAP capabilities

**Features**:

- Health, auth, and status endpoints
- Enforcement lifecycle endpoints (start/stop/status)
- Flow streaming over SSE
- Prometheus metrics endpoint (`/metrics`)

### 1. Policy Engine (`pkg/policy`)

**Responsibility**: Parse, validate, and manage network policies

**Features**:

- Kubernetes-style YAML parsing
- Bidirectional enforcement (ingress and egress rules)
- Policy validation (CIDR, protocols, ports)
- Conflict detection (intra- and cross-policy overlap)
- Label resolution interface
- Multi-document YAML support

**Key Functions**:

```go
LoadFromFile(filename string) ([]NetworkPolicy, error)
Validate() error
ResolveLabels(labels map[string]string) ([]string, error)
```

### 2. OS Enforcer (`pkg/enforcer`)

**Responsibility**: Apply policies using OS-native mechanisms

**Implementations**:

- **Linux**: eBPF
  - Attach to cgroup hooks (egress and ingress)
  - Per-pod traffic control
  - Kernel-level enforcement with BTF support
  - Safe packet parsing using bpf_skb_load_bytes
  - Bidirectional filtering (cgroup_skb/egress and cgroup_skb/ingress)
- **macOS**: pf (Packet Filter)
  - Manages `/etc/pf.anchors/ztap`
  - Updates `/etc/pf.conf`
  - Supports pass in/out rules for ingress/egress
  - Requires sudo for full functionality

**Key Functions**:

```go
EnforceWithEBPFIfAvailable(policies []NetworkPolicy, cgroupPath string) error
StopEBPFEnforcement() error
EnforceWithPF(policies []NetworkPolicy)
```

### 3. Cloud Integrator (`pkg/cloud`)

**Responsibility**: Sync policies to cloud providers

**AWS Integration**:

- Discover EC2 instances via `DescribeInstances`
- Map labels to AWS tags
- Convert policies to Security Group rules
- Handle stateful firewall differences

**Key Functions**:

```go
DiscoverResources() ([]Resource, error)
SyncPolicy(policy NetworkPolicy, sgID string) error
```

### 4. Anomaly Detector (`pkg/anomaly`)

**Responsibility**: Detect abnormal traffic patterns

**Implementations**:

- **Simple Detector**: Rule-based (suspicious ports, geolocation)
- **Python ML Service**: Isolation Forest algorithm

**Key Functions**:

```go
Detect(flow FlowRecord) (*AnomalyScore, error)
Train(flows []FlowRecord) error
```

### 5. Metrics Collector (`pkg/metrics`)

**Responsibility**: Export Prometheus metrics

**Metrics**:

- `ztap_policies_enforced_total`
- `ztap_flows_allowed_total`
- `ztap_flows_blocked_total`
- `ztap_anomaly_score`
- `ztap_policy_load_duration_seconds`

**Key Functions**:

```go
GetCollector() *Collector
StartServer(port int) error
```

## Data Flow

```
User
 │
 ├─> CLI Command (enforce/status/logs)
 │
 ├─> API Server (HTTP)
 │
 ├─> Policy Engine
 │    ├─> Parse YAML
 │    ├─> Validate
 │    └─> Resolve Labels
 │
 ├─> OS Enforcer
 │    ├─> eBPF (Linux)
 │    └─> pf (macOS)
 │
 ├─> Cloud Integrator (optional)
 │    └─> AWS Security Groups
 │
 ├─> Anomaly Detector (optional)
 │    └─> Python ML Service
 │
 └─> Metrics Collector
      └─> Prometheus (:9090/metrics)
```

## Security Model

### Threat Model

| Threat              | Mitigation                         |
| ------------------- | ---------------------------------- |
| Policy Bypass       | Kernel-level enforcement (eBPF/pf) |
| Label Spoofing      | Trusted inventory (AWS tags, DNS)  |
| Enforcer Compromise | Minimal privileges, sandboxed      |

### Trust Boundaries

- **Policy Files**: Trusted input (review via GitOps)
- **Cloud APIs**: Authenticated via IAM/credentials
- **Anomaly Service**: Internal-only (localhost:5000)

## Performance Considerations

### Policy Load Time

- Target: <100ms for 100 policies
- Optimization: Concurrent validation, caching

### CPU Overhead

- Target: <2% on 4-core system
- eBPF: Near-zero overhead (kernel space)
- pf: Minimal (optimized rule matching)

### Memory Usage

- Target: <50 MB
- Policy cache: In-memory (no persistence)

## Distributed Architecture

ZTAP supports multi-node deployments with distributed coordination:

```
+----------------+     +----------------+
|  Leader Node   | <-> |  Follower Node |
| (Coordinates)  |     +----------------+
+----------------+     +----------------+
       ^               |  Follower Node |
       |               +----------------+
       |               +----------------+
       +-------------- |  Follower Node |
                       +----------------+
```

### High Availability

- Leader election: In-memory (dev) or etcd (production)
- Policy sync: Automatic distribution to all nodes
- Nodes: Stateless with persistent etcd backend

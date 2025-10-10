# ZTAP Architecture

## Overview

ZTAP (Zero Trust Access Platform) implements microsegmentation across hybrid environments using a modular, policy-driven architecture.

## Components

### 1. Policy Engine (`pkg/policy`)

**Responsibility**: Parse, validate, and manage network policies

**Features**:

- Kubernetes-style YAML parsing
- Policy validation (CIDR, protocols, ports)
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

- **Linux**: eBPF (planned - currently simulated)
  - Attach to cgroup hooks
  - Per-pod traffic control
  - Kernel-level enforcement
- **macOS**: pf (Packet Filter)
  - Manages `/etc/pf.anchors/ztap`
  - Updates `/etc/pf.conf`
  - Requires sudo for full functionality

**Key Functions**:

```go
EnforceWithEBPF(policies []NetworkPolicy)
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

## Future Architecture

### Distributed Deployment

```
+----------------+     +----------------+
|  Controller    | <-> |  Agent (Node1) |
| (Central API)  |     +----------------+
+----------------+     +----------------+
       ^               |  Agent (Node2) |
       |               +----------------+
       |               +----------------+
       +-------------- |  Agent (Node3) |
                       +----------------+
```

### High Availability

- Controller: Active-passive with etcd
- Agents: Stateless, crash-safe
- Policy store: Git as source of truth

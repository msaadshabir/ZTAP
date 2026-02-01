# ZTAP Architecture

## Overview

ZTAP (Zero Trust Access Platform) implements microsegmentation across hybrid environments using a modular, policy-driven architecture.

## Components

### 0. API Server (`pkg/apihttp`)

**Responsibility**: Expose a minimal REST API around core ZTAP capabilities

**Features**:

- Health, auth, and status endpoints
- Enforcement lifecycle endpoints (start/stop/status)
- Compliance report/export endpoints (policy-to-control mapping + evidence)
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

- **Linux**: eBPF (Primary)
  - Attach to cgroup hooks (egress and ingress)
  - Uses `bpf_link` for atomic, graceful policy reloads without connection drops
  - Per-cgroup policy keys (Kubernetes agent programs per-pod cgroup rules)
  - In scoped mode, “selected pods only” semantics are enabled so pods without policies are not impacted
  - Kernel-level enforcement with BTF support
  - Safe packet parsing using bpf_skb_load_bytes
  - Bidirectional filtering (cgroup_skb/egress and cgroup_skb/ingress)
  - Dual-stack support (IPv4 and IPv6)
- **Linux**: iptables (Fallback)
  - Used automatically if kernel < 5.7 or BPF unavailable (or `ZTAP_FORCE_IPTABLES=1`)
  - Manages `ZTAP-INGRESS` and `ZTAP-EGRESS` chains
  - Uses `iptables-restore` and `ip6tables-restore` for atomic updates
- **macOS**: pf (Packet Filter)
  - Manages `/etc/pf.anchors/ztap`
  - Updates `/etc/pf.conf`
  - Supports pass in/out rules for ingress/egress
  - Requires sudo for full functionality
- **Windows**: Windows Filtering Platform (WFP)
  - Applies filters via `fwpuclnt.dll` (user-mode WFP API)
  - Uses a ZTAP provider/sublayer and a transactional apply/delete model
  - Supports IPv4/IPv6 `ipBlock.cidr` (arbitrary CIDRs) and TCP/UDP/ICMP (ICMP ignores `port`)
  - Permit-only by default; optional strict default-deny can be enabled with `ZTAP_WFP_STRICT=1`

**Key Functions**:

```go
EnforceWithEBPFIfAvailable(opts EnforcementOptions) error
StopEBPFEnforcement() error
EnforceWithPF(opts EnforcementOptions)
EnforceWithWFP(opts EnforcementOptions) error
StopWFPEnforcement() error
```

**Features**:

- **Dry-run Mode**: Simulate enforcement without applying kernel rules (`--dry-run`)
- **Platform Abstraction**: Unified interface across OSes

### 3. Cloud Integrator (`pkg/cloud`)

**Responsibility**: Sync policies to cloud providers

**AWS Integration**:

- Discover EC2 instances via `DescribeInstances`
- Map labels to AWS tags
- Convert policies to Security Group rules
- Handle stateful firewall differences

**Azure Integration**:

- Reconcile policies into NSG security rules (managed rule prefix + delete stale managed rules)
- Uses Azure Identity default credentials (DefaultAzureCredential chain)

**Key Functions**:

```go
DiscoverResources() ([]Resource, error)
SyncPolicy(policy NetworkPolicy, sgID string) error

// Azure
SyncPolicy(policy NetworkPolicy, resourceGroup, nsgName string) error
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

### 5. Alerting (`pkg/alert`)

**Responsibility**: Deliver alert notifications to external systems

**Features**:

- Async dispatch with a bounded queue
- Webhook sinks: Slack incoming webhooks, PagerDuty Events API v2
- Optional in-memory dedupe (TTL) via `dedup_key`

**Common sources**:

- Policy enforcement success/failure (CLI/API/cluster enforcement)

### 6. Metrics Collector (`pkg/metrics`)

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

### 7. Kubernetes Operator + Node Agent (WIP)

**Responsibility**: Kubernetes-native policy authoring and distribution using a CRD and per-node agents

**Components**:

- **Operator** (`cmd/ztap-operator`)
  - Watches `ZtapNetworkPolicy` (group `ztap.io/v1alpha1`)
  - Converts to internal `ztap/v1` policy YAML and validates via `pkg/policy`
  - Publishes validated policies into a ConfigMap “policy store”
- **Node Agent** (`ztap agent`)
  - Watches the ConfigMap policy store via a Kubernetes-backed PolicySync (`pkg/cluster/policy_sync_k8s.go`)
  - Enforces policies via the existing `PolicyEnforcer`
  - Resolves selectors (`matchLabels` + `matchExpressions`, optionally with `namespaceSelector`) to pod IPs using Kubernetes discovery:
    - single-namespace: `pkg/discovery/k8s_discovery.go`
    - multi-namespace/all namespaces: `pkg/discovery/k8s_discovery_all_namespaces.go` (tenant-scoped)
  - Translates `podSelector` targets into concrete host CIDRs (`/32` for IPv4, `/128` for IPv6) `ipBlock` rules and re-applies enforcement when the resolved Pod IP set changes

## Data Flow

```text
User
│
├─> CLI Command (enforce/status/logs)
│
├─> Kubernetes (WIP)
│   ├─> Operator (CRD -> validated policy ConfigMaps)
│   └─> Node Agent (watches ConfigMaps -> PolicyEnforcer)
│
├─> API Server (HTTP/gRPC)
│
├─> Policy Engine
│   ├─> Parse YAML
│   ├─> Validate
│   └─> Resolve Labels (and optionally re-resolve over time)
│
├─> OS Enforcer
│   ├─> eBPF (Linux)
│   ├─> pf (macOS)
│   └─> WFP (Windows)
│
├─> Cloud Integrator (optional)
│   └─> AWS Security Groups
│
├─> Anomaly Detector (optional)
│   └─> Python ML Service
│
├─> Alerting (optional)
│   └─> Slack / PagerDuty webhooks
│
└─> Metrics Collector
    └─> Prometheus (:9090/metrics)
```

## Security Model

### Threat Model

| Threat              | Mitigation                         |
| ------------------- | ---------------------------------- |
| Policy Bypass       | OS-level enforcement (eBPF/pf/WFP) |
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
- WFP: Low overhead (Windows kernel filtering path)

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
- Policy sync: Automatic distribution to all nodes with versioned revisions and rollback
- Nodes: Stateless with persistent etcd backend

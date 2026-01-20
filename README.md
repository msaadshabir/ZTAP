# ZTAP: Zero Trust Access Platform

> Open-source zero-trust microsegmentation with eBPF enforcement, policy-as-code, and hybrid cloud support

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![eBPF](https://img.shields.io/badge/eBPF-Enabled-orange?logo=linux&logoColor=white)](docs/ebpf.md)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Compatible-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![AWS](https://img.shields.io/badge/AWS-Integration-FF9900?logo=amazon-aws&logoColor=white)](docs/setup.md)
[![Test Coverage](https://img.shields.io/badge/coverage-79%25-brightgreen.svg)](docs/testing.md)
[![NIST SP 800-207](https://img.shields.io/badge/NIST-SP%20800--207-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Quick Start

### Installation

```bash
# Build and install (Linux/macOS/Windows)
go build -o ztap
sudo mv ztap /usr/local/bin/

# Note for Linux: The binary includes pre-compiled eBPF bytecode.
# No clang/llvm dependency is required at runtime.
```

### First Steps

```bash
# 1. Authenticate
echo "ztap-admin-change-me" | ztap user login admin
ztap user change-password admin

# 2. Register services
ztap discovery register web-1 10.0.1.1 --labels app=web,tier=frontend
ztap discovery register db-1 10.0.2.1 --labels app=database,tier=backend

# 3. Enforce a policy
# Validate the policy first (CI/CD friendly)
ztap policy validate -f examples/web-to-db.yaml

# macOS (pf)
ztap enforce -f examples/web-to-db.yaml

# Windows (WFP)
# Note: run in an elevated terminal (Administrator).
# The Windows WFP enforcer currently supports IPv4 `ipBlock` rules with `/32` CIDRs and TCP/UDP only.
ztap enforce -f policy.yaml

# Linux (eBPF)
# Note: `ztap enforce` keeps running while enforcement is active.
# The Linux eBPF enforcer currently supports IPv4 `ipBlock` rules with `/32` CIDRs and TCP/UDP only.
# Policies that use `podSelector.matchLabels` can be enforced by resolving selectors into `/32` rules first:
# - In-cluster: run `ztap agent`
# - Local/CLI: run `ztap enforce --resolve-labels` with `discovery.backend: k8s`
sudo ztap enforce -f policy.yaml

# Dry-run mode (all platforms)
# Simulate enforcement without making system changes
ztap enforce -f policy.yaml --dry-run
ztap agent --dry-run

# 4. Check status
ztap status
```

**[Full Setup Guide](docs/setup.md)** | **[Architecture](docs/architecture.md)** | **[eBPF Setup](docs/ebpf.md)**

---

## Features

<table>
<tr>
<td width="50%">

### Security & Enforcement

- **Kernel-Level Filtering** – Real eBPF on Linux
- **Zero-Downtime Updates** – Graceful, atomic policy reloads using eBPF `bpf_link`
- **Older Kernel Support** – iptables fallback for pre-5.7 kernels or non-BPF environments
- **Bidirectional Enforcement** – Ingress and egress policies
- **Secure Communication** – HTTPS/TLS support for API and gRPC endpoints
- **RBAC** – Admin, Operator, Viewer roles
- **Session Management** – Configurable TTL with persistent sessions (SQLite default)
- **Tamper-Proof Audit Logging** – Cryptographic hash chaining
- **NIST SP 800-207** compliant

### Distributed Architecture

- **Leader Election** – Automatic cluster coordination
- **Policy Synchronization** – Real-time policy distribution with auto-enforcement
- **Multi-Node Support** – High-availability deployments
- **Version Tracking & Rollback** – Revision history with rollback to prior versions
- **Prometheus Metrics** – 7 metrics for sync and enforcement monitoring

### Cloud Integration

- **AWS Security Groups** – Auto-sync policies
- **Azure NSGs** – Reconcile policies into NSG security rules
- **GCP Firewall Rules** – Reconcile policies into VPC firewall rules
- **EC2 Auto-Discovery** – Tag-based labeling
- **Hybrid View** – Unified on-prem + cloud status

</td>
<td width="50%">

### Observability

- **Flow Monitoring** – Real-time on Linux with eBPF enforcement active; simulated on macOS; Windows flow reader is WIP
- **Alerting (Webhooks)** – Slack and PagerDuty notifications
- **Prometheus Metrics** – Pre-built exporters
- **Grafana Dashboards** – Auto-provisioned
- **ML Anomaly Detection** – Isolation Forest
- **Structured Logs** – Filter & follow

### Developer Experience

- **Kubernetes-Style YAML** – Familiar syntax
- **Label-Based Discovery** – Kubernetes API, DNS, and caching
- **REST API Server** – Minimal v1 endpoints via `ztap api serve`
- **gRPC API Server** – Minimal v1 RPCs via `ztap grpc serve`
- **79% Test Coverage** – Production-ready
- **Multi-Platform** – Linux (eBPF) + macOS (pf) + Windows (WFP)

</td>
</tr>
</table>

---

## Documentation

| Guide                                      | Description                               |
| ------------------------------------------ | ----------------------------------------- |
| [Setup Guide](docs/setup.md)               | Installation and configuration            |
| [Architecture](docs/architecture.md)       | System design and components              |
| [eBPF Enforcement](docs/ebpf.md)           | Linux kernel-level enforcement            |
| [Cluster Coordination](docs/cluster.md)    | Multi-node clustering and leader election |
| [Audit Logging](docs/audit.md)             | Tamper-proof audit log system             |
| [Testing Guide](docs/testing.md)           | Comprehensive testing documentation       |
| [Roadmap](docs/roadmap.md)                 | Delivered and planned features            |
| [Anomaly Detection](pkg/anomaly/README.md) | ML service setup                          |

---

## Example Policies

<details>
<summary><b>Web to Database (Label-based)</b></summary>

```yaml
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
            app: db
      ports:
        - protocol: TCP
          port: 5432
```

</details>

<details>
<summary><b>PCI Compliant (IP-based)</b></summary>

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: pci-compliant
spec:
  podSelector:
    matchLabels:
      app: payment-processor
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
```

</details>

<details>
<summary><b>Bidirectional (Ingress + Egress)</b></summary>

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-tier
spec:
  podSelector:
    matchLabels:
      tier: web
  egress:
    - to:
        podSelector:
          matchLabels:
            tier: database
      ports:
        - protocol: TCP
          port: 5432
  ingress:
    - from:
        ipBlock:
          cidr: 10.0.0.0/24
      ports:
        - protocol: TCP
          port: 443
```

</details>

**More examples in [examples/](examples/)**

---

## CLI Commands

```bash
ztap [command]

Commands:
  api         Run REST API server (serve)
  grpc        Run gRPC API server (serve)
  azure       Azure NSG synchronization (nsg-sync)
  gcp         GCP firewall rule synchronization (firewall-sync)
  agent       Run node agent (Kubernetes / in-cluster)
  enforce     Enforce zero-trust network policies
  status      Show on-premises and cloud resource status
  cluster     Manage cluster coordination (status, join, leave, list)
  policy      Distributed policy management (sync, list, watch, show, history, rollback)
  flows       Real-time flow event monitoring (--follow, --action, --protocol)
  logs        View ZTAP logs (with --follow, --level, --policy filters)
  metrics     Start Prometheus metrics server
  user        Manage users (create, login, list, change-password)
  discovery   Service discovery (register, resolve, list)
  audit       Audit log management (view, verify, stats)
```

<details>
<summary><b>API Server</b></summary>

```bash
# Start REST API server (reads config.yaml or file set via ZTAP_CONFIG)
ztap api serve

# Start gRPC API server (default 127.0.0.1:9092)
ztap grpc serve

# Liveness
curl -s http://127.0.0.1:8080/healthz

# Readiness
curl -s http://127.0.0.1:8080/readyz

# Login (default users DB: ~/.ztap/users.json)
# Sessions persist by default in ~/.ztap/sessions.db (SQLite)
token=$(curl -sS http://127.0.0.1:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ztap-admin-change-me"}' | jq -r .token)

# Who am I
curl -sS http://127.0.0.1:8080/v1/auth/whoami -H "Authorization: Bearer $token"
```

Core endpoints:

- `POST /v1/auth/login`, `GET /v1/auth/whoami`

Rate limiting:

- Config (default: disabled): `api.rate_limit`, `grpc.rate_limit` in `config.yaml`
- CLI flags: `ztap api serve --rate-limit ...`, `ztap grpc serve --rate-limit ...`
- REST: invalid/expired `Authorization` tokens fall back to unauthenticated bucket
- gRPC: rate-limited calls return `RESOURCE_EXHAUSTED` and include `RetryInfo` (retry delay)
- `POST /v1/config/backup` (download bundle; requires `backup_restore`)
- `POST /v1/config/restore?dry_run=1&force=1` (upload bundle; requires `backup_restore`)
- `GET /v1/status`
- `GET /v1/enforcement/status`, `POST /v1/enforcement/start`, `POST /v1/enforcement/stop` (Linux only)
- `GET /v1/flows/stream` (SSE)
- `GET /metrics`

gRPC services (v1):

- `ztap.api.v1.AuthService` (`Login`, `WhoAmI`)
- `ztap.api.v1.StatusService` (`GetStatus`)
- `ztap.api.v1.EnforcementService` (`GetStatus`, `Start`, `Stop`)
- `ztap.api.v1.FlowsService` (`Stream` server-streaming)

Auth: send `authorization: Bearer <token>` as gRPC metadata.

</details>

<details>
<summary><b>User Management</b></summary>

```bash
# Create users with roles (admin, operator, viewer)
echo "password" | ztap user create alice --role operator
ztap user list
ztap user change-password alice
```

</details>

<details>
<summary><b>Service Discovery</b></summary>

```bash
# Register and resolve services by labels
ztap discovery register web-1 10.0.1.1 --labels app=web,tier=frontend
ztap discovery resolve --labels app=web
ztap discovery list
```

Configuration (optional):

```yaml
# config.yaml (or file set via ZTAP_CONFIG)
discovery:
  backend: dns # inmemory (default) or dns
  dns:
    domain: example.com
  cache:
    ttl: 30s # optional cache layer for the selected backend
```

</details>

<details>
<summary><b>Cluster & Policy Management</b></summary>

```bash
# Cluster operations
ztap cluster status                          # View cluster state
ztap cluster join node-2 192.168.1.2:9090   # Join a node
ztap cluster list                            # List all nodes

# Policy synchronization (leader-initiated)
ztap policy sync examples/web-to-db.yaml    # Sync policy to all nodes
ztap policy list                             # List all policies
ztap policy watch                            # Watch real-time updates
ztap policy show web-to-db                   # Show policy details
ztap policy history web-to-db                # Show revision history
ztap policy rollback web-to-db --to 3        # Roll back by creating a new latest version
```

</details>

<details>
<summary><b>Flow Monitoring</b></summary>

```bash
# View recent flow events
ztap flows

# Stream flow events in real-time
ztap flows --follow

# Filter by action/protocol/direction
ztap flows --action blocked --protocol TCP
ztap flows --direction egress --limit 100

# Output formats
ztap flows --output json    # JSON format
ztap flows --output wide    # Extended details
```

On Linux, if `ztap enforce` is active, `ztap flows --follow` streams real events from the pinned eBPF ring buffer map (`/sys/fs/bpf/ztap/flow_events`). On macOS, flow output remains simulated.

</details>

<details>
<summary><b>Audit Logging</b></summary>

```bash
# View audit log with tamper-proof cryptographic verification
ztap audit view                                   # View recent entries
ztap audit view --actor admin                     # Filter by actor
ztap audit view --type policy.created             # Filter by event type
ztap audit view --resource web-policy             # Filter by resource
ztap audit view --limit 100                       # Limit results

# Verify cryptographic integrity
ztap audit verify                                 # Detect tampering

# Display statistics
ztap audit stats                                  # Show log stats
```

</details>

---

## Observability

### Prometheus Metrics

| Metric                                     | Description                              |
| ------------------------------------------ | ---------------------------------------- |
| `ztap_policies_enforced_total`             | Number of policies enforced              |
| `ztap_flows_allowed_total`                 | Allowed flows counter                    |
| `ztap_flows_blocked_total`                 | Blocked flows counter                    |
| `ztap_anomaly_score`                       | Current anomaly score (0-100)            |
| `ztap_policy_load_duration_seconds`        | Policy load time histogram               |
| `ztap_policies_synced_total`               | Total policy sync operations             |
| `ztap_policy_sync_duration_seconds`        | Policy sync duration histogram           |
| `ztap_policy_version_current`              | Current version of each policy           |
| `ztap_policy_enforcement_duration_seconds` | Policy enforcement duration histogram    |
| `ztap_policy_subscribers_active`           | Active policy subscribers count          |
| `ztap_flows_total`                         | Flow events by action/protocol/direction |

### Grafana Dashboard

```bash
docker-compose up -d  # Access at http://localhost:3000 (admin/ztap)
```

Dashboard auto-provisioned from `deployments/grafana-dashboard.json`

---

## Requirements

| Component      | Requirement                      | Notes                               |
| -------------- | -------------------------------- | ----------------------------------- |
| **OS**         | Linux (kernel ≥5.7) or macOS 12+ | Linux for production, macOS for dev |
| **Go**         | 1.24+                            | Build requirement                   |
| **eBPF Tools** | clang, llvm, make, linux-headers | Linux production only               |
| **Privileges** | Root or CAP_BPF + CAP_NET_ADMIN  | Linux eBPF enforcement              |
| **AWS**        | EC2/VPC access (optional)        | For cloud integration               |
| **Docker**     | Latest (optional)                | For Prometheus/Grafana stack        |
| **Python**     | 3.8+ (optional)                  | For anomaly detection service       |

**[Full eBPF Setup Guide](docs/ebpf.md)**

---

## Development

```bash
# Build
go build

# Run tests
go test ./...

# eBPF integration test (Linux + root required)
sudo go test -tags integration ./pkg/enforcer -run TestEBPFIntegrationLoadAndAttach -v

# Coverage
go test ./... -cover

# Lint
go fmt ./... && go vet ./...
```

### Demo

```bash
./demo.sh  # Interactive demo with RBAC, service discovery, and policy enforcement
```

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Acknowledgments

- [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) Zero Trust Architecture
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) specification
- [Cilium](https://cilium.io/) and [Tetragon](https://tetragon.io/) for eBPF inspiration
- [MITRE ATT&CK](https://attack.mitre.org/) framework

---

<div align="center">

**Note:** macOS enforcement (pf) is for development only. Use Linux + eBPF for production.

[eBPF Setup Guide](docs/ebpf.md) | [Get Started](docs/setup.md) | [Open an Issue](../../issues)

</div>

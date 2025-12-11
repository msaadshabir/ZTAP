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
# Linux (Production with eBPF)
sudo apt-get install clang llvm make linux-headers-$(uname -r)
cd bpf && make && cd ..

# Build and install
go build && sudo mv ztap /usr/local/bin/
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
ztap enforce -f examples/web-to-db.yaml

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
- **Bidirectional Enforcement** – Ingress and egress policies
- **RBAC** – Admin, Operator, Viewer roles
- **Session Management** – 24-hour TTL
- **Tamper-Proof Audit Logging** – Cryptographic hash chaining
- **NIST SP 800-207** compliant

### Distributed Architecture

- **Leader Election** – Automatic cluster coordination
- **Policy Synchronization** – Real-time policy distribution with auto-enforcement
- **Multi-Node Support** – High-availability deployments
- **Version Tracking** – Conflict-free policy updates
- **Prometheus Metrics** – 7 metrics for sync and enforcement monitoring

### Cloud Integration

- **AWS Security Groups** – Auto-sync policies
- **EC2 Auto-Discovery** – Tag-based labeling
- **Hybrid View** – Unified on-prem + cloud status

</td>
<td width="50%">

### Observability

- **Real-Time Flow Monitoring** – Stream network events via eBPF ring buffer
- **Prometheus Metrics** – Pre-built exporters
- **Grafana Dashboards** – Auto-provisioned
- **ML Anomaly Detection** – Isolation Forest
- **Structured Logs** – Filter & follow

### Developer Experience

- **Kubernetes-Style YAML** – Familiar syntax
- **Label-Based Discovery** – DNS + caching
- **79% Test Coverage** – Production-ready
- **Multi-Platform** – Linux (eBPF) + macOS (pf)

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
  enforce     Enforce zero-trust network policies
  status      Show on-premises and cloud resource status
  cluster     Manage cluster coordination (status, join, leave, list)
  policy      Distributed policy management (sync, list, watch, show)
  flows       Real-time flow event monitoring (--follow, --action, --protocol)
  logs        View enforcement logs (with --follow and --policy filters)
  metrics     Start Prometheus metrics server
  user        Manage users (create, login, list, change-password)
  discovery   Service discovery (register, resolve, list)
  audit       Audit log management (view, verify, stats)
```

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
  backend: dns   # inmemory (default) or dns
  dns:
    domain: example.com
  cache:
    ttl: 30s      # optional cache layer for the selected backend
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

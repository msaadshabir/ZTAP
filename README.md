# ZTAP: Zero Trust Access Platform

> Open-source zero-trust microsegmentation with eBPF enforcement, policy-as-code, and hybrid cloud support

[![Test Coverage](https://img.shields.io/badge/coverage-79%25-brightgreen.svg)](docs/TESTING_GUIDE.md)
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

**[Full Setup Guide](docs/setup.md)** | **[Architecture](docs/architecture.md)** | **[eBPF Setup](docs/EBPF.md)**

---

## Features

<table>
<tr>
<td width="50%">

### Security & Enforcement

- **Kernel-Level Filtering** – Real eBPF on Linux
- **RBAC** – Admin, Operator, Viewer roles
- **Session Management** – 24-hour TTL
- **NIST SP 800-207** compliant

### Cloud Integration

- **AWS Security Groups** – Auto-sync policies
- **EC2 Auto-Discovery** – Tag-based labeling
- **Hybrid View** – Unified on-prem + cloud status

</td>
<td width="50%">

### Observability

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
| [eBPF Enforcement](docs/EBPF.md)           | Linux kernel-level enforcement            |
| [Cluster Coordination](docs/CLUSTER.md)    | Multi-node clustering and leader election |
| [Testing Guide](docs/TESTING_GUIDE.md)     | Comprehensive testing documentation       |
| [Implementation Status](docs/STATUS.md)    | Project status and roadmap                |
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

**More examples in [examples/](examples/)**

---

## CLI Commands

```bash
ztap [command]

Commands:
  enforce     Enforce zero-trust network policies
  status      Show on-premises and cloud resource status
  cluster     Manage cluster coordination
  logs        View enforcement logs (with --follow and --policy filters)
  metrics     Start Prometheus metrics server
  user        Manage users (create, login, list, change-password)
  discovery   Service discovery (register, resolve, list)
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

</details>

---

## Observability

### Prometheus Metrics

| Metric                              | Description                   |
| ----------------------------------- | ----------------------------- |
| `ztap_policies_enforced_total`      | Number of policies enforced   |
| `ztap_flows_allowed_total`          | Allowed flows counter         |
| `ztap_flows_blocked_total`          | Blocked flows counter         |
| `ztap_anomaly_score`                | Current anomaly score (0-100) |
| `ztap_policy_load_duration_seconds` | Policy load time histogram    |

### Grafana Dashboard

```bash
docker-compose up -d  # Access at http://localhost:3000 (admin/ztap)
```

Dashboard auto-provisioned from `deployments/grafana-dashboard.json`

---

## ⚙️ Requirements

| Component      | Requirement                      | Notes                               |
| -------------- | -------------------------------- | ----------------------------------- |
| **OS**         | Linux (kernel ≥5.7) or macOS 12+ | Linux for production, macOS for dev |
| **Go**         | 1.22+                            | Build requirement                   |
| **eBPF Tools** | clang, llvm, make, linux-headers | Linux production only               |
| **Privileges** | Root or CAP_BPF + CAP_NET_ADMIN  | Linux eBPF enforcement              |
| **AWS**        | EC2/VPC access (optional)        | For cloud integration               |
| **Docker**     | Latest (optional)                | For Prometheus/Grafana stack        |
| **Python**     | 3.8+ (optional)                  | For anomaly detection service       |

**[Full eBPF Setup Guide](docs/EBPF.md)**

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

## Project Status

**Current Phase:** Production Ready (Core Components)

### Test Coverage

| Package         | Coverage  | Status               |
| --------------- | --------- | -------------------- |
| `pkg/auth`      | 72.4%     | Excellent            |
| `pkg/cloud`     | 90.0%     | Excellent            |
| `pkg/discovery` | 76.3%     | Excellent            |
| `pkg/metrics`   | 85.2%     | Excellent            |
| `pkg/policy`    | 73.6%     | Excellent            |
| `pkg/enforcer`  | N/A\*     | Linux-only           |
| **Core Avg**    | **79.5%** | **Production Ready** |

_\*Enforcer tests require Linux kernel_

---

## Roadmap

### Completed (Oct 2025)

<details>
<summary>View completed milestones</summary>

- **Phase 1:** Core Policy Enforcement (eBPF + pf)
- **Phase 2:** Service Discovery & RBAC Authentication
- **Phase 3:** Hybrid Cloud Integration (AWS)
- **Phase 4:** Observability & Testing (79% coverage)
- **Phase 5:** Anomaly Detection (ML-based)
- **eBPF Linux Verification** (GitHub Actions)
- **CI/CD Pipeline** (Multi-OS testing)
- **Containerization** (Docker Compose stack)
- **Distributed Architecture** (Cluster coordination)

</details>

### High Priority

- [ ] Real-time flow monitoring dashboard
- [ ] Advanced alerting (AlertManager integration)
- [ ] Pre-compiled eBPF binaries for common kernels

### Medium Priority

- [ ] Additional platform support (Windows, iptables)
- [ ] Enhanced security (2FA, cert-based auth)
- [ ] Enterprise features (LDAP, SAML/OAuth SSO)

**[Full Roadmap](docs/STATUS.md)**

---

## Contributing

We welcome contributions! Here's where to start:

**Good First Issues:**

- Add Python tests for anomaly detection
- Document AWS label-to-IP resolution workflow
- Create smoke tests for `ztap status`

**High Impact:**

- Real-time flow monitoring
- Advanced alerting
- Performance optimization

**Resources:**

- [Testing Guide](docs/TESTING_GUIDE.md)
- [Implementation Status](docs/STATUS.md)
- [eBPF Development](docs/EBPF.md)

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

[eBPF Setup Guide](docs/EBPF.md) | [Get Started](docs/setup.md) | [Open an Issue](../../issues)

</div>

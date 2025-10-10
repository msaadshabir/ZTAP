# ZTAP: Zero Trust Access Platform

A capstone project implementing zero-trust microsegmentation across hybrid environments (on-prem + cloud) using policy-as-code and OS-native enforcement.

## Features

- Unified policy language (YAML, Kubernetes-style)
- eBPF enforcement on Linux (cloud-native)
- pf (packet filter) fallback on macOS (local dev)
- AWS cloud integration (Security Group sync)
- Anomaly detection (ML-based via Python microservice)
- Prometheus metrics and Grafana dashboards
- Comprehensive logging and observability
- Hybrid-ready: Extendable to AWS/Azure
- Academic rigor: Implements NIST SP 800-207

## Quick Start

### Build and Install

```bash
go build
sudo mv ztap /usr/local/bin/
```

### Enforce a Policy

```bash
ztap enforce -f examples/web-to-db.yaml
```

### View Status

```bash
# Local system
ztap status

# With AWS resources
ztap status --aws --region us-east-1
```

### View Logs

```bash
# All logs
ztap logs

# Filter by policy
ztap logs --policy web-to-db

# Follow logs
ztap logs --follow
```

### Start Metrics Server

```bash
ztap metrics --port 9090
```

## Architecture

```
+----------------+     +---------------------+     +------------------+
|  Policy YAML   | --> |   Policy Engine     | --> |  OS Enforcer     |
| (K8s-style)    |     | (Parser + Resolver) |     | (eBPF / pf)      |
+----------------+     +---------------------+     +------------------+
                              |
                              v
                   +---------------------+
                   |  Cloud Integrator   | --> AWS Security Groups
                   +---------------------+
                              |
                              v
                   +---------------------+
                   |  Anomaly Detector   | --> Alerts
                   | (ML-based)          |
                   +---------------------+
```

## Documentation

- [Setup Guide](docs/setup.md) - Installation and configuration
- [Architecture](docs/architecture.md) - System design and components
- [Evaluation](docs/evaluation.md) - Testing and validation
- [Anomaly Detection](pkg/anomaly/README.md) - ML service setup

## Example Policies

### Web to Database (Label-based)

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

### PCI Compliant (IP-based)

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

See [examples/](examples/) for more policies.

## Observability

### Prometheus Metrics

- `ztap_policies_enforced_total` - Number of policies enforced
- `ztap_flows_allowed_total` - Allowed flows counter
- `ztap_flows_blocked_total` - Blocked flows counter
- `ztap_anomaly_score` - Current anomaly score (0-100)
- `ztap_policy_load_duration_seconds` - Policy load time histogram

### Grafana Dashboard

```bash
cd deployments
docker-compose up -d
# Access at http://localhost:3000 (admin/ztap)
```

## Commands

```bash
ztap [command]

Available Commands:
  enforce     Enforce zero-trust network policies
  status      Show status of on-premises and cloud resources
  logs        View enforcement logs
  metrics     Start Prometheus metrics server
  help        Help about any command

Flags:
  -h, --help   help for ztap
```

## Requirements

- **OS**: macOS 12+ or Linux (kernel ≥4.18)
- **Go**: 1.22+
- **Optional**: AWS account for cloud integration
- **Optional**: Docker for Prometheus/Grafana
- **Optional**: Python 3.8+ for anomaly detection

## Development

```bash
# Install dependencies
go mod download

# Build
go build

# Run tests (when implemented)
go test ./...

# Format code
go fmt ./...

# Lint
go vet ./...
```

## Project Status

### Phase 1: Core Policy Enforcement (COMPLETE)

- [x] Parse Kubernetes-style YAML policies
- [x] Enforce on Linux via eBPF (simulated)
- [x] Enforce on macOS via pf
- [x] CLI with enforce command

### Phase 2: Hybrid Cloud Integration (COMPLETE)

- [x] Sync policies to AWS Security Groups
- [x] Auto-discover AWS resources (EC2, VPCs)
- [x] Unified view with status command
- [x] Tag-based label matching

### Phase 3: Anomaly Detection (COMPLETE)

- [x] Monitor traffic flows
- [x] Flag deviations (ML-based)
- [x] Python microservice with Flask
- [x] Isolation Forest algorithm

### Phase 4: Observability & UX (COMPLETE)

- [x] Prometheus metrics exporter
- [x] Grafana dashboard
- [x] Human-readable logs
- [x] Log filtering and following

## License

MIT License - See [LICENSE](LICENSE) file

## Contributing

This is a capstone project. For questions or suggestions, please open an issue.

## Acknowledgments

- NIST SP 800-207 Zero Trust Architecture
- Kubernetes NetworkPolicy specification
- Cilium and Tetragon projects for inspiration
- MITRE ATT&CK framework

---

**Note**: This is an academic project demonstrating zero-trust concepts. The macOS enforcement requires sudo and is intended for development/testing only. Production deployments should use Linux with eBPF.

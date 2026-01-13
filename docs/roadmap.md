# Roadmap

## Delivered

- Policy definition, parsing, and validation (label-based and IP-based rules)
- Offline policy validation CLI (`ztap policy validate`)
- Linux enforcement via eBPF
- macOS enforcement via pf
- DNS and label-based service discovery
- Pod IP auto-discovery from K8s API
- Role-based access control (admin, operator, viewer)
- Session management with configurable lifetimes
- AWS Security Group synchronization
- Azure NSG synchronization
- EC2 discovery and tagging
- Prometheus metrics and Grafana dashboards
- Structured logging with filtering
- Python-based anomaly detection using Isolation Forest
- Tamper-evident audit log with SHA-256 hash chaining
- Audit CLI (`ztap audit view`, `verify`, `stats`)
- Leader election with in-memory and etcd backends
- Distributed policy synchronization
- Automatic enforcement on all nodes
- Policy version tracking (revision history)
- Policy rollback (creates a new latest revision)
- Ingress policy support (bidirectional enforcement)
- Real-time flow event monitoring (`ztap flows` with `--follow` streaming)
- Policy conflict detection (structural + overlap)
- REST API server (basic v1 endpoints via `ztap api serve`)
- gRPC interface (basic v1 RPCs via `ztap grpc serve`)
- TLS/HTTPS support for API and gRPC servers
- Alerting with webhook integrations (Slack, PagerDuty)
- GCP VPC Firewall Rules synchronization
- Kubernetes Operator with NetworkPolicy CRD
- Windows enforcement via Windows Filtering Platform (WFP) (experimental; Windows flow monitoring is WIP)
- iptables fallback for older Linux kernels
- Pre-compiled eBPF binaries (built with bpf2go)
- **Policy dry-run mode** - `ztap enforce --dry-run` to preview rules without applying
- **IPv6 support** - Extend eBPF and iptables enforcers to handle IPv6 CIDRs

## Planned

### Essential for Production Use

- **Policy validation CLI** - `ztap policy validate -f policy.yaml` for CI/CD pipelines
- **Graceful policy reload** - Update policies without dropping active connections
- **Persistent sessions** - Store auth sessions in a durable backend (SQLite/etcd)

### Operational Readiness

- **Health/readiness probes** - `/healthz` and `/readyz` endpoints for Kubernetes deployments
- **Configuration backup/restore** - Export and import policies, discovery state, and config
- **Rate limiting on APIs** - Prevent abuse on REST and gRPC endpoints
- **Windows flow monitoring** - Complete WFP flow event capture

### Compliance and Enterprise

- **Namespace/tenant isolation** - Multi-tenant policy scoping
- **Compliance report generation** - PCI-DSS, SOC2, HIPAA policy mapping exports
- **Certificate-based authentication** - mTLS client authentication for API access

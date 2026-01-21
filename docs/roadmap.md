# Roadmap

## Delivered

- Rate limiting on APIs - Prevent abuse on REST and gRPC endpoints (implemented; configurable; off by default)
- Policy definition, parsing, and validation (label-based and IP-based rules)
- Offline policy validation CLI (`ztap policy validate`)
- Linux enforcement via eBPF
- macOS enforcement via pf
- DNS and label-based service discovery
- Pod IP auto-discovery from K8s API
- Role-based access control (admin, operator, viewer)
- Session management with configurable lifetimes
- Persistent auth sessions stored in SQLite (default)
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
- **Health/readiness probes** - REST `GET /healthz` (liveness) and `GET /readyz` (readiness); gRPC exposes standard `grpc.health.v1.Health` (`Check`, `Watch`)
- **Policy dry-run mode** - `ztap enforce --dry-run` to preview rules without applying
- **IPv6 support** - Extend eBPF and iptables enforcers to handle IPv6 CIDRs
- **Graceful policy reload** - Update eBPF policies without dropping active connections via atomic `bpf_link` updates
- **Certificate-based authentication** - mTLS client authentication for API access (implemented for REST + gRPC; optional gate that still uses bearer-token RBAC on top)

## Planned

### Operational Readiness

- **Configuration backup/restore** - Export/import config bundles via REST (`POST /v1/config/backup`, `POST /v1/config/restore`) with `backup_restore` permission; current scope: auth users + sessions (SQLite), policy current snapshot (optional), config stub, discovery export not implemented yet
- **Windows flow monitoring** - Complete WFP flow event capture

### Compliance and Enterprise

- **Namespace/tenant isolation** - Multi-tenant policy scoping
- **Compliance report generation** - PCI-DSS, SOC2, HIPAA policy mapping exports

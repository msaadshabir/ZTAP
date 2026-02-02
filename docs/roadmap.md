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
- Configuration backup/restore via REST (`POST /v1/config/backup`, `POST /v1/config/restore`) with `backup_restore` permission (auth users + sessions (SQLite) + config stub; optional policy snapshot; discovery export not implemented yet)
- gRPC interface (basic v1 RPCs via `ztap grpc serve`)
- TLS/HTTPS support for API and gRPC servers
- Alerting with webhook integrations (Slack, PagerDuty)
- GCP VPC Firewall Rules synchronization
- Kubernetes Operator with NetworkPolicy CRD
- Windows enforcement via Windows Filtering Platform (WFP) (experimental)
- Windows flow monitoring via WFP NetEvents (ztap-only; requires Administrator)
- iptables fallback for older Linux kernels
- Pre-compiled eBPF binaries (built with bpf2go)
- **Health/readiness probes** - REST `GET /healthz` (liveness) and `GET /readyz` (readiness); gRPC exposes standard `grpc.health.v1.Health` (`Check`, `Watch`)
- **Policy dry-run mode** - `ztap enforce --dry-run` to preview rules without applying
- **IPv6 support** - Extend eBPF, iptables, and Windows WFP enforcers to handle IPv6 CIDRs
- **CIDR + ICMP parity** - Support arbitrary CIDRs and ICMP/ICMPv6 consistently across Linux (eBPF/iptables) and Windows (WFP)
- **Graceful policy reload** - Update eBPF policies without dropping active connections via atomic `bpf_link` updates
- **Certificate-based authentication** - mTLS client authentication for API access (implemented for REST + gRPC; optional gate that still uses bearer-token RBAC on top)
- **Namespace/tenant isolation** - Multi-tenant policy scoping
- **Compliance report generation** - PCI-DSS, SOC2, HIPAA policy mapping exports
- Improve label-based enforcement outside Kubernetes agent mode (automatic selector resolution and re-resolution over time).
- Kubernetes NetworkPolicy parity extensions: `namespaceSelector`, `matchExpressions`, `ipBlock.except`, named ports, and port ranges.
- Ship a complete, production-ready Kubernetes install bundle (RBAC + agent DaemonSet + operator) and add dedicated unit tests for the operator reconcile loop. (DONE: see `deployments/kubernetes/ztap-install.yaml` and `pkg/operator/controllers/ztapnetworkpolicy_controller_test.go`)
- Add first-class CLI workflows for AWS Security Group sync (and inventory-based label resolution), and expand `ztap status` coverage for Azure/GCP.

## Planned

### Cloud Integrations

- Add first-class CLI workflows for AWS Security Group sync (and inventory-based label resolution), and expand `ztap status` coverage for Azure/GCP.

### Backup/Restore & Management Plane

- Implement full backup/restore coverage (policies: current + revisions, discovery snapshot, effective config) instead of best-effort partial restores.
- Expand REST/gRPC APIs beyond the current minimal surface (policy CRUD/history, user/role management, cluster operations).

### Cluster (Production)

- Add an etcd-backed PolicySync backend (store current policy + revisions in etcd; real multi-node distribution) and wire the CLI/runtime to use it instead of in-memory-only sync.

### Runtime / Daemonization

- Provide a long-running daemon/service mode (systemd/launchd/Windows service) so enforcement and cluster coordination survive process exits/reboots.

### macOS pf Hardening

- Make pf enforcement production-grade (apply/reload via pfctl, safe anchor management, and clean teardown/uninstall without leaving pf.conf modifications behind).

### Audit Log Hardening

- Strengthen audit log integrity guarantees beyond hash chaining (detect truncation, add HMAC/signing, and optionally support external anchoring or remote append-only sinks).

### Project Hygiene (Security Tooling)

- Add `SECURITY.md` (vulnerability reporting + supported versions), plus CONTRIBUTING / Code of Conduct / CHANGELOG for maintainability.

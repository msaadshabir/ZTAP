# Project Status

Current state of the ZTAP project: what has been delivered and what is planned.

## Delivered

- Policy definition, parsing, and validation (label-based and IP-based rules)
- Offline policy validation CLI (`ztap policy validate`)
- Linux enforcement via eBPF (pre-compiled binaries via bpf2go)
- iptables fallback for older Linux kernels
- macOS enforcement via pf
- Windows enforcement via Windows Filtering Platform (WFP) (experimental)
- Windows flow monitoring via WFP NetEvents
- Graceful policy reload via atomic `bpf_link` updates (zero-downtime)
- IPv6 support across eBPF, iptables, and WFP enforcers
- Arbitrary CIDRs and ICMP/ICMPv6 parity across all enforcers
- Policy dry-run mode (`ztap enforce --dry-run`)
- Bidirectional enforcement (ingress and egress)
- Policy conflict detection (structural + overlap)
- Policy version tracking, revision history, and rollback
- Namespace/tenant isolation (multi-tenant policy scoping)
- Kubernetes NetworkPolicy parity: `namespaceSelector`, `matchExpressions`, `ipBlock.except`, named ports, port ranges
- Kubernetes Operator with NetworkPolicy CRD and production install bundle
- DNS and label-based service discovery with Pod IP auto-discovery from K8s API
- Automatic selector resolution and re-resolution over time
- Leader election with in-memory and etcd backends
- Distributed policy synchronization with automatic enforcement
- etcd-backed PolicySync backend
- REST API server (`ztap api serve`) with policy CRUD, user/role management, cluster operations
- gRPC API server (`ztap grpc serve`) with equivalent RPCs
- Health/readiness probes (REST `/healthz`, `/readyz`; gRPC `grpc.health.v1.Health`)
- TLS/HTTPS and mTLS client certificate authentication
- Rate limiting on REST and gRPC endpoints
- Configuration backup/restore via REST
- Role-based access control (admin, operator, viewer)
- Session management with configurable lifetimes (SQLite default)
- Tamper-evident audit log with SHA-256 hash chaining, optional HMAC/Ed25519 signing, and checkpoints
- Audit CLI (`ztap audit view`, `verify`, `stats`, `keygen`)
- Compliance report generation (PCI-DSS, SOC2, HIPAA mapping exports)
- AWS Security Group synchronization with EC2 inventory export and selector/IP resolution
- Azure NSG synchronization
- GCP VPC Firewall Rules synchronization
- Expanded `ztap status` cloud coverage (Azure NSG, GCP firewall summaries)
- Real-time flow event monitoring (`ztap flows --follow`)
- Prometheus metrics and Grafana dashboards
- Alerting with webhook integrations (Slack, PagerDuty)
- Python-based anomaly detection using Isolation Forest
- Structured logging with filtering
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

## Current Focus

Documentation overhaul and bug fixes to stabilize the project. No new feature work is planned at this time.

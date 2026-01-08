# Roadmap

## Delivered

- Policy definition, parsing, and validation (label-based and IP-based rules)
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
- Alerting with webhook integrations (Slack, PagerDuty)
- GCP VPC Firewall Rules synchronization
- Kubernetes Operator with NetworkPolicy CRD
- Windows enforcement via Windows Filtering Platform (WFP) (experimental; Windows flow monitoring is WIP)
- iptables fallback for older Linux kernels

## Planned

### P0: Essential for Production Use

- **Persistent session storage** - Sessions are in-memory only; server restart loses all sessions. Add SQLite/PostgreSQL backend.
- **Pre-compiled eBPF binaries** - Remove clang/llvm build dependency for Linux deployment
- **Policy dry-run mode** - Show what rules would be applied without enforcement (partial support exists but needs completion)
- **Health checks and readiness probes** - Kubernetes-native liveness/readiness endpoints for reliable deployments
- **Graceful shutdown** - Clean detachment of eBPF programs and WFP filters on SIGTERM

### P1: Required for Team/Enterprise Adoption

- **Policy validation CLI** - `ztap policy validate -f policy.yaml` for CI/CD pipelines without enforcement
- **Policy diff command** - Show changes between policy versions before rollback
- **Backup and restore** - Export/import policies, users, and audit logs
- **TLS for API servers** - HTTPS for REST and TLS for gRPC (currently plaintext only)
- **OAuth/OIDC and SAML SSO** - Enterprise identity provider integration
- **LDAP/Active Directory integration** - Corporate directory support
- **2FA/MFA authentication** - Additional security for admin access

### P2: Operational Excellence

- **Web UI for policy management** - Visual policy editor and enforcement status dashboard
- **Network segmentation visualization** - Graph view of allowed/blocked flows
- **Compliance reporting (PCI-DSS, SOC2, HIPAA)** - Automated compliance posture reports
- **Certificate-based authentication** - mTLS for machine-to-machine auth
- **Namespace/tenant isolation** - Multi-tenant policy separation
- **Distributed rate limiting** - Cluster-wide rate limiting coordination

### P3: Advanced Features

- **Policy simulation mode** - Replay captured flows against new policies
- **Automatic policy generation** - Learn baseline from observed flows
- **Integration with service meshes** - Envoy/Istio sidecar coordination
- **Windows flow monitoring** - Complete WFP flow event capture (currently WIP)
- **IPv6 enforcement** - Currently IPv4 only for eBPF/WFP enforcers

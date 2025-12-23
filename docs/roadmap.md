# Roadmap

## Delivered

- Policy definition, parsing, and validation (label-based and IP-based rules)
- Linux enforcement via eBPF
- macOS enforcement via pf
- DNS and label-based service discovery
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

## Planned

- GCP Firewall Rules integration
- Kubernetes Operator with NetworkPolicy CRD
- Pod IP auto-discovery from K8s API
- Windows support via Windows Filtering Platform
- iptables fallback for older Linux kernels
- Pre-compiled eBPF binaries
- 2FA/MFA authentication
- Certificate-based authentication
- OAuth/OIDC and SAML SSO
- LDAP/Active Directory integration
- Distributed rate limiting
- Web UI for policy management
- Namespace/tenant isolation
- Compliance reporting (PCI-DSS, SOC2, HIPAA)
- Network segmentation visualization

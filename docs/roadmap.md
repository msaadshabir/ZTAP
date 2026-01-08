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

### Essential for Production Use

- **Pre-compiled eBPF binaries** - Remove clang/llvm build dependency for Linux deployment
- **TLS for API servers** - HTTPS for REST and TLS for gRPC
- **Policy validation CLI** - `ztap policy validate -f policy.yaml` for CI/CD pipelines

### Future Enhancements

- **Web UI for policy management** - Visual policy editor and enforcement status dashboard
- **Windows flow monitoring** - Complete WFP flow event capture

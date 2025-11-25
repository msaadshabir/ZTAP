# Project Status

ZTAP has a production-ready core with capabilities in cluster operations, observability, and security.

## Delivered Capabilities

### Core

- Policy definition, parsing, and validation (label-based and IP-based rules)
- Linux enforcement via eBPF
- macOS enforcement via pf

### Service Discovery and Access Control

- DNS and label-based service discovery
- Role-based access control (admin, operator, viewer)
- Session management with configurable lifetimes

### Cloud Integration

- AWS Security Group synchronization
- EC2 discovery and tagging

### Observability

- Prometheus metrics and Grafana dashboards
- Structured logging with filtering

### Anomaly Detection

- Python-based microservice using Isolation Forest

### Audit Logging

- Tamper-evident log with SHA-256 hash chaining
- Query and verification CLI (`ztap audit view`, `verify`, `stats`)

### Cluster and Policy Sync

- Leader election with in-memory and etcd backends
- etcd backend for production cluster deployments
- Distributed policy synchronization
- Automatic enforcement on all nodes
- Policy version tracking

## Near-Term Focus

- Real-time flow event monitoring across cluster nodes
- Distributed rate limiting and quota management
- Policy conflict detection for multi-tenant scenarios

## Related Documentation

- [Cluster](cluster.md) - Distributed coordination and policy sync
- [etcd Setup](etcd.md) - Production backend configuration
- [Audit](audit.md) - Audit logging system

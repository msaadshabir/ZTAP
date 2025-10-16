# Project Status

_Last updated: October 16, 2025_

## Phase Overview

| Phase    | Scope                              | Status      | Notes                                                                                     |
| -------- | ---------------------------------- | ----------- | ----------------------------------------------------------------------------------------- |
| Phase 1  | Core Policy Enforcement            | ✅ Complete | Parsing, validation, and Linux/macOS enforcement paths shipped.                           |
| Phase 2  | Service Discovery & Authentication | ✅ Complete | DNS + label resolution and RBAC finished.                                                 |
| Phase 3  | Hybrid Cloud Integration           | ✅ Complete | AWS Security Group sync and discovery validated.                                          |
| Phase 4  | Observability & Testing            | ✅ Complete | Prometheus/Grafana plus expanded coverage.                                                |
| Phase 5  | Anomaly Detection                  | ✅ Complete | Python microservice + ML detection live.                                                  |
| Critical | eBPF Verification on Linux         | ✅ Complete | Automated integration test ensures filter load, cgroup attach, and policy map population. |
| Medium   | Distributed Architecture           | ✅ Complete | Cluster coordination foundation with leader election backend.                             |

## Recent Highlights

### Cluster Coordination (Oct 16, 2025)

- Added cluster package (`pkg/cluster`) with leader election interface and in-memory backend.
- Lexicographic leader election: first healthy node becomes leader.
- Node registration, deregistration, and health monitoring via periodic heartbeats.
- Event-driven watcher API for cluster state and leader changes.
- CLI commands: `ztap cluster status`, `ztap cluster join`, `ztap cluster leave`, `ztap cluster list`.
- Comprehensive unit tests covering all major scenarios (10+ test cases, all passing).
- Foundation for future etcd/Raft backends and distributed policy synchronization.

### eBPF Verification (Oct 15, 2025)

- Added Linux-only integration test `TestEBPFIntegrationLoadAndAttach` (tagged `integration`) that recompiles `bpf/filter.o`, attaches to a temporary cgroup, and asserts policy map entries.
- CI workflow now runs an "eBPF Verification (Linux)" job on Ubuntu to compile the program and execute the integration test with `sudo`.
- Fixed kernel header path issue in bpf/Makefile: added missing architecture-specific generated uapi headers.
- Documentation updates describe how to run the verification test locally (`README.md`, `docs/EBPF.md`, `docs/TESTING_GUIDE.md`).

## Next Up

- Implement distributed policy synchronization on top of cluster foundation.
- Add etcd backend for production multi-node deployments.
- Extend cluster support to monitor real-time flow events across nodes.
- Add Prometheus metrics for cluster health (nodes total, leader elections, heartbeat latency).
- Investigate `TestCLIMetrics` timeout on macOS to restore `go test ./...` parity across platforms.

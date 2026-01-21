# ZTAP Documentation

Technical documentation for ZTAP.

## Core Documentation

| Document                        | Description                          |
| ------------------------------- | ------------------------------------ |
| [Architecture](architecture.md) | System design and component overview |
| [Setup Guide](setup.md)         | Installation and configuration       |
| [eBPF Setup](ebpf.md)           | Linux eBPF enforcement               |
| [Testing Guide](testing.md)     | Test suite and coverage              |

## Operations

| Document                    | Description                                                 |
| --------------------------- | ----------------------------------------------------------- |
| [Deployment](deployment.md) | Docker and containerized deployment                         |
| [Cluster](cluster.md)       | Distributed coordination and policy sync (history/rollback) |
| [etcd Setup](etcd.md)       | etcd backend for production clusters                        |
| [Audit Logging](audit.md)   | Tamper-proof audit system                                   |

## Reference

| Document                                      | Description                    |
| --------------------------------------------- | ------------------------------ |
| [Roadmap](roadmap.md)                         | Delivered and planned features |
| [Examples](../examples/)                      | Sample policies and use cases  |
| [Anomaly Detection](../pkg/anomaly/README.md) | ML service API                 |

## API Server

ZTAP includes a minimal REST API server and a minimal gRPC API server.

- Start: `ztap api serve`
- Start (gRPC): `ztap grpc serve`
- Configure: set `api.listen` and `api.auth.enabled` in `config.yaml` (see `config.yaml.example`)
- Configure (gRPC): set `grpc.listen` and `grpc.auth.enabled` in `config.yaml`
- Sessions: persistent by default (SQLite at `~/.ztap/sessions.db`); configure via `auth.sessions.*` in `config.yaml.example`

## Alerting

ZTAP supports webhook alerting via Slack and PagerDuty.

- Configure: set `alerting.enabled` and `alerting.slack.webhook_url` / `alerting.pagerduty.routing_key` in `config.yaml` (see `config.yaml.example`)
- Test: `ztap alert test`

Core endpoints:

- `GET /healthz` (liveness)
- `GET /readyz` (readiness)
- `POST /v1/auth/login` (body: `{ "username": "...", "password": "..." }`)
- `GET /v1/auth/whoami` (requires `Authorization: Bearer <token>`)
- `POST /v1/config/backup` (download a `.tar.gz` backup bundle; requires `backup_restore`)
- `POST /v1/config/restore?dry_run=1&force=1` (upload a `.tar.gz` backup bundle; requires `backup_restore`)
- `GET /v1/status`
- `GET /v1/enforcement/status`
- `POST /v1/enforcement/start` (body includes `policy_yaml`)
- `POST /v1/enforcement/stop` (Linux only)
- `GET /v1/flows/stream` (SSE stream)
- `GET /metrics`

Config backup/restore notes:

- `POST /v1/config/backup` accepts an optional JSON body with include flags. Defaults (Option B) include only stable/implemented exports: users, sessions, config stub.
- Export is best-effort; skipped components are recorded in `manifest.warnings` inside the bundle.
- `POST /v1/config/restore` supports `dry_run=1` (plan only) and `force=1` (apply even if files will be overwritten). Without `force=1`, destructive restores return `409`.
- Restore uploads are size-capped (default: 100 MiB); oversized uploads return `413`.
- A restart is required after applying a restore.

Notes:

- `/healthz` and `/readyz` are unauthenticated and intended for Kubernetes probes.
- `/readyz` returns `503` when dependencies (auth store, audit logger) are not ready.

gRPC services (v1):

- `ztap.api.v1.AuthService` (`Login`, `WhoAmI`)
- `ztap.api.v1.StatusService` (`GetStatus`)
- `ztap.api.v1.EnforcementService` (`GetStatus`, `Start`, `Stop`)
- `ztap.api.v1.FlowsService` (`Stream` server-streaming)

gRPC health:

- Standard `grpc.health.v1.Health` is exposed (`Check`, `Watch`) and does not require auth metadata.

Auth: send `authorization: Bearer <token>` as gRPC metadata.

See the [main README](../README.md) for project overview and quick start.

## Azure NSG Sync

ZTAP can reconcile NetworkPolicy objects into Azure NSG security rules:

- Command: `ztap azure nsg-sync <policy-file> --subscription-id ... --resource-group ... --nsg ...`
- Config: see `azure.*` in `config.yaml.example`

## GCP Firewall Sync

ZTAP can reconcile NetworkPolicy objects into GCP VPC firewall rules (using Application Default Credentials).

- Command: `ztap gcp firewall-sync <policy-file> --project-id ... --network ...`
- Flags: `--dry-run`, `--watch`, `--watch-interval`
- Config: see `gcp.*` in `config.yaml.example`

Label-based rules:

- `podSelector.matchLabels` targets are resolved against GCE instance labels within the specified VPC network.

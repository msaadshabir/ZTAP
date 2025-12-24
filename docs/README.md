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

## Alerting

ZTAP supports webhook alerting via Slack and PagerDuty.

- Configure: set `alerting.enabled` and `alerting.slack.webhook_url` / `alerting.pagerduty.routing_key` in `config.yaml` (see `config.yaml.example`)
- Test: `ztap alert test`

Core endpoints:

- `POST /v1/auth/login` (body: `{ "username": "...", "password": "..." }`)
- `GET /v1/auth/whoami` (requires `Authorization: Bearer <token>`)
- `GET /v1/status`
- `GET /v1/enforcement/status`
- `POST /v1/enforcement/start` (body includes `policy_yaml`)
- `POST /v1/enforcement/stop` (Linux only)
- `GET /v1/flows/stream` (SSE stream)
- `GET /metrics`

gRPC services (v1):

- `ztap.api.v1.AuthService` (`Login`, `WhoAmI`)
- `ztap.api.v1.StatusService` (`GetStatus`)
- `ztap.api.v1.EnforcementService` (`GetStatus`, `Start`, `Stop`)
- `ztap.api.v1.FlowsService` (`Stream` server-streaming)

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

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

| Document                    | Description                              |
| --------------------------- | ---------------------------------------- |
| [Deployment](deployment.md) | Docker and containerized deployment      |
| [Cluster](cluster.md)       | Distributed coordination and policy sync |
| [etcd Setup](etcd.md)       | etcd backend for production clusters     |
| [Audit Logging](audit.md)   | Tamper-proof audit system                |

## Reference

| Document                                      | Description                    |
| --------------------------------------------- | ------------------------------ |
| [Roadmap](roadmap.md)                         | Delivered and planned features |
| [Examples](../examples/)                      | Sample policies and use cases  |
| [Anomaly Detection](../pkg/anomaly/README.md) | ML service API                 |

## API Server

ZTAP includes a minimal REST API server.

- Start: `ztap api serve`
- Configure: set `api.listen` and `api.auth.enabled` in `config.yaml` (see `config.yaml.example`)

Core endpoints:

- `POST /v1/auth/login` (body: `{ "username": "...", "password": "..." }`)
- `GET /v1/auth/whoami` (requires `Authorization: Bearer <token>`)
- `GET /v1/status`
- `GET /v1/enforcement/status`
- `POST /v1/enforcement/start` (body includes `policy_yaml`)
- `POST /v1/enforcement/stop` (Linux only)
- `GET /v1/flows/stream` (SSE stream)
- `GET /metrics`

See the [main README](../README.md) for project overview and quick start.

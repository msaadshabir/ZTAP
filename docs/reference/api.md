# API Reference

REST and gRPC API surfaces for ZTAP. Sources: [`docs/openapi.yaml`](../openapi.yaml), [`proto/ztap/api/v1/api.proto`](../../proto/ztap/api/v1/api.proto).

## REST API

Default listen: `127.0.0.1:8080` (see [Configuration Reference](config.md)).

### Authentication

Most endpoints require a bearer token obtained from `POST /v1/auth/login`.

```
Authorization: Bearer <token>
```

### Health

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/healthz` | No | Liveness probe |
| `GET` | `/readyz` | No | Readiness probe (503 when dependencies not ready) |

### Auth

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/v1/auth/login` | No | Authenticate and create session |
| `GET` | `/v1/auth/whoami` | Yes | Return authenticated user info |

### Status

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/v1/status` | Yes | Process status |

### Enforcement

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/v1/enforcement/status` | Yes | Enforcement status |
| `POST` | `/v1/enforcement/start` | Yes | Start enforcement (body: `policy_yaml`) |
| `POST` | `/v1/enforcement/stop` | Yes | Stop enforcement (Linux only) |

### Flows

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/v1/flows/stream` | Yes | Server-Sent Events stream of flow events |

### Config Backup/Restore

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/v1/config/backup` | `backup_restore` | Download `.tar.gz` backup bundle |
| `POST` | `/v1/config/restore` | `backup_restore` | Upload `.tar.gz` bundle; query params: `dry_run`, `force` |

### Compliance

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/v1/compliance/report` | `view_compliance` | Generate compliance report |
| `POST` | `/v1/compliance/export` | `view_compliance` | Export compliance data (JSON/CSV) |

### Policies

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/v1/policies` | Yes | List policies (optional `?tenant=`) |
| `GET` | `/v1/policies/{tenant}/{name}` | Yes | Get a policy |
| `PUT` | `/v1/policies/{tenant}/{name}` | Yes | Create or update a policy |
| `DELETE` | `/v1/policies/{tenant}/{name}` | Yes | Delete a policy |
| `GET` | `/v1/policies/{tenant}/{name}/revisions` | Yes | List revisions |
| `GET` | `/v1/policies/{tenant}/{name}/revisions/{version}` | Yes | Get a specific revision |
| `POST` | `/v1/policies/{tenant}/{name}/rollback` | Yes | Rollback to a prior version |

### Users

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/v1/users` | Yes | List users |
| `POST` | `/v1/users` | Yes | Create user |
| `GET` | `/v1/users/{username}` | Yes | Get user |
| `PATCH` | `/v1/users/{username}` | Yes | Update user |
| `DELETE` | `/v1/users/{username}` | Yes | Delete user |
| `POST` | `/v1/users/{username}/password` | Yes | Set user password |

### Cluster

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/v1/cluster/status` | Yes | Cluster status |
| `GET` | `/v1/cluster/nodes` | Yes | List nodes |
| `POST` | `/v1/cluster/nodes` | Yes | Register a node |
| `DELETE` | `/v1/cluster/nodes/{id}` | Yes | Deregister a node |

### Metrics

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/metrics` | Conditional | Prometheus metrics (requires `view_metrics` when auth enabled) |

### Rate Limiting

When rate limiting is enabled (`api.rate_limit.enabled: true` or `--rate-limit`):

- Exceeded limits return HTTP `429` with `Retry-After` header and `{"error":"rate_limited"}`.
- `/healthz`, `/readyz`, and `/metrics` are always exempt.
- Invalid/expired tokens fall back to the unauthenticated bucket.

---

## gRPC API

Default listen: `127.0.0.1:9092`. Auth: send `authorization: Bearer <token>` as gRPC metadata.

### Error Handling

gRPC handlers return sanitized error messages using standard gRPC status codes. Internal error details are logged server-side but never exposed to clients. For example, an internal failure during enforcement returns `status.Error(codes.Internal, "enforcement failed")` rather than the raw error string. This prevents leaking implementation details to API consumers.

### Services

| Service | RPCs |
| --- | --- |
| `ztap.api.v1.AuthService` | `Login`, `WhoAmI` |
| `ztap.api.v1.StatusService` | `GetStatus` |
| `ztap.api.v1.EnforcementService` | `GetStatus`, `Start`, `Stop` |
| `ztap.api.v1.FlowsService` | `Stream` (server-streaming) |
| `ztap.api.v1.PolicyService` | `ListPolicies`, `GetPolicy`, `PutPolicy`, `DeletePolicy`, `ListPolicyRevisions`, `GetPolicyRevision`, `RollbackPolicy` |
| `ztap.api.v1.UsersService` | `ListUsers`, `GetUser`, `CreateUser`, `UpdateUser`, `SetUserPassword`, `DeleteUser` |
| `ztap.api.v1.ClusterService` | `GetClusterStatus`, `ListNodes`, `RegisterNode`, `DeregisterNode` |
| `grpc.health.v1.Health` | `Check`, `Watch` (no auth required) |

### Rate Limiting

When rate limiting is enabled (`grpc.rate_limit.enabled: true` or `--rate-limit`):

- Exceeded limits return `RESOURCE_EXHAUSTED` with `RetryInfo`.
- Health RPCs (`/grpc.health.v1.Health/*`) are always exempt.

---

## OpenAPI Spec

The full OpenAPI 3.0.3 specification is maintained at [`docs/openapi.yaml`](../openapi.yaml).

## Proto Definition

The gRPC service definitions are at [`proto/ztap/api/v1/api.proto`](../../proto/ztap/api/v1/api.proto).

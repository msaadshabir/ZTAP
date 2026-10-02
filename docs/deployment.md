# Deployment

ZTAP is deployed as one Linux DaemonSet. The maintained manifest is
[`deployments/kubernetes/ztap-agent.yaml`](../deployments/kubernetes/ztap-agent.yaml).
Its `ztap:v0.1.0` image is a local-build placeholder; published releases attach
a separate manifest with the immutable image digest.

## Requirements

- Linux nodes with cgroup v2 and a mounted bpffs at `/sys/fs/bpf`.
- containerd configured to use the systemd cgroup driver; cgroupfs, cgroup v1,
  Docker Engine, and CRI-O layouts are unsupported.
- Kubernetes 1.36.x (CI uses `kindest/node:v1.36.4`) with a CNI that does not
  enforce NetworkPolicy. ZTAP does not disable another NetworkPolicy
  implementation; running both produces intersected enforcement and is
  outside the first-release support contract.
- Kubernetes access for the agent ServiceAccount to read Nodes, Namespaces,
  Pods, and NetworkPolicies.
- Every non-host-network Pod in the cluster must explicitly drop `NET_RAW`
  (or `ALL`), set `allowPrivilegeEscalation: false`, and avoid privileged mode
  and added `NET_RAW` or `SYS_ADMIN`. This applies to regular, init, sidecar,
  and ephemeral containers, including non-host-network system workloads.
  The install manifest includes a cluster-wide, fail-closed
  `ValidatingAdmissionPolicy` and binding enforcing this prerequisite.
- Linux amd64 or arm64 nodes with the eBPF capabilities required by the
  kernel and runtime. The recorded release kernel is `6.17.0-1022-azure`;
  see [the reference environment](performance.md#published-v010-results).
- `kubectl` and `curl` on the machine used to install the agent.

The agent does not share the host network, PID, or IPC namespaces. It mounts
the host cgroup hierarchy read-only, while bpffs and `/run/ztap` are writable
for the engine's pinned state and process-owned runtime directory. It runs as
UID 0 without privileged mode or privilege escalation, drops all capabilities
first, and adds only `BPF`, `NET_ADMIN`, `PERFMON`, and `SYS_RESOURCE`. The root
filesystem is read-only.

## Install

The `v0.1.1` release includes the packet-socket admission guard and
connection-state fixes. Update workload templates and recreate unsafe Pods
as described below before installing it. The historical `v0.1.0` assets
predate these fixes.

Download the `v0.1.1` install manifest, inspect it, then apply it:

```sh
curl -fL -o ztap-agent-v0.1.1.yaml \
  https://github.com/saadshabir/ZTAP/releases/download/v0.1.1/ztap-agent-v0.1.1.yaml
kubectl apply -f ztap-agent-v0.1.1.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
kubectl -n ztap-system get pods -l app=ztap-agent -o wide
```

The [release asset](https://github.com/saadshabir/ZTAP/releases/download/v0.1.1/ztap-agent-v0.1.1.yaml)
pins `ghcr.io/saadshabir/ztap` to the immutable multi-architecture image digest
verified by the release workflow.

Check that an agent is Ready on each intended node. Then validate and apply
your native `NetworkPolicy` documents; see [policy examples](policies.md#examples).

### Build your own image

To deploy a source build, publish it to a registry reachable by your nodes:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v0.1.1 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --tag your-registry/ztap:v0.1.1 \
  --push .
```

Replace `your-registry` with your registry path. Change the source manifest's
`image` field from `ztap:v0.1.0` to your published image, preferably by digest,
then run:

```sh
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent
kubectl -n ztap-system get pods -o wide
```

Update existing workload templates before installing the manifest. For each
container, the minimum packet-socket restriction is:

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop: [NET_RAW]
```

Admission checks future Pod creation and ephemeral-container updates; it does
not change existing Pods. Recreate existing unsafe Pods after updating their
templates. The agent also audits the current Pod snapshot and refuses to
report enforcement readiness when any non-terminal, non-host-network Pod
violates this prerequisite. Readiness does not retroactively prevent unsafe
existing Pods from sending traffic. Static Pods must satisfy the same
restriction in their node-local manifests because API admission cannot
control their creation.

This restriction is necessary because Linux `AF_PACKET` sockets bypass
`cgroup_skb` filtering. Host-network workloads remain outside ZTAP's subject
set. Administrators must retain the admission policy and binding while ZTAP
is deployed; removing them admits workloads that the packet hooks cannot
enforce.

The image is built `CGO_ENABLED=0` from `scratch`. It contains the ZTAP binary
and CA certificates only; use Kubernetes logs, probes, port forwarding, and
node diagnostics rather than expecting a shell inside the container.

`make docker` builds a local `ztap:dev` image only. It neither pushes an image
nor changes the manifest; the local tag also differs from the manifest's
placeholder. Load and retag the image explicitly for a disposable local
cluster, or use the registry path above.

## Upgrade

Download the next release's digest-pinned manifest, or update your source
manifest to the new immutable digest. Apply that file (replace the filename
below with the one you prepared):

```sh
kubectl apply -f next-ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
kubectl -n ztap-system get pods -l app=ztap-agent -o wide
```

The rolling update uses `maxUnavailable: 1` and `maxSurge: 0`, but links are
process-owned. The node being updated therefore has a measured fail-open
interval between the old agent exiting and the replacement completing its
first successful reconciliation. Check `/readyz` and the agent logs after the
rollout; readiness does not prevent that interval.

A SIGKILL crash has the same process-owned link behavior. The crash interval
is measured separately from orderly restart and DaemonSet rollout; none of
these intervals are zero-gap availability guarantees.

### Measured fail-open intervals

The [published release evidence](performance.md#published-v010-results)
on Linux `6.17.0-1022-azure` recorded these separate boundaries for the
250-Pod/25-policy/2,500-rule fixture:

| Boundary | Measurement | What was observed |
| --- | ---: | --- |
| Pod start to classification | 103.284 ms p95 | Newly Running Pod appeared in a synchronized fake informer cache with its cgroup already present; API-server and runtime startup are excluded. |
| Orderly agent shutdown through replacement apply | 314.103 ms p95 | Process-owned links closed, then a new native agent applied the fixture. |
| SIGKILL to first allowed packet | 3.453 ms p95 | A link-owning child process was killed; this measures when fail-open begins, not when Kubernetes recovers. |
| Planned DaemonSet replacement | 1,652 ms | In kind, the selected smoke client first became allowed and was then blocked again on the same node. The replacement Pod was observed Running inside the interval and confirmed Ready. |

The failed-update Linux test separately preserved the active policy on an
already classified cgroup after an injected candidate-link failure. A newly
created cgroup had no link and sent an allowed packet until a controlled
retry classified it. The first allowed probe to the blocked probe after retry
spanned 2,056.943 ms in that test. This is a probe-to-retry measurement, not a
bound on Kubernetes watcher delay or failure recovery. A selected container
can also send before its ID and cgroup become visible to the watcher.

## Agent flags

The DaemonSet starts the equivalent of:

```sh
ztap agent \
  --node-name="$NODE_NAME" \
  --cgroup-root=/host/sys/fs/cgroup \
  --bpffs-root=/host/sys/fs/bpf \
  --run-dir=/run/ztap \
  --listen=:9090
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--node-name` | Required | Exact Kubernetes node name; supplied by the Downward API in the manifest |
| `--kubeconfig` | Empty | Uses in-cluster credentials; pass a file path for a node-local development run |
| `--cgroup-root` | `/sys/fs/cgroup` | Cgroup v2 root; manifest overrides it to `/host/sys/fs/cgroup` |
| `--bpffs-root` | `/sys/fs/bpf` | Mounted bpffs root; manifest overrides it to `/host/sys/fs/bpf` |
| `--run-dir` | `/run/ztap` | Shared node-agent and flow-reader lock directory |
| `--listen` | `:9090` | Health, readiness, and metrics listener |
| `--dry-run` | `false` | Compiles snapshots without loading or attaching eBPF; never reports enforcement readiness |

The status listener has no authentication. Restrict access through the cluster
network configuration or choose a narrower listen address for development.
Run `ztap agent --help` for the current flags; global logging flags apply too.

## Health and metrics

- `GET /healthz` reports process health.
- `GET /readyz` reports active enforcement readiness.
- `GET /metrics` exposes Prometheus text metrics.

These endpoints accept `GET` only; other methods receive `405 Method Not
Allowed`. During graceful shutdown, `/readyz` changes to HTTP 503 with reason
`stopping` before the status listener closes.

The manifest annotates the Pod for a Prometheus-compatible scraper. Port
forward the agent Pod when diagnosing a local installation. Set `POD` to
an agent name from `kubectl -n ztap-system get pods -o wide`:

```sh
kubectl -n ztap-system port-forward "pod/$POD" 9090:9090
```

Keep port forwarding running, and use a second terminal:

```sh
curl http://127.0.0.1:9090/healthz
curl http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/metrics
```

Readiness is false during initial cache synchronization, dry-run, an apply
failure, or local quarantine. A selected container can transmit before the
watcher observes its Kubernetes status and cgroup; this Pod-start
classification interval is measured separately from reconciliation duration.
The process-owned links also create separate, documented fail-open intervals
on orderly restart, SIGKILL crash, and during a rolling DaemonSet update.

| `/readyz` reason | HTTP status | Meaning |
| --- | --- | --- |
| `starting` | 503 | Initial synchronization or first apply has not completed |
| `dry_run` | 503 | Compilation succeeded without enforcement |
| `quarantined` | 503 | At least one local subject has a quarantined direction |
| `apply_error` | 503 | Compilation or application failed; inspect logs |
| `stopping` | 503 | Graceful shutdown has begun |
| `ok` | 200 | A snapshot is applied with no local quarantine |

Useful metrics include `ztap_agent_ready`, `ztap_agent_enforcing`,
`ztap_enforced_cgroups`, `ztap_compiled_rules`, `ztap_quarantined_cgroups`,
`ztap_unresolved_running_containers`, and `ztap_active_policy_epoch`.
`ztap_policy_reconciliations_total` counts attempts with a `result` label of
`success`, `rejected`, or `error`; `ztap_policy_reconcile_duration_seconds` measures
compile-and-apply duration, excluding API list latency and debounce.

## Live flow diagnostics

Select the agent Pod on the workload's node using `get pods -o wide`, set
`POD` to its name, and invoke the binary directly inside the scratch image:

```sh
kubectl -n ztap-system exec -i "$POD" -- \
  /ztap flows --bpffs-root=/host/sys/fs/bpf --output json
kubectl -n ztap-system exec -i "$POD" -- \
  /ztap flows --bpffs-root=/host/sys/fs/bpf --action blocked --direction egress
```

On the Linux node itself, use `ztap flows` with its default `/sys/fs/bpf` root
and `/run/ztap` lock directory, with permission to read the pinned maps.
When overriding agent paths, give the reader the same bpffs and run-directory
locations. Only one flow reader may run per node; filters apply after reading
and do not create independent subscriptions. Stop it with Ctrl-C and start it
again after an agent restart: shutdown, a stale heartbeat, or an agent-epoch
change ends the stream.

`--output` accepts `table` (default) or `json`. Filters accept `--action`
(`allowed`, `blocked`), `--protocol` (`TCP`, `UDP`), and `--direction`
(`ingress`, `egress`). JSON output is one object per line, with `timestamp`,
`policy_epoch`, `cgroup_id`, `direction`, `protocol`, `src_ip`, `src_port`,
`dst_ip`, `dst_port`, `action`, `reason`, and `schema_version` (currently `1`).

Flow events are rate-limited and can be dropped when the ring buffer is full.
Inspect `ztap_packet_decisions_total` (labels `action`, `direction`, `reason`)
and `ztap_flow_events_dropped_total` (`reason` is `rate_limited` or `ring_full`)
for packet decisions and suppressed events. An empty stream alone does not prove that
no packets were allowed or blocked; event loss does not change enforcement.

## Migration warning

The old `ZtapNetworkPolicy` CRD and operator are not consumed by this agent.
Export any objects that need translation before deleting the CRD: CRD deletion
removes its stored custom resources. Stop the old operator and agent before
starting this DaemonSet, then apply native `NetworkPolicy` objects and verify
readiness on every node.

## Troubleshooting

- `unsupported cgroup layout`: verify cgroup v2 and containerd's systemd
  cgroup driver; the agent intentionally does not guess paths.
- `readyz` returns 503 with a quarantine reason: inspect agent logs and correct
  or delete the rejected policy selected on that node.
- Missing eBPF attach or bpffs errors: verify the host mount, kernel feature
  probes, and the four capabilities in the manifest. Do not enable privileged
  mode as a workaround.
- `ImagePullBackOff`: check that the image is reachable by every node and
  that the source manifest's local placeholder has been replaced.
- `apply_error` or unresolved running containers: inspect logs and
  `ztap_unresolved_running_containers`; verify the containerd identity and
  cgroup path. Previously classified cgroups retain the last applied state
  after an apply failure, while an unobserved replacement can remain unlinked.
- Agent or reader lock already held: stop the other process using that
  node's run directory. Locks are released automatically after a crash;
  deleting a live lock file can allow competing owners.

## Removal and rollback

To roll back an image or flag change, apply the previous digest-pinned
manifest, or use the retained DaemonSet revision:

```sh
kubectl -n ztap-system rollout undo daemonset/ztap-agent
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
```

Rollback has the same restart fail-open interval. To stop enforcement while
keeping the namespace and RBAC, remove only the DaemonSet:

```sh
kubectl -n ztap-system delete daemonset ztap-agent
```

For a complete uninstall, delete the manifest you installed:

```sh
kubectl delete -f ztap-agent-v0.1.1.yaml
```

This also deletes `ztap-system` and any other resources in that namespace.
Deleting ZTAP does not delete your `NetworkPolicy` objects in other namespaces;
they remain stored without ZTAP enforcement. The manifest is the complete
shipped deployment surface; there is no operator, auxiliary control plane,
or second runtime image.

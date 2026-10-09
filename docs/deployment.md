# Deployment

ZTAP is deployed as an agent and a node initializer, using two Linux DaemonSets
and one runtime image. The maintained manifest is
[`deployments/kubernetes/ztap-agent.yaml`](../deployments/kubernetes/ztap-agent.yaml).
Its `ztap:dev` image matches `make docker`. Load that image into a disposable
local cluster, or use a copy of the manifest with your registry image's digest.

## Requirements

- Linux nodes with cgroup v2 and a mounted bpffs at `/sys/fs/bpf`.
- Pinnable cgroup BPF links with reopen and in-place program replacement,
  inherited ingress/egress hooks, cgroup socket storage with listener cloning,
  and socket network-namespace cookies. Startup probes these capabilities;
  restart-safe mode has no legacy attachment fallback. The new gates were
  exercised on Linux `7.0.14-orbstack-00380-ga7e0a2dc9535`, arm64,
  with containerd `2.3.4` and Kubernetes `1.36.4`.
- containerd configured to use the systemd cgroup driver; cgroupfs, cgroup v1,
  Docker Engine, and CRI-O layouts are unsupported.
- Kubernetes 1.36.x (CI uses `kindest/node:v1.36.4`) with a CNI that does not
  enforce NetworkPolicy. ZTAP does not disable another NetworkPolicy
  implementation; running both produces intersected enforcement and is
  outside the supported deployment contract.
- Kubernetes access for the agent ServiceAccount to read Nodes, Namespaces,
  Pods, and NetworkPolicies.
- Every non-host-network Pod in the cluster must explicitly drop `NET_RAW`
  (or `ALL`), set `allowPrivilegeEscalation: false`, and avoid privileged mode
  and added `NET_RAW` or `SYS_ADMIN`. This applies to regular, init, sidecar,
  and ephemeral containers, including non-host-network system workloads.
  The install manifest includes a cluster-wide, fail-closed
  `ValidatingAdmissionPolicy` and binding enforcing this prerequisite.
- Linux amd64 or arm64 nodes with the eBPF capabilities required by the
  kernel and runtime. The recorded reference kernel is `6.17.0-1022-azure`;
  see [the reference environment](performance.md#historical-reference-results).
- Docker with Buildx and `kubectl` on the machine used to build and install
  the agent; kind when loading an image into a disposable kind cluster.

The agent does not share the host network, PID, or IPC namespaces. It mounts
the host cgroup hierarchy read-only, while bpffs and `/run/ztap` are writable
for the engine's pinned state and process-owned runtime directory. It runs as
UID 0 without privileged mode or privilege escalation, drops all capabilities
first, and adds only `BPF`, `NET_ADMIN`, `PERFMON`, and `SYS_RESOURCE`. The root
filesystem is read-only.

`ztap-node-init` shares the node network namespace, drops **all** capabilities,
and mounts only the read-only cgroup hierarchy and `/run/ztap`. It authenticates
the Node and local host-network Pod identities with the Kubernetes API and
records the node socket namespace, supported cgroup parents, and verified
IPv4 TCP API endpoints in an owner-only bootstrap file. The agent grants its
exact verified container cgroup access only to those API endpoints before
classification. There is no namespace-wide workload bypass. Static mirror
identities also require an authenticated mirror hash and full runtime container
ID. Keep both DaemonSets and their downward-API `POD_UID` environment values.

## Install

Build from a source checkout. Update workload templates and recreate unsafe
Pods as described below before applying the manifest. Inspect the
checked-in manifest, including its cluster-wide admission guard.

For an existing disposable kind cluster named `ztap` that meets the
requirements above, build and load the local image:

```sh
make docker
kind load docker-image ztap:dev --name ztap
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-node-init --timeout=5m
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
kubectl -n ztap-system get pods -l app=ztap-agent -o wide
```

For other clusters, use [your own registry image](#build-your-own-image).
`make docker` builds the image locally; it does not push it or create a cluster.

Check that an agent is Ready on each intended node. Then validate and apply
your native `NetworkPolicy` documents; see [policy examples](policies.md#examples).

### Build your own image

To deploy a source build, publish it to a registry reachable by your nodes:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag your-registry/ztap:source \
  --push .
docker buildx imagetools inspect your-registry/ztap:source
cp deployments/kubernetes/ztap-agent.yaml ztap-agent.yaml
```

Replace `your-registry` with your registry path. In `ztap-agent.yaml`, change
the `image` field from `ztap:dev` to `your-registry/ztap@sha256:<digest>` using
the index digest reported by `imagetools inspect`, then run:

```sh
kubectl apply -f ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-node-init
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

The local `ztap:dev` tag is intended for disposable clusters. Use a digest
in the registry-backed manifest so each node runs the same source build.

## Upgrade

Build and push the updated source image, then update your prepared manifest
to the new immutable digest. Apply that file:

```sh
kubectl apply -f ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=5m
kubectl -n ztap-system get pods -l app=ztap-agent -o wide
```

The rolling update uses `maxUnavailable: 1` and `maxSurge: 0`. Normal exit,
cancellation, SIGKILL, and a stale userspace heartbeat leave committed maps and
both directional links pinned. The replacement validates boot identity,
durable ABI **3**, packet semantics **2**, kernel object IDs, program map
references, link targets, and full workload ownership before adopting them.
Compatible programs replace pinned links in place; their old and new versions
must share semantics while directional updates coexist. ABI or ownership errors
preserve surviving enforcement and stop unsafe mutation.

During an outage, the contract is the **last committed snapshot**. Unobserved
policy, label, and peer-address changes cannot take effect. Every reconciliation
defers its complete candidate if a committed live identity is absent, pending,
or inconsistent, even after informer synchronization. Confirmed cgroup
termination or a verified change to unisolated policy permits cleanup. Unknown
descendants remain blocked in both directions until the atomic policy/class
commit; known unisolated containers resume NetworkPolicy default allow.

The first migration from the historical process-owned version requires drained
workloads or a maintenance traffic gate: that old process still detaches on
exit. Fresh installation also requires preventing workload traffic until the
guard is installed and classification completes. Persistence covers one kernel
boot. A node reboot destroys these objects; this release does not provide or
verify a host/runtime startup dependency that installs protection before
workload traffic. Reboot continuity requires that separate gate and reboot test.

The [restart evidence](performance.md#restart-continuity-results) records finite
Linux and deployed-agent tests with zero observed prohibited traffic; it is not
proof of every possible failure schedule.

### Measured fail-open intervals

The [historical reference evidence](performance.md#historical-reference-results)
on Linux `6.17.0-1022-azure` recorded these separate boundaries for the
250-Pod/25-policy/2,500-rule fixture. These describe the older process-owned
implementation and remain historical measurements:

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
could also send before its ID and cgroup became visible to the watcher. The
current inherited guard blocks that unclassified interval after installation.

## Agent flags

The `--run-dir` directory and its ancestors must be owned by root or the
effective user and must forbid group and other writes. A sticky ancestor
such as `/tmp` is allowed when the final directory is protected. Lock files
must be owned by the effective user, have owner-only permissions (normally
`0600`), and have no hard links. The agent and flow reader reject unsafe
existing paths without changing their ownership or permissions.

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
failure, uncertain committed identity, or local quarantine. Controller readiness
does not determine the lifetime of pinned enforcement. Unknown containers
remain blocked while classification is pending. Existing containers retain the
committed policy when the controller is unavailable.

| `/readyz` reason | HTTP status | Meaning |
| --- | --- | --- |
| `starting` | 503 | Initial synchronization or first apply has not completed |
| `dry_run` | 503 | Compilation succeeded without changing kernel state |
| `quarantined` | 503 | At least one local subject has a quarantined direction |
| `apply_error` | 503 | Compilation or application failed; inspect logs |
| `stopping` | 503 | Graceful shutdown has begun |
| `ok` | 200 | A snapshot is applied with no local quarantine |

Useful metrics include `ztap_agent_ready`, `ztap_agent_enforcing`,
`ztap_enforced_cgroups`, `ztap_compiled_rules`, `ztap_quarantined_cgroups`,
`ztap_unresolved_running_containers`, and `ztap_active_policy_epoch`.
`ztap_active_enforcement_generation{generation="..."}` identifies the compatible
program generation, and
`ztap_last_successful_reconciliation_timestamp_seconds` reports this controller's
last successful apply separately from the recovered policy epoch.
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

Only roll back to a persistence-aware image with compatible ABI and packet
semantics. The historical process-owned image is not a supported live rollback.
Drain or gate traffic before an incompatible migration.

Deleting the DaemonSets leaves enforcement active, including the unknown
workload guard. Intentional removal has two steps:

```sh
kubectl -n ztap-system delete daemonset ztap-agent ztap-node-init
kubectl -n ztap-system wait --for=delete pod -l app=ztap-agent --timeout=5m
```

Then run the matching Linux binary with administrator privileges on **each**
node, using that node's actual bpffs and runtime directory:

```sh
sudo /path/to/ztap cleanup --bpffs-root=/sys/fs/bpf --run-dir=/run/ztap
```

Cleanup acquires the agent lock, refuses a competing agent, verifies ownership
before mutation, preserves unrelated objects, and supports retry after partial
removal. Run it before deleting the deployment's RBAC and admission resources.
For a complete uninstall, then delete the manifest you installed:

```sh
kubectl delete -f deployments/kubernetes/ztap-agent.yaml
```

If you installed a registry-backed copy, use `kubectl delete -f ztap-agent.yaml`
with that same file instead.

This also deletes `ztap-system` and any other resources in that namespace.
Deleting ZTAP does not delete your `NetworkPolicy` objects in other namespaces;
they remain stored. After explicit node cleanup they have no ZTAP enforcement.
The manifest is the complete shipped deployment surface; both DaemonSets use
the same runtime image.

# Restart-safe enforcement plan

Status: implemented in the working tree, with durable ABI 3 and packet semantics
2. Persistent enforcement and inherited new-workload coverage passed local
privileged Linux and capability-only kind gates on October 9, 2026. See the
[recorded results](performance.md#restart-continuity-results) and the updated
[deployment boundaries](deployment.md#upgrade). CI runs the same release gates.
Reboot continuity remains a separate, unimplemented startup-dependency gate.

## Objective and boundaries

Keep the last committed policy active on an already protected container during
agent shutdown, SIGKILL, replacement startup, and a compatible DaemonSet upgrade.
The replacement must recover the existing kernel state before reconciling a new
snapshot. An unavailable Kubernetes API or a failed recovery must not remove
working enforcement.

Deliver this in two milestones:

1. **Persistent enforcement:** existing protected containers retain enforcement
   throughout an agent outage, including crashes during policy updates.
2. **Coverage for new containers:** containers created during the outage remain
   blocked until their identity and policy classification are committed.

Milestone 1 closes the documented loss of process-owned attachments. It does not
close the current new-container classification gap; milestone 2 is required for
a claim that agent downtime cannot expose new workloads.

The policy contract during an outage is the last committed snapshot. Policy,
label, and peer-address changes that have not been observed cannot be enforced
as if they were known. Keep that limitation explicit. Persistence covers the
current kernel boot; a reboot needs installation before workload traffic starts.
Preserve the documented policy scope and node/self exceptions unless a separate
change explicitly revises them.

## Historical implementation before this plan

| Location | Relevant behavior |
| --- | --- |
| `internal/enforcer/engine_linux.go` | Pins only flow/status maps; creates a fresh collection and active configuration on startup. Cgroup attachments use unpinned BPF links, with a legacy attachment fallback. |
| `internal/enforcer/engine_core.go` | Holds the active slot, snapshot, link inventory, and pending cleanup in process memory. `Close()` detaches attachments. |
| `internal/cli/native_agent_linux.go` | Waits for informer cache synchronization before constructing the engine; defers destructive engine cleanup. |
| `bpf/engine.c` | Allows a missing subject entry. Uses attachment-local cgroup identity, which cannot simply be reused for an inherited parent guard. |
| `internal/cli/native_agent_performance_test.go` | Measures restart and SIGKILL fail-open intervals. |

The existing two-slot policy update and atomic `active_config` map replacement
are useful foundations. Keep their commit and packet-reader quiescence rules.

## Delivery sequence

### 1. Prove kernel support and define the durable ABI

On the supported Linux/containerd environment, write a small integration proof
that pins both ingress and egress links, kills their owner, reopens them in a
second process, and verifies that denied traffic remains denied.

Require actual pinnable cgroup `bpf_link` support for this mode. Probe creation,
pinning, reopening, and program replacement rather than relying only on a
kernel version. Do not silently use the current legacy attachment fallback
while claiming the same lifecycle guarantee.

Define a versioned, protected bpffs layout under `/sys/fs/bpf/ztap` containing:

- Enforcement maps, including both policy slots, `active_config`, connection
  state, cgroup storage, packet-reader counters, and observability maps.
- Ingress/egress programs and per-cgroup link pins with deterministic names.
- Recovery metadata: schema/ABI version, program generation, boot identity,
  owning Pod UID, full containerd ID, and cgroup ID/path and filesystem identity
  sufficient to validate attachment ownership without Pod status being complete.

Use kernel object information to verify map specs, program-to-map references,
link attachment types, and target cgroups. A matching pin name or program tag
alone is not proof of ownership. Preserve the existing directory-handle and
no-follow path protections; reject writable or foreign pin directories.

**Gate:** the two-process Linux proof passes, and incompatible objects are
rejected without removing existing enforcement.

### 2. Separate process exit from enforcement removal

Refactor attachment handling into explicit operations for creating/pinning,
adopting, releasing local handles, and removing an owned attachment.

Normal `Engine.Close()` must stop heartbeat/goroutines and close this process's
file descriptors while leaving committed pins and attachments in place. Startup
failure and context cancellation must follow the same preservation rule.
Rollback can explicitly remove newly created, uncommitted objects after
checking that they are not part of the active generation.

Replace unconditional startup pin removal with validation and adoption. Provide
an explicit cleanup command for intentional enforcement removal. It must take
the node agent lock, verify ownership, refuse a competing agent, and support
retrying partial cleanup. Deleting the DaemonSet alone will no longer mean
enforcement has been removed; document that operational change.

**Gate:** normal exit, cancellation, and SIGKILL preserve both directions on
an existing protected cgroup; explicit cleanup removes only ZTAP-owned objects.

### 3. Recover the active policy and interrupted transactions

After acquiring the existing node lock, open and validate durable kernel state
before waiting for Kubernetes caches. On adoption:

1. Read the current `active_config` inner map and recover its slot and policy
   epoch. Do not initialize it to slot 0/epoch 0.
2. Reconstruct the normalized active snapshot, per-slot map counts, and link
   inventory from the maps and verified link objects. This restores identical
   snapshot detection and capacity accounting.
3. Preserve connection state and policy epoch when the policy is unchanged;
   assign a new controller `AgentEpoch` for the replacement process.
4. Inspect the inactive slot and partially pinned attachments. Reclaim only
   objects proven uncommitted and only after existing quiescence checks pass.
   Never reset packet-reader counters while packets may still use them.
5. Start controller status reporting, then synchronize caches. Match recovered
   subjects to verified workload identities before reconciling through the
   existing atomic policy commit path.

Cache synchronization is not proof that container identity is complete. The
current resolver skips containers without a published ID or `Running` status,
and the compiler can accept a snapshot without their cgroup IDs. Committing that
snapshot would remove a recovered subject's policy entry; the BPF program then
allows its traffic even if its links remain pinned.

Before the first and every subsequent reconciliation, account for each committed
subject using its durable ownership metadata. If a recovered subject may still
be live but its Pod/container status is missing, pending, or inconsistent with
that identity, defer the entire candidate and retry. Keep the committed slot,
policy epoch, connection state, and links intact, and report degraded controller
readiness. A missing informer entry alone must not authorize cleanup. Remove a
subject only when kernel/runtime evidence confirms its old cgroup is no longer
live, or complete classification of the verified live identity establishes that
it is no longer isolated. This preservation rule is required for milestone 1
without relying on the later unknown-workload guard.

Keep `active_config` authoritative. Any recovery manifest or journal must be
published before the commit that references it; a crash after the kernel commit
must be recoverable even if subsequent bookkeeping never ran.

| Crash point | Required recovery |
| --- | --- |
| During inactive-slot population | Keep the old active slot; safely reclaim the partial candidate. |
| Between ingress/egress attachment or pin operations | Keep existing committed attachments; identify incomplete candidates and repair or remove them without weakening active policy. |
| After candidate links are pinned, before the flip | Keep the old committed snapshot; defer candidate cleanup until it is proven safe. |
| After the flip, before in-memory bookkeeping | Adopt the new active slot and its links; do not roll back from stale process metadata. |
| During old-slot or obsolete-link cleanup | Resume cleanup after quiescence; retain the current active generation. |

For missing pins, corrupt metadata, or ABI mismatch, keep surviving attachments
and report a degraded controller. Stop unsafe mutation rather than wiping the
directory and starting with an empty policy. Repairing a live container's lost
attachment must use protection from milestone 2 or a workload traffic gate.

**Gate:** fault injection at every row recovers the last committed policy;
unchanged reconciliation preserves policy epoch and valid reply state.
Also recover a live, default-denied subject with synchronized caches that omit
its container ID, report pending container state, or temporarily omit its Pod.
Verify that reconciliation preserves its policy, epoch, connections, and both
links until identity is resolved. Then verify that confirmed cgroup termination
and a verified change to unisolated policy permit the intended cleanup.

### 4. Make compatible upgrades and status safe

Load replacement programs against verified existing maps using
`CollectionOptions.MapReplacements`. For compatible program changes, update
pinned links in place rather than detaching and reattaching them. Record and
recover partially completed upgrades.

Ingress/egress link updates are separate operations. Require compatible old/new
programs to share policy semantics and map ABI while they coexist. Reject an
incompatible upgrade and retain the old generation until an explicit migration
has been designed and tested. Limit normal rollback to persistence-aware,
ABI-compatible versions.

Expose controller readiness, active enforcement generation/policy epoch, and
last successful reconciliation separately. A stale controller heartbeat must
not cause BPF policy expiry or attachment removal. Preserve the flow reader's
documented reconnect behavior, and test its handling of a new `AgentEpoch`.

**Gate:** an upgrade or downgrade, including a crash between directional
updates, produces no observed prohibited traffic and remains recoverable.

### 5. Protect containers created while the agent is unavailable

Start with a Linux feasibility test for pinned ingress/egress guards on the
supported Kubernetes cgroup parents, including both supported systemd layouts.
The guard must cover descendants created after installation and must determine
the packet socket's actual workload identity in both directions. Using the
current attachment-local ID or the executing task's ID is insufficient.

If that identity and inheritance behavior can be proved, implement a guard
that drops unknown workloads until an explicit classification is committed.
Represent known, unisolated workloads explicitly so normal Kubernetes
NetworkPolicy default-allow behavior resumes after classification. A separate,
slot-versioned classification table can preserve the current policy model's
requirement that policy subjects have an isolation direction.

Test host-network exclusions, node/self exceptions, cgroup and container
replacement, and stale identity reuse. Ensure a replacement agent can reach
the API to recover without depending on its own yet-unavailable informer
classification; any bootstrap exception must have a narrow, verified identity
and documented traffic scope. Do not grant a whole namespace a broad bypass.

If a parent guard cannot cover ingress/egress with reliable identity, use a
runtime/CNI gate that prevents workload network use until ZTAP has committed
classification. Define its identity source and release ordering before choosing
the integration:

- A gate that blocks process startup must provide ZTAP with authenticated
  runtime identity after the target cgroup exists: Pod UID, full containerd ID,
  and a verifiable cgroup ID/path. Resolve Pod policy facts from synchronized
  caches and classify that identity without requiring `Running` container status.
  An early CNI hook before container identity/cgroup creation cannot wait for
  this classification if returning from that hook is required to create them.
- Alternatively, allow the process to reach `Running` while a network gate
  blocks both ingress and egress before its first possible packet. The current
  resolver can then discover its identity; the network gate remains closed
  until classification and any required enforcement links are committed.

Tie release to the verified identity and committed policy epoch. For an
unreleased workload, agent loss, timeouts, or failed classification must leave
the gate closed; cancellation and container replacement must invalidate stale
release requests. Test bootstrap of the replacement agent through the narrow
exception described above, so its startup does not depend on releasing its own
gate through informer classification.
Kubernetes readiness or an admission policy alone does not provide this network
gate. Record the identity feed, runtime/CNI lifecycle hook, network barrier, and
release protocol as deployment requirements before treating this milestone as
complete.

**Gate:** a pod created while the agent is killed, paused, or disconnected from
the API cannot send or receive prohibited traffic before classification. After
recovery, allowed controls and unisolated pods work normally.
If the fallback is used, prove that a gated container with no published
`Running` identity can progress to classification and eventual allowed traffic
after recovery, without a startup dependency cycle or any early traffic window.

### 6. Add Linux release gates and publish the new guarantee

Extend `engine_core_test.go` with recovery state-machine tests and
`engine_linux_integration_test.go` with real map/link lifecycle and crash tests.
Replace the restart/crash-gap performance assertions with continuity tests;
retain historical measurements and version the evidence format and verifier.

Use continuous sequenced TCP/UDP traffic with separate directional topologies:

- Egress: create the sending socket inside the protected cgroup and receive
  traffic outside it.
- Ingress: create the receiving socket inside the protected cgroup and send
  traffic from outside it.

Establish denied baselines and working allowed controls for each direction before
the outage. Include established replies and packet/counter evidence identifying
the protected subject, direction, and policy epoch. Deliberately delay replacement
startup and API recovery so tests exercise a sustained outage. Killing only a
child test helper or measuring a fast restart is insufficient evidence for the
deployed agent.

Required scenarios include SIGTERM, SIGKILL, SIGSTOP, API outage, repeated
restart, every transaction checkpoint, map capacity failure, partial pinning,
partial cleanup, duplicate-agent lock contention, cgroup disappearance and
replacement, recovery with incomplete informer identities, fallback gate startup
and release ordering when applicable, compatible rollout/rollback, and explicit
uninstall.

Run `make check`, generated binding checks, privileged `make integration`, and
the capability-only kind DaemonSet gate. Add restart continuity and new-pod
coverage to `.github/workflows/migration-ci.yml` using real Linux eBPF tests.
macOS compilation and mocked tests cannot establish this guarantee.

The acceptance criterion is **zero observed prohibited packets across each
tested outage**, with working allowed controls. Report duration, packet counts,
kernel/runtime versions, and checkpoint coverage; do not present a finite test
as proof of every possible failure schedule.

Update `README.md`, `docs/deployment.md`, `docs/development.md`,
`docs/policies.md`, and `docs/performance.md` only after the corresponding gates
pass. Document preserved enforcement after DaemonSet deletion, explicit
cleanup, supported ABIs/kernels, and the last-committed-policy contract.

The first migration from today's process-owned version needs a maintenance
traffic gate or drained workloads: its orderly shutdown still removes its
attachments. Do not claim that first rollout is already gap-free. For reboot
coverage, add a host/runtime startup dependency that installs the guard before
workload traffic is possible and test a full node reboot separately.

## Completion criteria

- Milestone 1: persistent maps and both directional links survive process
  loss; recovery retains protection while workload identity is uncertain;
  compatible upgrades retain the committed policy; all transaction crash tests
  and deployed-agent continuity gates pass in both directions.
- Milestone 2: new containers are covered before traffic starts, stale workload
  identities cannot inherit authorization, and bootstrap/recovery works without
  a broad bypass or startup dependency cycle.
- Broad agent-downtime claims require both milestones. Reboot continuity needs
  the separate node-startup gate. Unobserved policy changes remain explicitly
  outside the last-committed-policy guarantee.

## Library references checked for this design

The project's cilium/ebpf v0.22.0 API supports retaining pinned links when local
handles close, reopening them, and updating their program. See the
[link API implementation](https://github.com/cilium/ebpf/blob/v0.22.0/link/link.go).
The loader can reuse compatible existing maps through `MapReplacements`; see
the [collection API](https://github.com/cilium/ebpf/blob/v0.22.0/collection.go).
These APIs provide the mechanisms; the Linux gates above must establish ZTAP's
actual enforcement behavior.

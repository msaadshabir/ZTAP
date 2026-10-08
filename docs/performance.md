# Performance evidence

ZTAP's performance claims refer to a specific source commit, fixture, and Linux
environment. Offline validation and Go-only benchmarks do not establish
kernel-path performance or Kubernetes availability.

- [Historical reference results](#historical-reference-results)
- [Run measurements](#run-measurements)
- [Evidence contract](#evidence-contract)
- [CI acceptance](#ci-acceptance)

## Historical reference results

The measurements below were recorded on September 24, 2026, at source commit
`1b196c068b9ea42d545303dc56c77c1c5dc1ff44`.
[Measurement run 36055138894](https://github.com/saadshabir/ZTAP/actions/runs/36055138894)
produced fresh measurements and combined them with the privileged eBPF and
capability-only Kubernetes evidence from the successful same-commit
[Migration CI run 36052715910](https://github.com/saadshabir/ZTAP/actions/runs/36052715910).

The reference fixture contains 250 Pods, 25 policies, and 2,500 compiled
ordinary rules. The Linux/amd64 runner used Go `1.26.6` and kernel
`6.17.0-1022-azure`; the measurement process was pinned to CPUs `0,1` with
`GOMAXPROCS=2`. The host exposed four CPUs and no finite quota in its readable
`cpu.max` entries. The separate kind reference node had a two-CPU cgroup
quota and Kubernetes `1.36.4`, with kindnet's policy controller disabled.

| Measurement | Result | Scope |
| --- | ---: | --- |
| Direct engine apply p95 | 45.171 ms | Real cgroup creation, map population, policy flip, and link attachment |
| Native reconciliation p95 | 146.319 ms | Synchronized fake informer cache and real engine apply; excludes API list latency and fixed debounce |
| Initial activation p95 | 417.027 ms | Fake informer startup, cgroup resolution, compilation, and real engine apply |
| Informer event to active epoch p95 | 103.956 ms | Synchronized fake cache, fixed debounce, compilation, and real engine apply |
| New Pod classification p95 | 103.284 ms | Newly Running Pod in a fake cache with its cgroup already created; excludes API-server and runtime startup |
| Orderly restart p95 | 314.103 ms | Process-owned engine shutdown, replacement startup, and initial apply |
| SIGKILL to first allowed packet p95 | 3.453 ms | Link-owning child process and one selected cgroup; measures onset of fail-open, not recovery |
| Same-node DaemonSet rollout fail-open interval | 1,652 ms | Capability-only agent in kind, from first allowed probe to restored deny |
| Quiet shipped-agent maximum | 0.000683 CPU cores; 49.379 MiB `memory.current` | Three five-second kind samples; cgroup memory includes non-RSS charges |
| Quiet helper maximum | 0 measured CPU cores; 55.605 MiB RSS | Three five-second fake-client samples; CPU is limited by process-tick resolution and kernel-map memory is excluded |
| UDP p99 latency increase | 0.996 µs | Three loopback samples, 10,000 round trips each, from one selected cgroup |
| Maximum sampled TCP throughput regression | 4.113% | Three detached/attached comparisons, each transferring 8 GiB |
| Flow decisions | 60,099 accounted | 12,000 delivered + 48,099 rate-limited + 0 ring-full over 60.100 seconds |

The failed-update integration test retained policy on an already classified
cgroup while a newly created cgroup remained unobserved. Its first allowed
probe through a controlled retry and subsequent blocked probe spanned
2,056.943 ms. That is a probe-to-retry measurement, not a bound on watcher
delay or failure recovery.

Results are rounded from the historical measurement data. They describe that
source commit and those fixtures; later dependency updates, other nodes, and
workloads require fresh measurements.
Pod-start, restart, crash, and rollout measurements have different boundaries;
none is a zero-gap availability guarantee. See
[deployment limits](deployment.md#upgrade) for their operational meaning.

## Run measurements

### Compiler benchmark

```sh
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test -run '^$' -bench '^BenchmarkCompileReferenceFixture$' -benchmem -count=5 ./internal/policy
```

This measures compilation for the reference fixture only. It cannot satisfy
packet-path, resource, flow-accounting, or fail-open gates.

For before-and-after comparisons, use the same Go toolchain, host, and
`GOMAXPROCS` setting for both revisions. Run the benchmarks sequentially on
an idle host; concurrent builds and analysis can distort timings. Compare
the median `ns/op` across runs alongside `B/op` and `allocs/op`, and record
both source revisions and the environment. Local compiler improvements do
not update the historical reference measurements above; those require fresh
Linux evidence for the changed commit.

### Linux performance harness

Use a disposable Linux host with cgroup v2, mounted bpffs, and the privileges
required by [the integration suite](development.md#test-layers). Pin the
measurement process to CPUs `0,1`, as the hosted performance job does:

```sh
sudo --preserve-env=PATH,GOFLAGS,GOMODCACHE,GOCACHE \
  taskset --cpu-list 0,1 make performance
make verify-performance PHASE5_EVIDENCE_DIR=dist
```

The target sets `GOMAXPROCS=2`, assigns one run ID to both test processes,
and removes only its ten named JSON outputs before generating fresh evidence.
It rejects a symlinked or non-directory `dist` root. The harness uses real
cgroups and packets, while native-agent tests use a fake Kubernetes client.

Local `make performance` does not produce the hosted kind resource, status,
flow, or rollout transcripts. Verifying local JSON alone therefore does not
establish the full Linux/Kubernetes acceptance contract. If privileged execution
leaves files owned by root, restore ownership before reusing the checkout.

For a hosted measurement run, manually dispatch
`.github/workflows/migration-ci.yml` with `run_performance_preflight=true`
and `migration_ci_run_id` set to a successful push run for the exact selected
commit and branch. The workflow downloads that run's eBPF and Kubernetes
evidence, captures the environment, runs measurements, and verifies the
combined bundle. This dispatch is separate from the required merge checks.

## Evidence contract

The harness retains these files under `dist/`:

| File | Measurement |
| --- | --- |
| `phase5-performance.json` | Engine apply and kernel-map memory snapshots |
| `phase5-agent.json` | Initial native-agent activation |
| `phase5-agent-reconcile.json` | Native compile-and-apply reconciliation |
| `phase5-agent-event.json` | Informer event to active policy epoch |
| `phase5-agent-pod-start.json` | New Pod classification |
| `phase5-agent-restart.json` | Orderly restart interval |
| `phase5-agent-crash.json` | SIGKILL to onset of fail-open |
| `phase5-agent-resource.json` | Quiet helper CPU and RSS |
| `phase5-packet.json` | UDP latency and TCP throughput comparison |
| `phase5-flow.json` | Delivered, rate-limited, and ring-full accounting |

The fixed gates are 2 seconds p95 for engine apply and reconciliation,
3 seconds p95 for activation and informer events, 10 µs for the UDP p99
increase, 10% for maximum sampled TCP throughput regression, and 0.10 CPU
cores / 200 MiB for quiet resources. Pod-start, restart, crash, and rollout
intervals are recorded separately without an availability budget.

The verifier requires the complete 250-subject/25-policy/2,500-rule fixture,
the exact artifact set, expected producer scopes, consistent run and
environment metadata, and the required sample counts. It recomputes percentile,
packet, resource, map-memory, and flow-accounting summaries from retained
samples. Unknown or duplicate JSON fields, duplicate environment keys,
extra evidence JSON files, symlinks, and non-regular files fail verification.

Kernel-map evidence reports calculated bounded-map payload capacity and
kernel-reported memlock where available, with snapshots before warm-up,
after warm-up, and after each of three applies. The cgroup-storage map is
explicitly unbounded per cgroup; bounded maps must retain their exact
generated inventory and dimensions. Repeated applies must not show
unexplained map growth after warm-up.

Hosted Kubernetes evidence binds resource and rollout samples to actual
Pod, container, cgroup, and node identities. It includes the exact fixture,
three quiet five-second resource samples, readiness/status probes, a blocked
flow for the smoke client's exact tuple, and same-node rollout timestamps.
`memory.current` includes non-RSS charges and is a conservative cgroup-memory
upper bound, distinct from the helper's RSS measurement.

For changes to the producer or verifier contract, review
[`tools/phase5verify`](../tools/phase5verify),
[`tools/phase5probe`](../tools/phase5probe), and the integration-tagged
performance tests in [`internal/enforcer`](../internal/enforcer) and
[`internal/cli`](../internal/cli). Preserve field names and scope literals
unless the producer and verifier are updated together.

## CI acceptance

The [Migration CI workflow](../.github/workflows/migration-ci.yml) checks
formatting, lint, vulnerabilities, generated bindings, portable tests,
privileged Linux eBPF integration, the runtime image, and Kubernetes
acceptance in a disposable kind cluster. It also builds the Linux arm64
binary. Privileged jobs run only for trusted repository events.

The optional hosted performance job requires a successful push run for the
same source commit and branch. It verifies fresh measurement JSON, the
recorded Linux environment, and the downloaded eBPF/Kubernetes transcripts.
It uploads the combined evidence as an Actions artifact retained for 14 days.

### Verify downloaded hosted evidence

Use a checkout of the measured source commit and run the following from the
repository root. The download requires an authenticated GitHub CLI (`gh`)
with access to the repository's Actions artifacts. Replace the four
placeholders with the dispatch run ID, its selected commit and branch, and
the successful push run ID supplied as `migration_ci_run_id`. Take these
expected values from the workflow runs, rather than from the downloaded
evidence itself.

```sh
ztap_measurement_run_id='<dispatch-run-id>'
ztap_migration_run_id='<successful-push-run-id>'
ztap_commit='<full-measured-commit-sha>'
ztap_branch='<selected-branch>'
ztap_evidence_dir="$(mktemp -d)"

gh run download "$ztap_measurement_run_id" --repo saadshabir/ZTAP \
  --name hosted-performance-preflight-evidence --dir "$ztap_evidence_dir"

make verify-performance \
  PHASE5_EVIDENCE_DIR="$ztap_evidence_dir/dist" \
  PHASE5_EXPECTED_RUN_ID="${ztap_measurement_run_id}-${ztap_commit}" \
  PHASE5_ENVIRONMENT_FILE="$ztap_evidence_dir/performance-preflight-environment.txt" \
  PHASE5_EXPECTED_MIGRATION_RUN_ID="$ztap_migration_run_id" \
  PHASE5_EXPECTED_COMMIT="$ztap_commit" \
  PHASE5_EXPECTED_REF="refs/heads/$ztap_branch" \
  PHASE5_EXPECTED_WORKFLOW_RUN_ID="$ztap_measurement_run_id" \
  PHASE5_EXPECTED_WORKFLOW_EVENT=workflow_dispatch \
  PHASE5_EXPECTED_WORKFLOW_PATH=.github/workflows/migration-ci.yml \
  PHASE5_EXPECTED_MIGRATION_BRANCH="$ztap_branch" \
  PHASE5_EXPECTED_ENVIRONMENT_ARCH=amd64 \
  PHASE5_HOSTED_EBPF_DIR="$ztap_evidence_dir/dist/hosted-ebpf-engine-evidence" \
  PHASE5_HOSTED_CAPABILITY_DIR="$ztap_evidence_dir/dist/hosted-capability-agent-evidence"
```

The environment file and both hosted directories enable provenance and
transcript validation in addition to the ten measurement JSON files. Success
prints `validated Phase 5 evidence`. Verification reads the retained data;
it does not rerun Linux enforcement and can run on macOS. The downloaded
files remain in `$ztap_evidence_dir`; retain them before the Actions artifact
expires if you need a longer-lived copy.

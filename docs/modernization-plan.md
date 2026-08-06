# ZTAP Modernization Plan — Execution Checklist

> **Purpose:** step-by-step execution plan to bring ZTAP in line with current (2026) standards.
> Generated from a full codebase audit. Each phase is independently shippable; phases are ordered to
> minimize merge conflicts (mechanical edits → additive CI work → big rename → deep refactors).
>
> **Status (2026-02):** Phases A and B are **complete and verified** against the tree (evidence in
> the completed-workstreams tables below; a handful of residuals are listed there). The active
> checklist is **C → D → E → F**. Pre-flight 0.2/0.3 baselines must be re-captured immediately
> before Phase C starts — the `/tmp` snapshots are ephemeral and the binary has since been rebuilt.
>
> **Scope decisions (agreed):**
> - ✅ In scope: quick code modernization (A), CI/release supply chain (B), `pkg/`→`internal/` + cmd split (C), centralized config (D), anomaly service wire-up + hardening (E), `log/slog` migration (F).
> - ❌ Out of scope (see Appendix B): broad Docker/compose/k8s-manifest modernization (except what release signing requires), standalone docs cleanup, operator controller-gen adoption.

**Conventions used below:**
- Commands assume macOS dev shell (`sed -i ''`); on Linux use `sed -i`.
- Commit messages follow the repo's conventional-commit style (`ci:`, `build:`, `refactor:`, `feat:`, `test:`, `docs:`, `chore:`).
- New GitHub Actions are written with version tags + `# TODO: pin to SHA` — the repo convention is 100% SHA pinning; resolve and pin before merging.
- Per-phase **gate** (run before every commit unless noted):
  ```bash
  go build ./... && go test ./... -race && golangci-lint run
  ```

---

## Pre-flight

- [x] **0.1** Baseline: confirm clean tree and green tests. *(done — A/B landed on a clean tree)*
  ```bash
  git status
  go test ./...
  ```
- [ ] **0.2** Snapshot CLI surface (used to prove the Phase C restructure changes nothing user-visible):
  ```bash
  go build -o /tmp/ztap-baseline .
  /tmp/ztap-baseline --help > /tmp/ztap-help-baseline.txt
  for c in api grpc aws azure gcp agent compliance enforce version status cluster policy flows logs metrics user discovery audit; do
    /tmp/ztap-baseline "$c" --help > "/tmp/ztap-help-${c}-baseline.txt" 2>&1 || true
  done
  ```
- [ ] **0.3** Snapshot policy round-trip (proves the yaml v2→v3 migration is wire-safe):
  ```bash
  go build -o /tmp/ztap-baseline .
  for f in examples/*.yaml; do /tmp/ztap-baseline policy validate -f "$f" || echo "BASELINE-FAIL: $f"; done
  ```

> **Note:** 0.2/0.3 snapshots live in `/tmp` and are ephemeral — re-capture them on the working
> branch immediately before Phase C starts (the baseline binary has since been rebuilt).

- [ ] **0.4** Working branch: `git checkout -b modernization/main` (each phase merges or stacks; see commit splits).

---

## Phase A — Quick code modernization ✅ COMPLETE (verified 2026-02)

**Status:** every item below was verified against the tree. The table is evidence, not action
items; the original detailed checklist is superseded.

| Item | Evidence (verified in tree) |
|---|---|
| A.1 YAML v3 | 0 files import `gopkg.in/yaml.v2`; 16 files on `yaml.v3`. Note: `go.yaml.in/yaml/v2` remains in go.mod **as an indirect dep** (transitive via k8s tooling) — expected; the original "should drop out of go.mod" criterion meant *direct imports* only |
| A.2 modernize | 0 `sort.Strings`, 0 no-arg `fmt.Errorf`; remaining `interface{}` sites are all in generated `proto/*.pb.go` (correctly skipped). The `go run ...modernize@latest -test -fix ./...` invocation was re-confirmed working |
| A.3 typed atomics | 0 package-func `atomic.Add/Load/Store` in `pkg/alert`, `pkg/flow` |
| A.4 error chains | `%w` at `pkg/enforcer/iptables_linux.go:39`; 0 `fmt.Errorf(...).Error()` anti-patterns in `pkg/apigrpc/server.go`; no `var _ = errors.New` import-keeper in `policy_sync_etcd.go` |
| A.5 context hygiene | `errors.Is` for `io.EOF`/`context.Canceled`; `context.AfterFunc` in `pkg/discovery/discovery.go` + `pkg/alert/dispatcher.go`; no `time.Sleep(HeartbeatInterval)` remains in `election_etcd.go` |
| A.6 test refresh | 4 `context.Background()` remain in tests (was ~100) — sweep opportunistically |
| A.7 dedup | landed as `pkg/paths.Expand` + `pkg/apiutil.DefaultAuthManager()` — exactly the plan's proposed `pkg/apiutil/` home; tilde-expansion and auth defaults no longer duplicated |

**Gate (was run pre-merge):** `go build ./... && go test ./... -race && golangci-lint run && bash scripts/security_check.sh`

---

## Phase B — CI / release supply chain ✅ COMPLETE (verified 2026-02)

**Status:** every item below was verified against the tree (workflows, configs, Dockerfiles).

| Item | Evidence (verified in tree) |
|---|---|
| B.1 GoReleaser | `.goreleaser.yaml` present (cosign sign-blob, SBOMs, checksums); `release.yml` has cosign + `sbom: true`/`provenance: mode=max` on build-push-action, SLSA generic-generator job (SHA-pinned v2.1.0), CHANGELOG-based VERSION build-arg. **Residual:** `cosign verify-blob` / `gh release view` on the *first tagged release* — cannot be done before a tag exists |
| B.2 Dockerfiles | `alpine:3.24` SHA-pinned runtime (EOL 3.19 gone); `ARG VERSION` + `-trimpath -ldflags` build lines; OCI labels incl. `org.opencontainers.image.version` |
| B.3 covergate ratchet | `-baseline`/`-update-baseline` flags in `cmd/covergate`; `ci.yml:193` runs it with `.covergate-baseline.json` and no `\|\| echo`; empty benchmark job deleted; documented in `CONTRIBUTING.md` + `docs/guides/testing.md` |
| B.4 golangci v2 | `.golangci.yml` matches the proposed v2 config — govet + gofmt/goimports formatters enabled |
| B.5 drift checks | buf lint/breaking + `./scripts/gen_proto.sh && git diff --exit-code` (`ci.yml:160`); eBPF regenerate drift check (`ci.yml:383-384`). `buf.yaml` still v1 — optional v2 migration deferred, fine |
| B.6 dependabot | docker ecosystems (root + `pkg/anomaly`), 7-day cooldowns, dedicated `k8s` group all present |
| B.7 supply chain | `scorecard.yml` present with SARIF upload + `publish_results: true`, all actions SHA-pinned with `# vX.Y.Z` comments (0 `TODO: pin to SHA` remain); shellcheck + zizmor jobs in `ci.yml`. Note: the README badge was added, then **deliberately removed** (b274f26 / 71764c2 "Remove badges") — not an open item |

**Residual to close (small):** cosign/provenance verification on first tagged release.

---

## Phase C — Structure: `pkg/` → `internal/` + cmd split

**Goal:** idiomatic layout; `internal/` communicates app-not-library. Big rename — land as one
focused PR (Phases A/B already merged; D/E/F branches stack on top).

### C.1 — Module path decision

- [x] **Decision (2026-02): keep the bare `ztap` module path.** The earlier "recommended" rename
  to `github.com/msaadshabir/ZTAP` was re-scored: GoReleaser already works with `main: .`, the
  rename has zero user-visible effect (C.4 proves behavior is identical either way), and it churns
  Dockerfiles, docs, and `.github/copilot-instructions.md` for a single `go install` convenience.
  Revisit only if `go install`-from-GitHub becomes a hard requirement:
  ```bash
  go mod edit -module github.com/msaadshabir/ZTAP
  rg -l '"ztap/' --type go | xargs sed -i '' 's|"ztap/|"github.com/msaadshabir/ZTAP/|g'
  go mod tidy
  ```

### C.2 — Move packages

- [ ] Move everything, rewrite imports:
  ```bash
  git mv pkg internal
  rg -l '/pkg/' --type go | xargs sed -i '' 's|/pkg/|/internal/|g'
  go mod tidy && go build ./... && go test ./...
  ```
- [ ] **Exception decision:** if external tooling should import the CRD/policy types, keep
  `pkg/operator/api/v1alpha1` + `pkg/policy` public under the new module path; otherwise move all.
- [ ] Fix non-Go references: `rg '/pkg/' -g '!*.go'` — update `Dockerfile*`, workflows,
  `scripts/*`, `docs/**`, `.github/copilot-instructions.md`, `pkg/anomaly/Dockerfile`
  (which copies `detector.go`), `docker-compose.yml`.

### C.3 — CLI restructure

- [ ] Layout: root `main.go` → `cmd/ztap/main.go`; today's flat `cmd` package (41 files) →
  `internal/cli` (same package, one import path change). Keep `cmd/covergate` and
  `cmd/ztap-operator` where they are.
  ```bash
  mkdir -p cmd/ztap && git mv main.go cmd/ztap/main.go
  git mv cmd internal/cli   # move the 41 files, not the two sub-commands — move those back:
  git mv internal/cli/ztap-operator cmd/ztap-operator
  git mv internal/cli/covergate cmd/covergate
  # then fix package name + imports in internal/cli/*.go and cmd/ztap/main.go
  ```
- [ ] Replace the 20 `init()`-based registrations with an explicit `NewRootCmd(version string)`
  factory in `internal/cli/root.go` (register subcommands in one list); `cmd/ztap/main.go` calls
  `cli.NewRootCmd(Version).Execute()`. Preserve `PersistentPreRunE` logging behavior exactly
  (current `cmd/root.go:17-44`).
- [ ] Add a command-tree test: `internal/cli/root_test.go` asserting every expected command is
  registered with the same `Use`/flags as before.
- [ ] Update build paths: `Dockerfile`, `Dockerfile.operator`, `.goreleaser.yaml` (`main: ./cmd/ztap`),
  `ci.yml` build-check (`go build -o ... ./cmd/ztap`), docs. **Also:** `cmd/covergate`
  `isGatedPath` hardcodes `pkg/`/`cmd/` prefixes — update to `internal/`/`cmd/` or the gate
  silently stops gating after the move.

### C.4 — Verify against baseline

```bash
go build -o /tmp/ztap-new ./cmd/ztap
diff <(/tmp/ztap-baseline --help) <(/tmp/ztap-new --help)
for c in api grpc aws azure gcp agent compliance enforce version status cluster policy flows logs metrics user discovery audit; do
  diff "/tmp/ztap-help-${c}-baseline.txt" <(/tmp/ztap-new "$c" --help 2>&1) || echo "HELP-DIFF: $c"
done
go test ./... -race
sudo go test -tags=integration ./internal/enforcer -run TestEBPFIntegration -v   # Linux only
```

**Commits (in order):**
1. `refactor: move pkg/ to internal/`
2. `refactor: split CLI into cmd/ztap entrypoint and internal/cli with command factory`

---

## Phase D — Centralized config package

**Goal:** one parse, one source of truth; implement the 4 dead sections.

### D.1 — New package

- [ ] Create `internal/config/config.go`: single typed `Config` mirroring `config.yaml.example` —
  sections `api`, `grpc`, `auth`, `cluster`, `discovery`, `logging`, `alerting`, `aws`, `azure`,
  `gcp`, `audit`, plus the currently-dead `metrics`, `enforcement`, `policy`, `anomaly`.
- [ ] One loader: `Load(path string) (*Config, error)` with the existing lookup order
  (`ZTAP_CONFIG` env → `./config.yaml` → none = defaults) and yaml.v3 decoding with
  `KnownFields(true)` so typos fail loudly. **Breaking-change note:** `KnownFields` rejects
  configs containing unknown keys — existing user configs with stale/extra sections will start
  failing. Announce it in the CHANGELOG as a breaking change and consider a transition window:
  warn-and-ignore unknown keys by default, `ZTAP_CONFIG_STRICT=1` opts into hard failure.
- [ ] Table-driven loader tests: defaults, file, env override, precedence, unknown-key rejection.

### D.2 — Migrate consumers

- [ ] Replace the ~10 ad-hoc parsers: `cmd→internal/cli/{api.go:155, grpc.go, alert.go, aws.go,
  azure.go, gcp.go, auth_sessions.go, discovery.go, cluster_runtime_config.go, logs.go}` and fold
  `pkg→internal/{audit/config.go, logging/config.go}` section parsing into the central loader
  (keep those packages' `Configure(cfg)` APIs; feed them sub-structs).
- [ ] Wire through `NewRootCmd`: parse once in `PersistentPreRunE`, store on a small
  `cli.App`-style struct; precedence **flag > env > config > default**.

### D.3 — Implement the dead sections (they're documented; users expect them to work)

- [ ] `metrics.enabled/port/path` → defaults for `ztap metrics` (today: `--port` flag +
  `ZTAP_METRICS_LISTEN` only).
- [ ] `enforcement.dry_run` / `enforcement.default_action` → defaults for `ztap enforce` flags.
  `enforcement.mode` is OS-determined — remove from example/docs (note in changelog).
- [ ] `policy.strict` / `allow_empty_egress` / `resolve_labels` → defaults for
  `ztap policy validate` / `ztap enforce`.
- [ ] `anomaly.*` → consumed by Phase E.
- [ ] Sync `config.yaml.example` + `docs/reference/config.md` with the final struct (optionally
  generate the example from the struct in a test to keep them permanently in sync).

**Verify:** every command behaves identically with/without `config.yaml`; `config.yaml.example`
round-trips; `rg 'yaml.Unmarshal' internal/cli` returns only the central loader.

**Commits:**
1. `feat: add centralized internal/config package with typed loader`
2. `refactor: migrate all commands to central config (drop ad-hoc parsers)`
3. `feat: honor metrics/enforcement/policy config sections (flag > env > config)`

---

## Phase E — Wire + harden the anomaly service

**Goal:** turn the dead Python service into a real, safe feature. Biggest net-new-code phase.

### E.1 — Go wiring

- [ ] Consume `anomaly:` config (from D): existing keys `enabled`, `endpoint`, `threshold`;
  add `batch_size` (default 50), `flush_interval` (default 10s), `auth_token`, `fail_open`
  (default true).
- [ ] Extend `internal/anomaly/detector.go`: add `DetectBatch([]FlowRecord)` hitting `/batch`;
  add `Authorization: Bearer` header when token set; retry with backoff on 5xx.
  **Ordering:** the Python service currently exposes `/batch_predict`, not `/batch` — land the
  service-side endpoint (E.2 item) in the **same commit stack** as the Go pipeline, or point
  `DetectBatch` at the existing `/batch_predict`. The pipeline is untestable end-to-end until
  both sides exist.
- [ ] New `internal/anomaly/pipeline.go`: subscribes to `internal/flow.Monitor` events,
  buffers to `batch_size`/`flush_interval`, calls `DetectBatch` **async** — enforcement must
  never sit on the detection path. Service down + `fail_open`: count and continue.
- [ ] Wire into `ztap agent` (and `enforce` when flows active) behind `anomaly.enabled`.
- [ ] Emit: `metrics.SetAnomalyScore` (currently uncalled), structured log, `internal/alert`
  webhook when score > `threshold`, audit entry for high-severity anomalies.
- [ ] Tests: mock HTTP server (httptest) for detector + pipeline; fail-open test; batch flush test.

### E.2 — Python hardening (`pkg/anomaly/` → `internal/anomaly/py/` or keep dir, decide in C)

- [ ] **Determinism fix** in `service.py:21-22`: replace built-in `hash()` (randomized per
  `PYTHONHASHSEED`) with `int(ipaddress.ip_address(ip))` — current features are non-reproducible
  across restarts. Update `test_service.py` accordingly.
- [ ] Auth: `ZTAP_ANOMALY_TOKEN` env; `@require_token` decorator on `/train`, `/detect`, `/batch`.
- [ ] Bind address: **`0.0.0.0` in the container image / compose service** — the agent connects
  from another container on `ztap-net` to `anomaly-detector:5000`; a `127.0.0.1` bind inside the
  container listens on loopback only and cross-container traffic would be refused. Keep
  `127.0.0.1` as the default only for host-local dev runs, via env override
  (`ZTAP_ANOMALY_HOST`). Serve via **gunicorn** not `flask run` (`FLASK_ENV=production` in
  compose is ignored by modern Flask — remove it there when touched).
- [ ] Add `/batch` endpoint if used by E.1; model persistence via joblib (load on start, save
  after `/train`) so training survives restarts — this makes the already-pinned `joblib`
  dependency actually used (or drop it).
- [ ] Packaging: replace `requirements.txt` with `pyproject.toml` (ruff config inside; pinned
  deps); update dependabot pip path if the dir moved; add `ruff check` + `pytest` steps to the
  `test-python` CI job.
- [ ] `pkg/anomaly/Dockerfile`: stop copying `detector.go`/`README.md` into the image, add
  non-root `USER`, `HEALTHCHECK` on `/health`, CMD → gunicorn.

**Verify:** end-to-end: start service with token → run `ztap agent --dry-run` with
`anomaly.enabled: true` → generate flows → observe `ztap_anomaly_score` metric + alert webhook.
`pytest` + `ruff` green; new Go tests green.

**Commits:**
1. `feat(anomaly): async batched detection pipeline wired into flow monitor`
2. `fix(anomaly): deterministic features, token auth, gunicorn, model persistence`
3. `build(anomaly): pyproject packaging, ruff in CI, slim Dockerfile`

---

## Phase F — `log/slog` migration

**Goal:** stdlib logging core; kill global state; unify operator output. Shim-first = low blast radius.

- [ ] **F.1** Reimplement `internal/logging` internals over `slog`: `New()` builds an
  `slog.Logger` with `JSONHandler`/`TextHandler` per config; keep the existing public `Logger`
  API as a thin shim so call sites are untouched. Preserve field-sanitization behavior — write
  golden-output tests first (`internal/logging/testdata/*.golden`) since current coverage is thin
  (`logger_test.go` is 57 lines).
- [ ] **F.2** Remove global state: delete `defaultLogger`/`exitFn` (`default.go`), replace the
  stdlib-`log` hijack in `New()` (`logger.go:74-75`) with `slog.SetDefault` +
  `slog.NewLogLogger(handler, slog.LevelInfo)` bridge for etcd/client-go stdlib output.
- [ ] **F.3** Operator: replace `zap.Options{Development: true}` in `cmd/ztap-operator/main.go`
  with `logr.FromSlogHandler(...)` so both binaries share format/config.
- [ ] **F.4** Verify: log JSON schema unchanged (golden tests), `ztap logs --follow/--level`
  filtering works, operator emits structured production logs, full test suite + race.
- [ ] **F.5 (optional follow-up):** migrate call sites to `slog` directly; retire the shim.

**Commits:**
1. `refactor(logging): reimplement over log/slog behind existing API`
2. `refactor(logging): remove global default logger and stdlib hijack`
3. `refactor(operator): unify logging via logr-over-slog`

---

## Appendix A — Per-phase verification matrix

| Phase | Build | Unit+race | Lint | Security | Extra |
|---|---|---|---|---|---|
| A | ✅ | ✅ | ✅ | `scripts/security_check.sh` | ✅ complete — see completed-workstreams table |
| B | — | — | actionlint + zizmor | — | ✅ complete — residual: cosign verify on first tagged release |
| C | ✅ | ✅ | ✅ | — | help-output diff (C.4), eBPF integration test |
| D | ✅ | ✅ | ✅ | — | config round-trip + precedence tests |
| E | ✅ | ✅ | ✅ | — | live service e2e, `pytest`, `ruff` |
| F | ✅ | ✅ | ✅ | — | golden log-output tests |

> Rows A and B are historical (completed); the matrix gates C–F going forward.

## Appendix B — Out of scope (flagged for later)

Found during the audit, not covered by the selected workstreams:

- **Docker/compose/k8s beyond B.2:** compose `version:` key removal, prometheus v2.48→v3 /
  grafana 10.2→11+ bumps, healthchecks for all services, `./config` mount points at a nonexistent
  dir, Grafana creds externalization, `USER ztap` vs eBPF-capabilities conflict, kustomize/Helm
  single-sourcing, pinned image tags (kill `:latest`), capability-based agent instead of full
  `privileged`, operator `seccompProfile`, duplicate root `grafana-dashboard.json`.
- **Operator generation story:** adopt controller-gen/kubebuilder — CRD YAML duplicated in
  `ztap-install.yaml` vs `ztapnetworkpolicy-crd.yaml` (433 lines each), RBAC annotation↔ClusterRole
  drift, hand-written DeepCopy.
- **Docs cleanup:** Go "1.25+" refs (`README.md:5,452`, `docs/guides/setup.md:10`,
  `docs/guides/etcd.md:41`, `docs/concepts/ebpf.md:53`) vs go.mod 1.26.5; phantom
  `tests/fixtures/test-policy.yaml` in `docs/guides/testing.md:236`; nonexistent "Consul backend"
  mention (`testing.md:331`); empty `tests/data/`; stale CHANGELOG "1.25.8" line.
- **Observability:** custom Prometheus registry instead of global `MustRegister`; drop redundant
  mutex + legacy duplicated flow counters (`collector.go:102-107`); OpenTelemetry is entirely
  indirect/unused — wire it or prune.
- **Security defaults:** TLS off by default for api/grpc, rate limiting off by default,
  `audit.integrity_mode: "none"` default, Trivy `continue-on-error` in `security.yml`.
- **Working-dir hygiene:** ~800 MB of ignored local build artifacts (`*.test.exe`, `ztap*`,
  `coverage*.out`) — add a `clean` target when a top-level Makefile/Taskfile lands.
- **Top-level Makefile/Taskfile:** unify `build/test/lint/generate/security/compose` entry points.

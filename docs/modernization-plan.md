# ZTAP Modernization Plan — Execution Checklist

> **Purpose:** step-by-step execution plan to bring ZTAP in line with current (2026) standards.
> Generated from a full codebase audit. Each phase is independently shippable; phases are ordered to
> minimize merge conflicts (mechanical edits → additive CI work → big rename → deep refactors).
>
> **Status (2026-02):** Phases A, B, C and D are **complete and verified** against the tree (evidence in
> the completed-workstreams tables below; a handful of residuals are listed there). The active
> checklist is **E → F**. Path references inside the A/B/C/D evidence tables reflect the layout
> at the time of verification (the Phase C/D tables use the post-move `internal/` paths).
>
> **Scope decisions (agreed):**
> - ✅ In scope: quick code modernization (A), CI/release supply chain (B), `pkg/`→`internal/` + cmd split (C), centralized config (D), anomaly service wire-up + hardening (E), `log/slog` migration (F).
> - ❌ Out of scope (see Appendix B): broad Docker/compose/k8s-manifest modernization (except what release signing requires), standalone docs cleanup, operator controller-gen adoption.

**Conventions used below:**
- Commands assume macOS dev shell (`sed -i ''`); on Linux use `sed -i`.
- Commit messages follow the repo's conventional-commit style (`ci:`, `build:`, `refactor:`, `feat:`, `test:`, `docs:`, `chore:`).
- New GitHub Actions are written with version tags + `# TODO: pin to SHA` — the repo convention is 100% SHA pinning; resolve and pin before merging. **Exception:** SLSA's v2.1.0 generic generator requires a semantic tag reference, so the release workflow uses `@v2.1.0` with a documented zizmor exception.
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
- [x] **0.2** Snapshot CLI surface (used to prove the Phase C restructure changes nothing user-visible):
  ```bash
  go build -o /tmp/ztap-baseline .
  /tmp/ztap-baseline --help > /tmp/ztap-help-baseline.txt
  for c in api grpc aws azure gcp agent compliance enforce version status cluster policy flows logs metrics user discovery audit; do
    /tmp/ztap-baseline "$c" --help > "/tmp/ztap-help-${c}-baseline.txt" 2>&1 || true
  done
  ```
  *(done on `modernization/main` before Phase C — `/tmp/ztap-baseline` sha256 `87907512…`)*
- [x] **0.3** Snapshot policy round-trip (proves the yaml v2→v3 migration is wire-safe):
  ```bash
  go build -o /tmp/ztap-baseline .
  for f in examples/*.yaml; do /tmp/ztap-baseline policy validate -f "$f" || echo "BASELINE-FAIL: $f"; done
  ```
  *(done — per-file outputs saved to `/tmp/ztap-policy-*-baseline.txt`; note `examples/deny-all.yaml`
  intentionally exits 1: its `deny-all-default` policy has `egress: []` and the validator requires at
  least one rule. That is baseline behavior, preserved byte-for-byte after C.)*

> **Note:** 0.2/0.3 snapshots live in `/tmp` and are ephemeral — re-capture them on the working
> branch immediately before Phase C starts (the baseline binary has since been rebuilt).

- [x] **0.4** Working branch: `git checkout -b modernization/main` (each phase merges or stacks; see commit splits).

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
| B.1 GoReleaser | `.goreleaser.yaml` present (cosign sign-blob, SBOMs, checksums); `release.yml` has cosign + `sbom: true`/`provenance: mode=max` on build-push-action, the correct SLSA `generator_generic_slsa3.yml` job (v2.1.0 semantic tag required upstream), and tag/CHANGELOG release-note handling. **Residual:** `cosign verify-blob` / `gh release view` on the *first tagged release* — cannot be done before a tag exists |
| B.2 Dockerfiles | `alpine:3.24` SHA-pinned runtime (EOL 3.19 gone); `ARG VERSION` + `-trimpath -ldflags` build lines; OCI labels incl. `org.opencontainers.image.version` |
| B.3 covergate ratchet | `-baseline`/`-update-baseline` flags in `cmd/covergate`; `ci.yml:193` runs it with `.covergate-baseline.json` and no `\|\| echo`; empty benchmark job deleted; documented in `CONTRIBUTING.md` + `docs/guides/testing.md` |
| B.4 golangci v2 | `.golangci.yml` matches the proposed v2 config — govet + gofmt/goimports formatters enabled |
| B.5 drift checks | buf lint/breaking + `./scripts/gen_proto.sh && git diff --exit-code` (`ci.yml:160`); eBPF regenerate drift check (`ci.yml:383-384`). `buf.yaml` still v1 — optional v2 migration deferred, fine |
| B.6 dependabot | docker ecosystems (root + `internal/anomaly`), 7-day cooldowns on Go, pip, GitHub Actions, and Docker updates, and the dedicated `k8s` group are present |
| B.7 supply chain | `scorecard.yml` present with SARIF upload + `publish_results: true`, all actions except the upstream-required SLSA semantic tag are SHA-pinned with version comments (the SLSA exception has an explicit zizmor suppression); shellcheck + zizmor jobs in `ci.yml`. Note: the README badge was added, then **deliberately removed** (b274f26 / 71764c2 "Remove badges") — not an open item |

**Residual to close (small):** cosign/provenance verification on first tagged release.

---

## Phase C — Structure: `pkg/` → `internal/` + cmd split ✅ COMPLETE (verified 2026-02)

**Goal:** idiomatic layout; `internal/` communicates app-not-library. Big rename — landed as a
focused 3-commit PR on `modernization/main`. Every item below was verified against the tree.

| Item | Evidence (verified in tree) |
|---|---|
| C.1 module path | Kept the bare `ztap` module path (decision recorded below); no `go.mod` churn |
| C.2 move packages | `git mv pkg internal`; 0 imports of `ztap/pkg/` remain (verified by `rg '"ztap/pkg' --type go`); external deps containing `/pkg/` (`github.com/pkg/browser`, `go.etcd.io/etcd/pkg/v3`, `k8s.io/apimachinery/pkg/...`) untouched; `tools/bpfgen` path fixed |
| C.2 exception | Not taken: no external importers exist (bare module path) so `internal/operator/api/v1alpha1` + `internal/policy` moved like everything else |
| C.2 non-Go refs | `README.md`, `CONTRIBUTING.md`, `docs/**` (incl. `architecture.md`), `.github/copilot-instructions.md`, `.github/dependabot.yml`, `ci.yml` (coverpkg, eBPF drift check, docker context, fuzz targets), `release.yml` (docker context), `docker-compose.yml`, and build scripts use the post-move paths. Historical Phase A notes and generated dependency provenance comments may still mention the former `pkg/` layout. |
| C.3 CLI layout | `cmd/ztap/main.go` entrypoint; flat `cmd` package (36 files) → `internal/cli` (`package cli`); `cmd/ztap-operator` + `cmd/covergate` stay; `Dockerfile` builds `./cmd/ztap`, `.goreleaser.yaml` `main: ./cmd/ztap`, `ci.yml` matrix build uses `./cmd/ztap` |
| C.3 factory | All 21 `func init()`s in the old `cmd` package removed (`rg 'func init\(' internal/cli cmd/ztap` → 0); `NewRootCmd(version string)` in `internal/cli/root.go` registers the 19 top-level commands in one list; `PersistentPreRunE` logging behavior preserved; cluster backends are created during construction but started only from `PersistentPreRunE` for cluster/policy commands, after Cobra installs the command context, and stopped in the persistent post-run hook |
| C.3 command tree test | `internal/cli/root_test.go`: asserts all 19 top-level + nested commands with expected `Use`, persistent flags, and version propagation (`NewRootCmd("9.9.9-test")` → `ztap version` prints it) |
| C.3 covergate | `cmd/covergate` `isGatedPath` now `internal/`+`cmd/`; `isExcludedByPattern` updated to `internal/enforcer/bpf_bpf*`; `.covergate-baseline.json` remapped: 84 `internal/` entries kept, 28 `cmd/`→`internal/cli/` paths renamed, `cmd/ztap/main.go` added at 0.0 (same convention as operator/covergate mains) |
| C.4 help parity | `diff` of root + all 17 subcommand `--help` outputs vs pre-flight baseline: **identical**; nested subcommands (`api serve`, `aws inventory export`, `cluster config set-backend`, …) all present |
| C.4 policy parity | `policy validate` output diff vs baseline for all 8 `examples/*.yaml` (incl. the intentional `deny-all.yaml` exit-1): **identical** |
| C.4 tests | `go build ./... && go test ./... -race` green; `golangci-lint run` (CI-pinned v2.12.2) 0 issues; `golangci-lint fmt` clean. eBPF integration test (`TestEBPFIntegration`) not run — Linux-only, macOS host |
| C.4 generated files | `internal/enforcer/bpf_bpf{el,eb}.go` comment updated to `./internal/enforcer/...` (matches `tools/bpfgen` output; bytecode bytes untouched — regeneration on Linux CI must stay byte-identical) |

**Commits (landed on `main`, 2026-02):**
1. `refactor: move pkg/ to internal/` (fc4de4e)
2. `refactor: split CLI into cmd/ztap entrypoint and internal/cli with command factory` (cbd9b57)
3. `chore: update covergate baseline and eBPF build paths for internal/ move` (76a1739)
4. `docs: mark Phase C complete in modernization plan` (970961e)

### C.1 — Module path decision (recorded)

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

---

## Phase D — Centralized config package ✅ COMPLETE (verified 2026-02)

**Goal:** one parse, one source of truth; implement the 4 dead sections. Landed as 3 commits; every
item below was verified against the tree.

| Item | Evidence (verified in tree) |
|---|---|
| D.1 new package | `internal/config/config.go`: single typed `Config` with all 15 sections incl. the dead `metrics`, `enforcement`, `policy`, `anomaly`; `Load(path)` resolves `ZTAP_CONFIG` env → `./config.yaml` → defaults; defaults pre-populated so absent keys keep documented values and **present keys override** (no pointer soup); `Duration`/`String` custom YAML types preserve the old "explicit empty = keep default" semantics (`config.go` `UnmarshalYAML`) |
| D.1 strict mode | `ZTAP_CONFIG_STRICT=1` → `KnownFields(true)` hard failure; default = warn-and-ignore with stderr warning listing unknown keys (probe decode). CHANGELOG announced as breaking change; `config.yaml.example` + `docs/reference/config.md` updated |
| D.1 loader tests | `internal/config/config_test.go`: defaults, file override, explicit-empty-keeps-default, env precedence, unknown-key warn (captured stderr), strict rejection, invalid duration, **strict round-trip of `config.yaml.example`** (keeps example ↔ struct in sync) |
| D.2 migrate consumers | `rg 'yaml.Unmarshal' internal/cli` → 0; `rg 'logging.LoadConfig|audit.LoadConfig|LoadConfigFromFile'` → 0. Ad-hoc parsers deleted: `apiConfigFile`, `grpcConfigFile`, `alertConfigFile`, `aws/azure/gcpConfigFile`, `authSessionsConfigFile`, `clusterConfigFile`, inline discovery struct, `audit.fileConfig`, `logging.fileConfig`. `audit.LoadConfigFromFile/LoadConfig` replaced by `audit.OptionsFromSection(cfg.Audit)`; `logging.LoadConfig` deleted (root + `logs` read the central config); `apiutil.DefaultAuditLogger` uses the central loader |
| D.2 App wiring | `cli.App` struct in `internal/cli/root.go`; `PersistentPreRunE` parses once into `app.cfg`; all 15 config-consuming command constructors take `*App`; `App.Config()` lazily loads for direct-invocation unit tests; `initClusterBackend` unchanged |
| D.2 precedence | **flag > env > config > default** everywhere: `cmd.Flags().Changed()` gates flag application (API/gRPC `--auth`, rate-limit, TLS; `enforce --dry-run/--resolve-labels/--default-action`; `policy validate --strict/--allow-empty-egress`; `metrics --port`). Side effect: `api.auth.enabled: false` in config is now honored (previously the `--auth` flag default true silently overrode it) — noted in CHANGELOG |
| D.2 env centralization | All ~40 `ZTAP_*` overrides (logging, alerting, auth sessions, cluster/etcd, aws/azure/gcp, audit, metrics listen) applied once in `applyEnvOverrides`; malformed env durations now fail loudly (CHANGELOG note); `ZTAP_ALERT_SLACK_WEBHOOK_URL`/`PAGERDUTY_ROUTING_KEY` still imply `alerting.enabled: true` |
| D.3 metrics | `metrics.enabled/port/path` honored by `ztap metrics` (disabled → explicit message; `metrics.StartServer(listen, path)` — no more hardcoded `/metrics`); `ZTAP_METRICS_LISTEN` still wins for the bind address |
| D.3 enforcement | `enforcement.dry_run` → `ztap enforce --dry-run` default; new `--default-action` flag (block\|allow, validated) backed by `enforcement.default_action`; threaded into `EnforcementOptions.DefaultAction` and honored by the pf backend (allow → catch-all pass rules; block → historical behavior); eBPF/WFP remain default-deny (documented). `enforcement.mode` **removed from example/docs** (OS-determined, never read) — CHANGELOG note |
| D.3 policy | `policy.strict` → `ztap policy validate --strict` (false = warn + exit 0); `policy.allow_empty_egress` → `--allow-empty-egress` via new `policy.ValidateWithOptions(ValidateOptions{})` (also used by `ztap enforce`); `policy.resolve_labels` → `ztap enforce --resolve-labels` default (auto-enable on podSelector policies preserved) |
| D.3 anomaly | `anomaly.*` section defined with existing keys + `batch_size` (50), `flush_interval` (10s), `auth_token`, `fail_open` (true) — consumed by Phase E |
| D.3 docs sync | `config.yaml.example` + `docs/reference/config.md` updated (mode removed, new keys + env documented, `ZTAP_CONFIG_STRICT` documented); round-trip enforced by `TestExampleConfigRoundTrip` |
| Gate | `go build ./... && go test ./... -race` green; `golangci-lint run` (CI-pinned v2.12.2) 0 issues; manual smoke: `policy validate` exit codes preserved (incl. `deny-all.yaml` exit 1), `metrics` serves custom path/port from config, `--default-action` validation, all subcommand `--help` intact |

**Commits (landed on `main`, 2026-02):**
1. `feat: add centralized internal/config package with typed loader` (b9f2581)
2. `refactor: migrate all commands to central config (drop ad-hoc parsers)` (1183232)
3. `feat: honor metrics/enforcement/policy config sections (flag > env > config)` (see log)

**Residuals:** `metrics.enabled` only gates `ztap metrics` (API/gRPC servers still always serve `/metrics`); `enforcement.default_action: allow` only affects the pf backend; the config file is read once per invocation, not watched/reloaded — none were in scope for D.

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

### E.2 — Python hardening (`internal/anomaly/` — the dir was moved in C, kept in place)

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
- [ ] `internal/anomaly/Dockerfile`: stop copying `detector.go`/`README.md` into the image, add
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
| C | ✅ | ✅ | ✅ | — | ✅ complete — help diff + policy round-trip vs baseline, eBPF integration test pending Linux CI |
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
  `audit.integrity_mode: "none"` default.
- **Working-dir hygiene:** ~800 MB of ignored local build artifacts (`*.test.exe`, `ztap*`,
  `coverage*.out`) — add a `clean` target when a top-level Makefile/Taskfile lands.
- **Top-level Makefile/Taskfile:** unify `build/test/lint/generate/security/compose` entry points.

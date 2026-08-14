# ZTAP Modernization Plan — Execution Checklist

> **Purpose:** step-by-step execution plan to bring ZTAP in line with current (2026) standards.
> Generated from a full codebase audit. Each phase is independently shippable; phases are ordered to
> minimize merge conflicts (mechanical edits → additive CI work → big rename → deep refactors).
>
> **Status (2026-02):** Phases A, B, C, D, E and F are **complete and verified** against the tree (evidence in
> the completed-workstreams tables below; a handful of residuals are listed there). The active
> checklist is empty — remaining items are residuals/follow-ups noted per phase. Path references
> inside the A–E evidence tables reflect the layout at the time of verification (the Phase C/D/E
> tables use the post-move `internal/` paths).
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

## Phase E — Wire + harden the anomaly service ✅ COMPLETE (verified 2026-02)

**Goal:** turn the dead Python service into a real, safe feature. Biggest net-new-code phase.
The original implementation landed as 4 commits on `main`; the review hardening below is also verified against the current tree.

| Item | Evidence (verified in tree) |
|---|---|
| E.1 config | `anomaly:` section consumed end-to-end: `enabled`, `endpoint`, `threshold` + new `batch_size` (50), `flush_interval` (10s), `auth_token`, `fail_open` (true) already landed in D; `internal/cli/anomaly.go` `startAnomalyRunner` reads every key and passes them into the pipeline/detector options |
| E.1 detector | `internal/anomaly/detector.go`: `DetectBatch([]FlowRecord)` posts `{"flows": [...]}` to `/batch`, validates exact totals, prediction cardinality, unique indexes, required fields, finite 0–100 scores, and anomaly counts; `Authorization: Bearer` header when token set (`WithAuthToken`); retries 408/429/5xx + transport errors with exponential backoff (`WithRetries`/`WithRetryBackoff`, defaults 2 retries/200ms) and bounds response bodies. The service-side `/batch` endpoint uses the same schema — no reliance on the legacy `/batch_predict` endpoint |
| E.1 pipeline | `internal/anomaly/pipeline.go`: buffers `FlowRecord`s to `batch_size`/`flush_interval`, flushes into a **detached** goroutine — ingestion never blocks on the service. `fail_open` (true): failed batches counted + dropped, pipeline continues; `fail_open` (false): pipeline stops on the first detection error with synchronized stop signaling. `Submit` is lock-free and drops (counted) when the queue is full; normal shutdown drains queued flows and flushes the partial batch, then waits for every detached detection. Zero-value threshold/fail-open defaults are explicit and overrideable |
| E.1 wiring | `ztap agent` (always) and `ztap enforce` (Linux + Windows, non-dry-run) start the pipeline behind `anomaly.enabled` via `startAnomalyRunner`; a flow `Monitor` over the platform reader feeds `Submit` with a pre-registered subscription; Linux anomaly readers wait for the real pinned map and never use synthetic demo flows. Setup failures only warn (detection is advisory). The anomaly runner embeds the metrics endpoint when enabled and creates the configured audit logger when enforcement does not provide one. Shutdown waits for the monitor, pipeline detections, alerts, and audit callbacks in order |
| E.1 emit | `metrics.SetAnomalyScore` via `OnScore` with the batch max and an embedded metrics server in agent/enforce; structured `logging.Info` per anomaly; `internal/alert` webhook when score > `threshold` (`SeverityWarning`, dedup key `anomaly:<src>:<port>`); audit entry `anomaly.detected` (new event type in `internal/audit/audit.go`) for high-severity anomalies, including the enforce path |
| E.1 tests | httptest detector tests: `/batch` payload+decode, strict response validation, Bearer header present/absent, 408/429/5xx retry behavior, retries exhausted, transport errors; pipeline tests: defaults, batch-size flush, interval flush, manual `Flush`, fail-open continues + OnError, concurrent fail-closed failures, anomaly/score callbacks, queue overflow drops, flush-on-shutdown — all `-race` clean. Flow startup subscription and embedded metrics endpoint are covered |
| E.2 determinism | `service.py` `_ip_feature`: `int(ipaddress.ip_address(ip)) % 10000` (was `hash()`, randomized per `PYTHONHASHSEED`); malformed IPs → stable 0; `test_service.py` asserts known values (192.168.1.100 → 5876, 10.0.0.50 → 2210) and repeatability |
| E.2 auth | `ZTAP_ANOMALY_TOKEN` env; `@require_token` (constant-time `hmac.compare_digest`) on `/train`, `/detect`, `/batch`, `/predict`, `/batch_predict`; `/health` open for container healthchecks; auth suite tests 401/200/wrong-token; Go side presents the configured `anomaly.auth_token` |
| E.2 bind/serving | Container/compose: gunicorn binds `0.0.0.0` with one worker (model state is process-local; horizontal scaling requires shared state); agent connects cross-container to `anomaly-detector:5000` via `ZTAP_ANOMALY_ENDPOINT`; host-local dev `python service.py` binds `127.0.0.1` via `ZTAP_ANOMALY_HOST`; `FLASK_ENV=production` removed from compose (ignored by modern Flask) |
| E.2 /batch + persistence | `/batch` returns the `/detect` schema per prediction (index/score/is_anomaly/reason), rejects malformed flow items, and uses rule-based fallback when untrained; ML scores map the Isolation Forest decision boundary to 50 so they agree with Go thresholding; model persisted atomically with joblib to `$MODEL_PATH/model.joblib` after `/train` and loaded on start (`load_model`/`save_model`) — persistence and score-calibration tests pass |
| E.2 packaging | `requirements*.txt` (uv-compiled, stale `pkg/anomaly/` paths) deleted; `pyproject.toml` with pinned deps (flask 3.1.3, scikit-learn 1.9.0, numpy 2.5.1, joblib 1.5.3, gunicorn 26.0.0), `[dev]` extra (pytest 9.1.1, pytest-cov 7.1.0, ruff 0.16.2), ruff config inside; dependabot pip path already `/internal/anomaly` (post-C) and picks up pyproject.toml; `test-python` CI installs `-e "[dev]"` and runs `ruff check .` before pytest |
| E.2 Dockerfile | no more `detector.go`/`README.md` copies, no apt/curl layer; `pip install .` from pyproject; non-root `USER 65532` with writable `/app/models`; `HEALTHCHECK` via urllib (no curl in image); CMD gunicorn; `internal/anomaly/.dockerignore` excludes test artifacts from the build context |

**Verify (local, macOS):** `go build ./... && go test ./... -race` green; detector, pipeline, flow, CLI, and metrics tests pass under race detection; `pytest` 24 passed / `ruff check .` clean in a py3.13 venv against the pinned versions. The covergate run reports no new failures against the baseline; 21 pre-existing platform-specific baseline deficits remain (two baseline deficits improved by the new tests). Live end-to-end (`ztap agent --dry-run` → real flow source → `ztap_anomaly_score` + webhook) requires a Linux/Windows host with a flow source and the container service — deferred to the first tagged release, same as Phase B's cosign residual.

**Commits (landed on `main`, 2026-02):**
1. `feat(anomaly): async batched detection pipeline wired into flow monitor` (a9e6582)
2. `fix(anomaly): deterministic features, token auth, gunicorn, model persistence` (217e66a)
3. `build(anomaly): pyproject packaging, ruff in CI, slim Dockerfile` (d021eeb)
4. `docs: mark Phase E complete in modernization plan` (this commit)

---

## Phase F — `log/slog` migration ✅ COMPLETE (verified 2026-02)

**Goal:** stdlib logging core; kill global state; unify operator output. Shim-first = low blast radius.

**Status:** every item below was verified against the tree. `internal/logging` is now a thin shim over `log/slog`; the emitted JSON/text schema is preserved and deterministic (pinned by golden tests, with sorted text field keys), all ~300 package-level call sites are untouched, and the operator shares the same core.

| Item | Evidence (verified in tree) |
|---|---|
| F.1 slog core | `internal/logging/logger.go` builds a `slog.Logger` over the custom `ztapHandler` (`internal/logging/handler.go`) which reproduces the historical schema: JSON lines `{"timestamp":"<RFC3339Nano UTC>","level":"info","message":"...","fields":{...}}` (fields omitted when empty) and text lines `2026-01-02T15:04:05Z [INFO] message key=value`. Sanitization preserved (CR/LF → space + trim in messages; field keys trimmed, empties dropped); field keys are now **sorted** (was map-iteration order — deterministic improvement, JSON was already sorted by `encoding/json`). The public `Logger` API (incl. `Printf`/`Println`/`Write`/`SetLevel`/`SetFormat`/`SetOutput`/`Output` + new `Handler()`) is a thin shim; `rg 'logging\.' internal cmd | wc` ≈ 300 untouched call sites. New `Handler()` exposes the slog handler for the operator bridge |
| F.1 golden tests | `internal/logging/testdata/{json,text}.golden` pin the exact lines for all four levels, empty-fields omission, message sanitization, and field-key trimming/sorting; `golden_test.go` emits through the public API and normalizes only the timestamp. `logger_test.go` bridge tests stdlib `log.Printf`, `slog.Info`, and level filtering; `handler_test.go` covers `LogValuer`/error values, canonical logr verbosity levels, and concurrent writes producing valid JSON lines |
| F.2 global state | `internal/logging/default.go` no longer has `defaultLogger`/`Default()`/`exitFn`; it retains only the package-level helpers, while `default_test.go` was removed. Helpers (`Info`/`Warn`/`Error`/`Debug`/`*f`/`Fatal`/`Fatalf`) delegate to `slog.Default()`, and `Fatal` calls `os.Exit(1)` directly. `Configure` = `New` + the process-wide install. Before the first `Configure` (CLI always configures in `PersistentPreRunE`) helpers fall back to the stdlib default (text to stderr) instead of a lazily-created JSON-on-stdout singleton |
| F.2 stdlib bridge | `New`/`SetFormat`/`SetOutput` re-install via `rebuildLocked`: `slog.SetDefault(l.slog)` — **deviation from the plan text, same effect**: the plan's `slog.NewLogLogger(handler, slog.LevelInfo)` bridge is now built into `slog.SetDefault` (its internal `handlerWriter` links the stdlib `log` sink at `SetLogLoggerLevel`, default info), and `(*log.Logger).Write` no longer exists on Go 1.26 so the explicit `log.SetOutput(slog.NewLogLogger(...))` wiring no longer compiles. etcd/client-go stdlib output is still routed through the configured handler at info level and still filtered by the configured level |
| F.3 operator | `cmd/ztap-operator/main.go` drops `zap.Options{Development: true}` + the `--zap-*` flag family; `logging.New(operatorLoggingConfig())` reads the shared defaults + `ZTAP_LOG_LEVEL`/`ZTAP_LOG_FORMAT`/`ZTAP_LOG_FILE` and `ctrl.SetLogger(logr.FromSlogHandler(logger.Handler()))`. Smoke-verified: without a kubeconfig the operator emits structured JSON with error values rendered as strings and text mode emits `2026-…Z [ERROR] …` (logr names become `logger` fields). Invalid logging configuration is reported directly to stderr before the controller-runtime logger is installed. `setupLog` remains the deferred controller-runtime logger for post-configuration errors. `go mod tidy`: `go-logr/logr` direct, `go-logr/zapr` dropped |
| F.4 verify | Gate: `go build ./...` + `go test ./... -race` (24 packages ok) + `golangci-lint run` (CI-pinned v2.12.2) 0 issues; `go vet ./...` clean. `ztap logs` smoke against slog-produced files: `--level warn` filters debug/info, `--contains` works, `--follow --tail 1` prints the tail then live-appended JSON entries; text-format lines still pass through raw (pre-existing reader behavior). Regression tests cover concurrent handler writes, slog value resolution, error serialization, and logr level normalization. Operator binary emits both formats |
| F.5 optional | **Not taken** — call sites stay on the shim (~300 package-level + Logger-method calls); retiring it is a mechanical follow-up when desired |

**Commits (landed on `main`, 2026-02):**
1. `refactor(logging): reimplement over log/slog behind existing API`
2. `refactor(logging): remove global default logger and stdlib hijack`
3. `refactor(operator): unify logging via logr-over-slog`
4. `docs: changelog entries for Phase F (slog logging, operator unification)`
5. `docs: mark Phase F complete in modernization plan`
6. `fix(logging): harden slog handler and operator startup diagnostics`
7. `docs: record Phase F review fixes`

**Residuals (pre-existing, fixed as a drive-by chore):** 8 golangci findings on `main` before F (3 no-verb `fmt.Errorf` in `internal/anomaly` + 5 dead `cluster.go` symbols orphaned by the Phase C cmd split) — fixed in `chore: fix pre-existing golangci findings` so the gate is green. Live log-format e2e through a long-running `ztap agent` on Linux/Windows still deferred to the first tagged release (same as Phases B/E residuals).

---

## Appendix A — Per-phase verification matrix

| Phase | Build | Unit+race | Lint | Security | Extra |
|---|---|---|---|---|---|
| A | ✅ | ✅ | ✅ | `scripts/security_check.sh` | ✅ complete — see completed-workstreams table |
| B | — | — | actionlint + zizmor | — | ✅ complete — residual: cosign verify on first tagged release |
| C | ✅ | ✅ | ✅ | — | ✅ complete — help diff + policy round-trip vs baseline, eBPF integration test pending Linux CI |
| D | ✅ | ✅ | ✅ | — | config round-trip + precedence tests |
| E | ✅ | ✅ | ✅ | — | `pytest` 24 passed + `ruff check` clean (py3.13 venv, pinned versions); Go race suite and focused repeated detector/pipeline tests pass; covergate has no new failures; live e2e deferred to first tagged release (needs Linux/Windows + container service) |
| F | ✅ | ✅ | ✅ | — | golden log-output tests + `ztap logs` filter/follow smoke, operator JSON/text smoke; **F.5 (call-site migration to slog) not taken** — optional follow-up |

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

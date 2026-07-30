# ZTAP Modernization Plan — Execution Checklist

> **Purpose:** step-by-step execution plan to bring ZTAP in line with current (2026) standards.
> Generated from a full codebase audit. Each phase is independently shippable; phases are ordered to
> minimize merge conflicts (mechanical edits → additive CI work → big rename → deep refactors).
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

- [ ] **0.1** Baseline: confirm clean tree and green tests.
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
- [ ] **0.4** Working branch: `git checkout -b modernization/main` (each phase merges or stacks; see commit splits).

---

## Phase A — Quick code modernization (mechanical, low-risk)

**Goal:** one uniform idiom baseline. Most of A2–A4 and A8 is auto-fixable with the Go team's
`modernize` suite; do tool-driven fixes first, then the manual items.

### A.1 — Unify YAML on v3

Files importing `gopkg.in/yaml.v2` (7): `pkg/policy/policy.go:22`,
`pkg/operator/controllers/ztapnetworkpolicy_controller.go:7`,
`pkg/operator/controllers/converter_test.go:7`, `cmd/discovery.go:14`, `cmd/azure.go:16`,
`cmd/gcp.go:16`, `cmd/aws.go:18`.

- [ ] Edit all 7 files: import `gopkg.in/yaml.v3` as `yaml` (drop the v2 import).
  ```bash
  rg -l 'gopkg.in/yaml.v2' --type go | xargs sed -i '' 's|yaml "gopkg.in/yaml.v2"|yaml "gopkg.in/yaml.v3"|; s|"gopkg.in/yaml.v2"|"gopkg.in/yaml.v3"|'
  go mod tidy   # yaml.v2 should drop out of go.mod
  rg 'gopkg.in/yaml.v2' go.mod go.sum || true   # confirm gone
  ```
- [ ] **Wire-safety check** (policy + operator converter moved together — the operator marshals
  ConfigMap YAML that agents unmarshal): re-run the Pre-flight 0.3 validation and the operator tests.
  ```bash
  go test ./pkg/policy/... ./pkg/operator/... -count=1
  for f in examples/*.yaml; do go run . policy validate -f "$f" || echo "FAIL: $f"; done
  ```
- [ ] Watch for v3 strictness differences: duplicate map keys now error (good), `omitempty`
  zero-value behavior, `inline` maps. Fix any fallout in `pkg/policy` types.

**Commit:** `refactor: unify YAML handling on gopkg.in/yaml.v3 (drop yaml.v2)`

### A.2 — Tool-driven idiom fixes (errors.New, slices.Sort, any, CutPrefix, min, for-range-int)

- [ ] Run the modernize suite (covers `interface{}`→`any`, `sort.Strings`→`slices.Sort`,
  `fmt.Errorf` without args→`errors.New`, `min`/`max`, `range`-over-int, and more):
  ```bash
  go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -test -fix ./...
  go build ./... && go test ./...
  ```
- [ ] Expected hotspots to spot-check manually afterwards: `pkg/cluster/*` (≈159 no-format
  `fmt.Errorf`), `pkg/discovery/*` + `pkg/enforcer/*` (≈44 `sort.Strings`), `pkg/audit/*` +
  `pkg/enforcer/policy_enforcer.go` + `cmd/aws.go` (≈20 `interface{}`; skip k8s
  `cache.ResourceEventHandlerFuncs` signatures — they're API-dictated), `pkg/apigrpc/server.go:1617`
  (`min` clamp), `pkg/apihttp/{users,cluster,policies}.go` + `pkg/compliance/mapping_annotations.go`
  + `pkg/logging/logger.go` + `pkg/audit/config.go` (`strings.CutPrefix`).

**Commit:** `refactor: apply gopls modernize fixes (any, slices, errors.New, min, CutPrefix)`

### A.3 — Typed atomics

- [ ] `pkg/alert/dispatcher.go:73,85,91,96` and `pkg/flow/reader_windows.go` (≈14 sites):
  convert `atomic.AddUint64(&x, 1)` / `atomic.LoadUint64(&x)` package-func style to typed
  `atomic.Uint64` / `atomic.Bool` struct fields. (No autofix; hand-edit, tests in both packages
  must pass unchanged.)

**Commit:** `refactor: use typed sync/atomic fields in alert and flow packages`

### A.4 — Error-chain fixes (manual)

- [ ] `pkg/enforcer/iptables_linux.go:39` — `fmt.Errorf("%v: %s", err, ...)` → `fmt.Errorf("%w: %s", err, ...)`.
- [ ] `pkg/apigrpc/server.go` (~8 sites, lines 866–976) — replace the
  `fmt.Errorf("...: %w", err).Error()` anti-pattern with direct `status.Errorf(codes.X, "...: %v", err)`.
- [ ] `pkg/cluster/policy_sync_etcd.go:479-480` — delete `var _ = errors.New(...)` import-keeper hack
  and the now-unneeded import.
- [ ] `pkg/enforcer/policy_enforcer.go:80` — handle the swallowed `os.UserHomeDir()` error
  (fall back to a temp dir or return the error).

**Commit:** `fix: preserve error chains in enforcer and gRPC server paths`

### A.5 — Context hygiene quick wins

- [ ] `pkg/audit/audit.go:277,358,430,684` + `pkg/audit/file_read.go:87`: `err == io.EOF` → `errors.Is(err, io.EOF)`.
- [ ] `pkg/cluster/election_etcd.go:446`: `err == context.Canceled` → `errors.Is(err, context.Canceled)`.
- [ ] `pkg/cluster/election_etcd.go:450`: replace uncancellable `time.Sleep(HeartbeatInterval)` in the
  campaign retry loop with `select { case <-e.ctx.Done(): ...; case <-time.NewTimer(...).C: }`
  (defer timer Stop) — shutdown currently blocks up to a full heartbeat.
- [ ] `pkg/discovery/discovery.go:179-196` and `pkg/alert/dispatcher.go:65-68`: replace
  "goroutine that only waits for `<-ctx.Done()`" with `context.AfterFunc`.

**Commit:** `fix: cancellable etcd campaign loop and context-aware error checks`

### A.6 — Test suite refresh

- [ ] `context.Background()` → `t.Context()` in tests (~100 sites; modernize suite flags some,
  finish by hand with `rg 'context.Background\(\)' --type go -g '*_test.go'`).
- [ ] `pkg/enforcer/ebpf_linux_integration_test.go:552`: `os.Setenv` → `t.Setenv`.
- [ ] Remove hand-rolled `contextWithTimeout` helper at `pkg/apihttp/cluster_test.go:85`
  (use `t.Context()` + `context.WithTimeout`).
- [ ] Pilot `testing/synctest` on 2–3 timer-heavy files (e.g. `pkg/cluster/election_test.go`,
  `pkg/discovery/*_test.go`); expand only if runtime drops materially.

**Commit:** `test: adopt t.Context and t.Setenv across the suite`

### A.7 — Deduplicate helpers

- [ ] Extract identical `defaultAuthManager()`/`defaultAuditLogger()` from
  `pkg/apihttp/server.go:678-695` and `pkg/apigrpc/server.go:317-337` into a shared location
  (e.g. `pkg/auth/defaults.go` or `pkg/apiutil/`), update both call sites.
- [ ] Extract the 3× duplicated `~`-expansion helper (`pkg/logging/logger.go:44-50`,
  `pkg/audit/config.go:235-252`, `cmd/logs.go:~172`) into one exported helper.
- [ ] Consolidate repeated test server/login helpers across `pkg/apihttp/*_test.go` and
  `pkg/apigrpc/*_test.go` into a shared test helper file per package (or `internal/testutil`
  after Phase C).

**Commit:** `refactor: deduplicate auth/audit defaults and path-expansion helpers`

**Gate + full check:** `go build ./... && go test ./... -race && golangci-lint run && bash scripts/security_check.sh`

---

## Phase B — CI / release supply chain

**Goal:** signed, attested, reproducible releases; CI gates that actually gate. Mostly additive —
safe to land while later phases proceed.

### B.1 — GoReleaser adoption (replaces `release.yml`)

- [ ] Create `.goreleaser.yaml` at repo root:
  ```yaml
  version: 2
  project_name: ztap
  builds:
    - id: ztap
      main: .            # Phase C note: becomes ./cmd/ztap
      binary: ztap
      goos: [linux, darwin, windows]
      goarch: [amd64, arm64]
      env: [CGO_ENABLED=0]
      flags: [-trimpath]
      ldflags:
        - -s -w -X main.Version={{.Version}}
  archives:
    - formats: [tar.gz]
      format_overrides: [{ goos: windows, formats: [zip] }]
      name_template: "{{ .ProjectName }}-{{ .Tag }}-{{ .Os }}-{{ .Arch }}"
  checksum:
    name_template: "checksums.txt"
  sboms:
    - artifacts: [archive]
  signs:
    - cmd: cosign
      args: [sign-blob, --bundle, "${artifact}.sigstore.json", "${artifact}"]
      artifacts: [checksum]
  release:
    prerelease: auto
  ```
- [ ] Docker: keep the existing `docker-release` job pattern but add to each `build-push-action`
  step: `sbom: true`, `provenance: mode=max`, and pass the version build-arg
  (`build-args: VERSION=${{ steps.version.outputs.VERSION }}` — requires B.2). Add keyless
  `cosign sign` of the three image digests (ghcr OIDC: job needs `id-token: write`,
  `packages: write`).
- [ ] SLSA 3 provenance for binaries: add a job using
  `slsa-framework/slsa-github-generator/.github/workflows/generic-generator.yml`  # TODO: pin to SHA
  fed by the GoReleaser checksums.
- [ ] Rewrite `.github/workflows/release.yml` to orchestrate the above; keep: tag trigger
  `v*.*.*`, `concurrency` with `cancel-in-progress: false`, changelog extraction from
  `CHANGELOG.md` (GoReleaser `release.footer` or keep the existing sed step), 6-target matrix
  behavior (GoReleaser handles it), 7-day artifact retention.
- [ ] Dry-run locally:
  ```bash
  go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean
  ls dist/   # expect archives, checksums.txt, *.sbom.json
  ```
- [ ] Verify on a test tag after merge: `cosign verify-blob`, `cosign verify` on ghcr digests,
  and provenance download via `gh release view`.

**Commit:** `build: adopt GoReleaser with cosign signing, SBOMs, and SLSA provenance`

### B.2 — Minimal Dockerfile fixes (required for trustworthy release images)

Both `Dockerfile` and `Dockerfile.operator`:
- [ ] Runtime base `alpine:3.19` → `alpine:3.22` (3.19 is EOL since 2025-11).
- [ ] Build line: replace `go build -a -installsuffix cgo -o ztap .` with
  `ARG VERSION=dev` + `go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o ztap .`
  (`-a` defeats caching; `-installsuffix` was removed in Go 1.20).
  Phase C note: build path becomes `./cmd/ztap` / `./cmd/ztap-operator`.
- [ ] Add OCI labels (`org.opencontainers.image.source/title/description/licenses/version/revision`).
- [ ] `Dockerfile` only: drop unused `apk add git make` (keep `clang llvm` for the `go generate`
  step, or drop the step entirely — the `bpf_bpf*.o` outputs are already vendored; prefer dropping
  and rely on the B.5 drift check).
- [ ] Build check: `docker build --build-arg VERSION=v0.0.0-test -t ztap:test .` then
  `docker run --rm ztap:test version` shows the injected version.

**Commit:** `build(docker): fix EOL alpine, inject version ldflags, add OCI labels`

### B.3 — Make the coverage gate real

- [ ] `cmd/covergate/main.go`: replace the 100%-per-file gate with a ratchet — add
  `-baseline <file>` flag; fail only when a file's coverage drops below its baseline entry.
  Generate the initial baseline from current `coverage-local.out`.
- [ ] `.github/workflows/ci.yml:131`: extend to `-coverpkg=./pkg/...,./cmd/...`
  (Phase C note: `./internal/...`).
- [ ] `ci.yml:136`: drop `|| echo ...` so covergate can fail the job; delete the
  "Coverage report skipped" advisory step.
- [ ] Delete the no-op `benchmark` job (`ci.yml:416-443`) — zero benchmarks exist
  (`rg 'func Benchmark' --type go` is empty). Re-add when benchmarks land.
- [ ] Document covergate in `CONTRIBUTING.md` and `docs/guides/testing.md`
  (how to run: `go run ./cmd/covergate -coverprofile coverage.out -repo . -baseline .covergate-baseline.json`).

**Commit:** `ci: enforce coverage ratchet, measure cmd/, drop empty benchmark job`

### B.4 — Fix the lint blind spot (gofmt + govet never run today)

- [ ] `.golangci.yml` →
  ```yaml
  version: "2"
  run:
    timeout: 5m
  linters:
    default: none
    enable: [errcheck, ineffassign, staticcheck, unused, govet, gocritic, perfsprint, usestdlibvars]
    exclusions:
      paths: [^examples/]
  formatters:
    enable: [gofmt, goimports]
  ```
- [ ] Run `golangci-lint run` and fix new findings (Phase A pre-clears most `perfsprint` items);
  run `golangci-lint fmt` once.
- [ ] Remove the stale CHANGELOG claim that golangci covers gofmt/vet via the old config (fix in
  the same commit's changelog entry).

**Commit:** `ci: enable govet and formatters in golangci-lint v2 config`

### B.5 — Proto + eBPF drift checks

- [ ] New job in `ci.yml` (or `proto.yml`):
  ```yaml
  proto:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # v7.0.0
      - uses: bufbuild/buf-action@<sha> # TODO: pin to SHA
        with:
          lint: true
          breaking: true
          breaking_against: '.git#branch=main'
      - run: ./scripts/gen_proto.sh && git diff --exit-code
  ```
  Optionally migrate `buf.yaml`/`buf.gen.yaml` to v2 format + remote plugins in the same pass.
- [ ] In the `ebpf-verification` job (`ci.yml:287+`), after `make -C bpf` add:
  ```yaml
      - name: Check vendored eBPF is up to date
        run: |
          go generate ./pkg/enforcer/...
          git diff --exit-code -- pkg/enforcer/bpf_bpfel.go pkg/enforcer/bpf_bpfel.o pkg/enforcer/bpf_bpfeb.go pkg/enforcer/bpf_bpfeb.o
  ```
- [ ] `scripts/gen_proto.sh`: verify versions instead of presence-only (`buf --version` match
  against pinned `v1.64.0`; same for plugins) or always `go run` the pinned module versions.

**Commit:** `ci: add buf lint/breaking/drift and eBPF regeneration drift checks`

### B.6 — Dependabot hardening

- [ ] `.github/dependabot.yml`: add docker ecosystem (catches stale alpine/prometheus/grafana):
  ```yaml
    - package-ecosystem: "docker"
      directory: "/"
      schedule: { interval: "weekly", day: "monday", time: "09:00", timezone: "UTC" }
      labels: ["dependencies", "automated"]
  ```
- [ ] Add `cooldown: { default-days: 7 }` to gomod + pip ecosystems.
- [ ] Add a dedicated `k8s` group (`k8s.io/*`, `sigs.k8s.io/*`) since they move in lockstep.

**Commit:** `build: add docker ecosystem and cooldowns to dependabot`

### B.7 — Supply-chain visibility

- [ ] New `.github/workflows/scorecard.yml`: `ossf/scorecard-action`  # TODO: pin to SHA,
  `security-events: write`, upload SARIF; add badge to `README.md`.
- [ ] Add zizmor job to `ci.yml` (Actions security lint): `woodruffw/zizmor-action`  # TODO: pin to SHA
  or `pipx run zizmor .github/workflows/`.
- [ ] Add shellcheck to the lint job: `shellcheck scripts/*.sh demo.sh`; fix findings.
- [ ] Add `# vX.Y.Z` comments to all SHA-pinned actions (only 2/16 have them).

**Commit:** `ci: add OpenSSF Scorecard, zizmor, and shellcheck`

**Gate:** full CI green on the branch; actionlint + zizmor clean; snapshot release verified.

---

## Phase C — Structure: `pkg/` → `internal/` + cmd split

**Goal:** idiomatic layout; `internal/` communicates app-not-library. Big rename — land as one
focused PR right after Phase A merges (rebase B/D/E/F branches after).

### C.1 — Module path decision

- [ ] Decide: keep bare `ztap`, or rename to `github.com/msaadshabir/ZTAP` (recommended — makes
  `go install ...@latest` work and pairs with GoReleaser). If renaming:
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
  `ci.yml` build-check (`go build -o ... ./cmd/ztap`), docs.

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
1. `refactor: rename module to canonical GitHub path` (if C.1 accepted)
2. `refactor: move pkg/ to internal/`
3. `refactor: split CLI into cmd/ztap entrypoint and internal/cli with command factory`

---

## Phase D — Centralized config package

**Goal:** one parse, one source of truth; implement the 4 dead sections.

### D.1 — New package

- [ ] Create `internal/config/config.go`: single typed `Config` mirroring `config.yaml.example` —
  sections `api`, `grpc`, `auth`, `cluster`, `discovery`, `logging`, `alerting`, `aws`, `azure`,
  `gcp`, `audit`, plus the currently-dead `metrics`, `enforcement`, `policy`, `anomaly`.
- [ ] One loader: `Load(path string) (*Config, error)` with the existing lookup order
  (`ZTAP_CONFIG` env → `./config.yaml` → none = defaults) and yaml.v3 decoding with
  `KnownFields(true)` so typos fail loudly.
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
- [ ] Bind `127.0.0.1` by default (env override); serve via **gunicorn** not `flask run`
  (`FLASK_ENV=production` in compose is ignored by modern Flask — remove it there when touched).
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
| A | ✅ | ✅ | ✅ | `scripts/security_check.sh` | policy round-trip (0.3) |
| B | — | — | actionlint + zizmor | — | `goreleaser release --snapshot --clean`, cosign verify |
| C | ✅ | ✅ | ✅ | — | help-output diff (C.4), eBPF integration test |
| D | ✅ | ✅ | ✅ | — | config round-trip + precedence tests |
| E | ✅ | ✅ | ✅ | — | live service e2e, `pytest`, `ruff` |
| F | ✅ | ✅ | ✅ | — | golden log-output tests |

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

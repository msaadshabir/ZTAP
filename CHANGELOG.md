# Changelog

All notable changes to this project will be documented in this file.

This project aims to follow Keep a Changelog (https://keepachangelog.com/en/1.1.0/)
and Semantic Versioning (https://semver.org/).

## Unreleased

### Changed
- **Documentation overhaul**: restructured docs into `guides/`, `concepts/`, `reference/`, and `runbooks/` subdirectories. Created `docs/index.md` as navigation hub and dedicated CLI, Configuration, and API reference pages. Replaced `docs/roadmap.md` with `docs/project-status.md`. Fixed Go version (1.25), Python version (3.11+), removed nonexistent `ztap daemon` command, corrected admin bootstrap workflow, standardized `docker compose` (no hyphen), and removed stale coverage numbers.

### Added
- Documented comprehensive local security audit workflow in `README.md`, `CONTRIBUTING.md`, and `docs/guides/testing.md`.

### Changed
- Clarified recommended contributor test workflow to include race detection (`go test ./... -race`).

### Fixed
- Removed data races in flow-stream API tests by avoiding concurrent reads/writes of `httptest.ResponseRecorder` in `pkg/apihttp/flows_test.go`.
- Resolved `staticcheck` `SA5011` nil-dereference warning in `cmd/policy.go` by returning early in `policy show` when a policy is not found.
- Fixed Windows CI failure in `.github/workflows/ci.yml` by removing bash-only line continuation from the advisory coverage gate step so matrix jobs run correctly under PowerShell.

### Security
- Added documented secret-scanning step using `gitleaks detect --source . --redact --no-banner`.

When cutting a release, move entries from `Unreleased` into a section named:

`## vX.Y.Z - YYYY-MM-DD`

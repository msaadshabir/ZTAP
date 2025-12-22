#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> go test"
go test ./...

echo "==> go vet"
go vet ./...

echo "==> govulncheck"
if ! command -v govulncheck >/dev/null 2>&1; then
  echo "Installing govulncheck..."
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi
export PATH="$(go env GOPATH)/bin:$PATH"
govulncheck ./...

echo "==> gosec"
if ! command -v gosec >/dev/null 2>&1; then
  echo "Installing gosec..."
  go install github.com/securego/gosec/v2/cmd/gosec@latest
fi
export PATH="$(go env GOPATH)/bin:$PATH"

# G304 (variable file path) is expected in a CLI that intentionally reads operator-specified files.
# We track these as a review item in docs/security-audit.md instead of failing CI.
gosec -exclude=G304 ./...

echo "All security checks passed."

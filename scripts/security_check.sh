#!/usr/bin/env bash
set -euo pipefail

GOVULNCHECK_VERSION="v1.6.0"
GOSEC_VERSION="v2.28.0"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SKIP_TESTS="${ZTAP_SECURITY_SKIP_TESTS:-0}"
SKIP_VET="${ZTAP_SECURITY_SKIP_VET:-0}"

if [ "${SKIP_TESTS}" != "1" ]; then
  echo "==> go test"
  go test ./...
else
  echo "==> go test (skipped)"
fi

if [ "${SKIP_VET}" != "1" ]; then
  echo "==> go vet"
  go vet ./...
else
  echo "==> go vet (skipped)"
fi

echo "==> govulncheck"
if ! command -v govulncheck >/dev/null 2>&1; then
  echo "Installing govulncheck..."
  go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
fi
GOBIN="$(go env GOPATH)/bin"
export PATH="$GOBIN:$PATH"
govulncheck ./...

echo "==> gosec"
if ! command -v gosec >/dev/null 2>&1; then
  echo "Installing gosec..."
  go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
fi
GOBIN="$(go env GOPATH)/bin"
export PATH="$GOBIN:$PATH"

# G304/G703 (variable file path / path-traversal taint): expected in a CLI that reads operator-specified files.
# G602 (slice bounds): false positive on fixed-length arrays (e.g., [4]uint32 index 0).
# G115 (integer overflow): false positive on byte extraction from uint32 (e.g., byte(ip>>24)).
# G706 (log injection): low-severity taint noise in operator-facing log output.
# G709 (yaml deserialization): operator-specified config files are trusted input.
# Skip generated code to avoid false positives in protobuf outputs.
gosec -exclude=G304,G602,G703,G706,G709,G115 -exclude-generated ./...

echo "All security checks passed."

#!/usr/bin/env bash
set -euo pipefail

BUF_VERSION="v1.64.0"
PROTOC_GEN_GO_VERSION="v1.36.8"
PROTOC_GEN_GO_GRPC_VERSION="v1.6.0"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

GOBIN="$(go env GOPATH)/bin"
export PATH="$GOBIN:$PATH"

# Install pinned versions when missing OR when the installed version does not
# match the pin (presence-only checks let stale tools drift).

# `buf --version` prints e.g. "1.64.0"
if ! command -v buf >/dev/null 2>&1 || [ "$(buf --version 2>/dev/null || true)" != "${BUF_VERSION#v}" ]; then
  echo "Installing buf (${BUF_VERSION})..."
  go install "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"
fi

# `protoc-gen-go --version` prints e.g. "protoc-gen-go v1.36.8"
if ! command -v protoc-gen-go >/dev/null 2>&1 || [ "$(protoc-gen-go --version 2>/dev/null | awk '{print $2}' || true)" != "${PROTOC_GEN_GO_VERSION}" ]; then
  echo "Installing protoc-gen-go (${PROTOC_GEN_GO_VERSION})..."
  go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
fi

# `protoc-gen-go-grpc --version` prints e.g. "protoc-gen-go-grpc 1.6.0"
if ! command -v protoc-gen-go-grpc >/dev/null 2>&1 || [ "$(protoc-gen-go-grpc --version 2>/dev/null | awk '{print $2}' || true)" != "${PROTOC_GEN_GO_GRPC_VERSION#v}" ]; then
  echo "Installing protoc-gen-go-grpc (${PROTOC_GEN_GO_GRPC_VERSION})..."
  go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}"
fi

buf generate

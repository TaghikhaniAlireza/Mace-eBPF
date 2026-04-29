#!/usr/bin/env bash
# Run Go tests for mace-ebpf/pkg/mace with CGO against the in-tree static Rust lib.
#
# Usage (from repo root):
#   ./mace-ebpf/pkg/mace/run_go_tests.sh
#
# Release static lib:
#   MACE_GO_STATIC_RELEASE=1 ./mace-ebpf/pkg/mace/run_go_tests.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${ROOT}/mace-ebpf/pkg/mace"

export CGO_ENABLED=1

if [[ "${MACE_GO_STATIC_RELEASE:-}" == "1" ]]; then
  exec go test -race -v -tags mace_static_release ./...
else
  exec go test -race -v ./...
fi

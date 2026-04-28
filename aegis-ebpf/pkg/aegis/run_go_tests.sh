#!/usr/bin/env bash
# Run Go tests (CGO links libaegis_ebpf.a statically; no LD_LIBRARY_PATH).
# Usage (from repo root):
#   cargo build -p aegis-ebpf
#   ./aegis-ebpf/pkg/aegis/run_go_tests.sh
#
# After `cargo build --release -p aegis-ebpf`, use release Rust artifacts:
#   AEGIS_GO_STATIC_RELEASE=1 ./aegis-ebpf/pkg/aegis/run_go_tests.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$(dirname "$0")"
export CGO_ENABLED=1
if [[ "${AEGIS_GO_STATIC_RELEASE:-}" == "1" ]]; then
	exec go test -race -v -tags aegis_static_release ./...
else
	exec go test -race -v ./...
fi

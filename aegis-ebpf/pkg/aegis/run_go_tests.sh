#!/usr/bin/env bash
# Run Go tests with the Rust cdylib on LD_LIBRARY_PATH.
# Usage (from repo root):
#   cargo build -p aegis-ebpf
#   ./aegis-ebpf/pkg/aegis/run_go_tests.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
export LD_LIBRARY_PATH="${ROOT}/target/debug:${LD_LIBRARY_PATH:-}"
cd "$(dirname "$0")"
go test -race -v ./...

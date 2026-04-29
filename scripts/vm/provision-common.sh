#!/usr/bin/env bash
# =============================================================================
# Minimal guest packages for eBPF loader smoke tests
# =============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  # python3: short-lived mmap stress for Step 2.3 suite.
  # bpftool: optional map introspection (package name differs; install what exists).
  apt-get install -y --no-install-recommends ca-certificates curl kmod python3
  apt-get install -y --no-install-recommends bpftool 2>/dev/null \
    || apt-get install -y --no-install-recommends "linux-tools-$(uname -r)" 2>/dev/null \
    || true
fi

echo "[provision-common] VM=${MACE_VM_NAME:-unknown}"
echo "[provision-common] ${MACE_KERNEL_NOTE:-}"
uname -a

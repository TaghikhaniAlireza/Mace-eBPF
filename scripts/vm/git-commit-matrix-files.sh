#!/usr/bin/env bash
# =============================================================================
# Optional: stage Vagrant + matrix scripts and commit (run manually)
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

git add Vagrantfile scripts/vm mace-ebpf-loader Cargo.toml Cargo.lock mace-ebpf/tests/common/mod.rs || true

if git diff --cached --quiet; then
  echo "Nothing to commit."
  exit 0
fi

git commit -m "ci(ebpf): Add Vagrant kernel matrix for CO-RE smoke tests" \
  -m "- Vagrantfile for k510/k515/k61/k66 guest definitions" \
  -m "- provision + run-test scripts; optional Step 2.3 suite hooks" \
  -m "- mace-ebpf-loader binary to load/attach without cargo test" \
  -m "- MACE_EBPF_OBJECT override in integration test common helper"

git push origin main

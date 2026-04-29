#!/usr/bin/env bash
# =============================================================================
# Guest: load pre-built mace-ebpf + attach tracepoints; optional Step 2.3 suites
# =============================================================================
set -euo pipefail

ART="/vagrant/scripts/vm/artifacts"
RESULT_DIR="${MACE_MATRIX_RESULT_DIR:-/vagrant/scripts/vm/matrix-results}"
mkdir -p "$RESULT_DIR"

VM="${MACE_VM_NAME:-unknown}"
OUT="$RESULT_DIR/${VM}.txt"

{
  echo "=== mace kernel matrix ==="
  echo "vm: $VM"
  echo "date: $(date -Is 2>/dev/null || date)"
  uname -a
  echo "--- dmesg (tail before) ---"
  dmesg -T 2>/dev/null | tail -n 20 || true
} | tee "$OUT"

if [[ ! -f "$ART/mace-ebpf" ]]; then
  echo "FAIL: missing $ART/mace-ebpf (run ./scripts/vm/prepare-artifact.sh on the host)" | tee -a "$OUT"
  exit 1
fi
if [[ ! -f "$ART/mace-ebpf-loader" ]]; then
  echo "FAIL: missing $ART/mace-ebpf-loader" | tee -a "$OUT"
  exit 1
fi

chmod +x "$ART/mace-ebpf-loader" || true

export MACE_EBPF_OBJECT="$ART/mace-ebpf"
export MACE_ARTIFACT_DIR="$ART"

echo "--- mace-ebpf-loader ---" | tee -a "$OUT"
if "$ART/mace-ebpf-loader" "$ART/mace-ebpf" 2>&1 | tee -a "$OUT"; then
  echo "RESULT: PASS (load+attach)" | tee -a "$OUT"
else
  echo "RESULT: FAIL (load+attach)" | tee -a "$OUT"
  echo "--- dmesg (tail after failure) ---"
  dmesg -T 2>/dev/null | tail -n 80 || true
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 2.3 extension point — TOCTOU / orphan eviction (LRU) checks
# ---------------------------------------------------------------------------
# Drop executable scripts into scripts/vm/suites/ on the host; they are visible
# under /vagrant/scripts/vm/suites/ here. Name suggestion: step-2.3-toctou-lru.sh
# -----------------------------------------------------------------------------
SUITES_DIR="/vagrant/scripts/vm/suites"
if [[ -d "$SUITES_DIR" ]]; then
  for suite in "$SUITES_DIR"/*.sh; do
    [[ -e "$suite" ]] || continue
    [[ "$suite" == *.example ]] && continue
    if [[ -x "$suite" ]]; then
      echo "--- optional suite: $suite ---"
      "$suite" 2>&1 | tee -a "$OUT" || { echo "RESULT: FAIL (suite $suite)" | tee -a "$OUT"; exit 1; }
    fi
  done
fi

echo "--- dmesg (tail after) ---"
dmesg -T 2>/dev/null | tail -n 40 | tee -a "$OUT" || true
echo "RESULT: PASS (full)" | tee -a "$OUT"

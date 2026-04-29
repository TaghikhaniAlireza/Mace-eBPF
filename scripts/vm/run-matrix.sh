#!/usr/bin/env bash
# =============================================================================
# Host: run all matrix VMs sequentially and summarize pass/fail
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

RESULT_DIR="$ROOT/scripts/vm/matrix-results"
mkdir -p "$RESULT_DIR"

SUMMARY="$RESULT_DIR/summary.txt"
{
  echo "mace-ebpf kernel matrix summary"
  date -Is 2>/dev/null || date
} >"$SUMMARY"

if [[ ! -f "$ROOT/scripts/vm/artifacts/mace-ebpf" ]]; then
  echo "Run ./scripts/vm/prepare-artifact.sh first." | tee -a "$SUMMARY" >&2
  exit 1
fi

for vm in k510 k515 k61 k66; do
  echo "========== $vm ==========" | tee -a "$SUMMARY"
  if vagrant up "$vm" --provision; then
    rf="$RESULT_DIR/${vm}.txt"
    if [[ -f "$rf" ]] && grep -q 'RESULT: PASS (full)' "$rf"; then
      echo "PASS $vm" | tee -a "$SUMMARY"
    else
      echo "FAIL $vm (missing PASS marker in ${vm}.txt)" | tee -a "$SUMMARY"
    fi
  else
    echo "FAIL $vm (vagrant up)" | tee -a "$SUMMARY"
  fi
done

echo "Wrote $SUMMARY"

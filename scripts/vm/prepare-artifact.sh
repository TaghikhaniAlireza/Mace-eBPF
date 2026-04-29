#!/usr/bin/env bash
# =============================================================================
# Host: copy pre-built BPF ELF + release loader into scripts/vm/artifacts/
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

DEST="$ROOT/scripts/vm/artifacts"
mkdir -p "$DEST"

echo "[prepare-artifact] workspace: $ROOT"

cargo build --release -p mace-ebpf-loader
cp -v "$ROOT/target/release/mace-ebpf-loader" "$DEST/"

cargo build -p mace-ebpf

# Collect candidate BPF ELFs (exclude host binaries named mace-ebpf under target/release).
mapfile -t CANDS < <(
  {
    find "$ROOT/target" -path '*/bpfel-unknown-none/release/mace-ebpf' -type f 2>/dev/null || true
    find "$ROOT/target" -path '*/bpfel-unknown-none/debug/mace-ebpf' -type f 2>/dev/null || true
    find "$ROOT/target" -path '*/build/mace-ebpf-*/out/mace-ebpf' -type f 2>/dev/null || true
  } | sort -u
)

if [[ ${#CANDS[@]} -eq 0 ]]; then
  echo "[prepare-artifact] ERROR: no mace-ebpf BPF ELF found. Run: cargo build -p mace-ebpf" >&2
  exit 1
fi

BEST=""
BEST_M=0
for f in "${CANDS[@]}"; do
  [[ -f "$f" ]] || continue
  if file "$f" 2>/dev/null | grep -q ELF; then
    :
  else
    continue
  fi
  m=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0)
  if (( m >= BEST_M )); then
    BEST_M=$m
    BEST=$f
  fi
done

if [[ -z "$BEST" ]]; then
  echo "[prepare-artifact] ERROR: no ELF mace-ebpf candidates among: ${CANDS[*]}" >&2
  exit 1
fi

cp -v "$BEST" "$DEST/mace-ebpf"
echo "[prepare-artifact] OK: $DEST/mace-ebpf (from $BEST)"
ls -la "$DEST"

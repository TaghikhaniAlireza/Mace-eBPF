#!/usr/bin/env bash
# =============================================================================
# Step 2.3 — TOCTOU / orphan eviction stress for BPF_MAP_TYPE_LRU_HASH (pending_syscalls)
# =============================================================================
#
# Strategy:
#   1. Start `aegis-ebpf-loader --daemon` so tracepoints stay attached during the test.
#   2. Spawn many short-lived children that call mmap() and exit quickly, maximizing the window
#      where sys_enter_* may record into pending_syscalls while the task can disappear before
#      sys_exit_* (TOCTOU class of issues). The eBPF program uses LRU maps so unbounded growth
#      of pending entries must not leak kernel memory.
#   3. Sample host-visible signals:
#        - MemAvailable from /proc/meminfo (coarse RSS proxy for the cgroup/VM)
#        - bpftool map metadata / entry count for `pending_syscalls` when available
#        - dmesg for aya_log warnings ("pending syscall insert failed", ringbuf failures)
#
# Tunables (environment):
#   AEGIS_LRU_BATCHES       — number of outer loop iterations (default: 40)
#   AEGIS_LRU_CHILDREN      — children per batch (default: 200)
#   AEGIS_LRU_SAMPLE_SEC    — seconds between metric samples (default: 2)
#   AEGIS_LRU_MAX_MEM_DROP_KB — fail if MemAvailable drops more than this many KB vs baseline
#                               (default: 524288 = 512 MiB; set lower to be stricter)
#   AEGIS_LRU_REQUIRE_BPFTOOL — if set to 1, fail when bpftool is missing (default: 0)
#
# Pass criteria:
#   - No sustained MemAvailable collapse beyond threshold (heuristic; not a perfect BPF map RSS read)
#   - No burst of BPF error lines in dmesg (heuristic grep)
#   - If bpftool works: pending_syscalls entry count stays bounded (well under max_entries 10240)
#
# O(1) eviction: the kernel LRU implementation is amortized O(1) per insert; this test does not
# micro-benchmark latency — it validates *bounded* map population under adversarial fork load.
# =============================================================================
set -euo pipefail

ART="${AEGIS_ARTIFACT_DIR:-/vagrant/scripts/vm/artifacts}"
LOADER="$ART/aegis-ebpf-loader"
OBJ="$ART/aegis-ebpf"

BATCHES="${AEGIS_LRU_BATCHES:-40}"
CHILDREN="${AEGIS_LRU_CHILDREN:-200}"
SAMPLE_SEC="${AEGIS_LRU_SAMPLE_SEC:-2}"
MAX_DROP_KB="${AEGIS_LRU_MAX_MEM_DROP_KB:-524288}"
REQUIRE_BPFTOOL="${AEGIS_LRU_REQUIRE_BPFTOOL:-0}"

LOG_TAG="[aegis-lru-suite]"
FAIL=0

log() { echo "$LOG_TAG $*"; }

mem_avail_kb() {
  awk '/^MemAvailable:/{print $2}' /proc/meminfo
}

find_pending_map_id() {
  if ! command -v bpftool >/dev/null 2>&1; then
    echo ""
    return 0
  fi
  # Typical text line: "165: lru_hash  name pending_syscalls  flags 0x0 ..."
  bpftool map list 2>/dev/null | awk '/pending_syscalls/ { sub(/:/, "", $1); print $1; exit }'
}

map_entry_count() {
  local id="$1"
  [[ -z "$id" ]] && echo "" && return 0
  # Count top-level "key" lines in `bpftool map dump` text output (no jq required).
  bpftool map dump id "$id" 2>/dev/null | grep -c '^[[:space:]]*key' || echo "0"
}

sample_metrics() {
  local phase="$1"
  local map_id="$2"
  local ma kb cnt
  ma="$(mem_avail_kb)"
  kb=""
  cnt=""
  if [[ -n "$map_id" ]]; then
    kb=$(bpftool map show id "$map_id" 2>/dev/null | head -c 200 | tr '\n' ' ' || true)
    cnt=$(map_entry_count "$map_id")
  fi
  log "phase=$phase MemAvailable_kB=$ma pending_syscalls_entries=${cnt:-n/a} map_show=${kb:-n/a}"
}

check_dmesg_noise() {
  # Recent lines mentioning our program or generic BPF errors after stress.
  if dmesg -T 2>/dev/null | tail -n 500 | grep -Ei 'pending syscall insert failed|ring buffer reserve failed|bpf.*(error|fail)|verifier' >/dev/null; then
    log "WARN: suspicious dmesg lines (showing matches):"
    dmesg -T 2>/dev/null | tail -n 500 | grep -Ei 'pending syscall insert failed|ring buffer reserve failed|bpf.*(error|fail)|verifier' | tail -n 20 || true
    FAIL=1
  fi
}

if [[ ! -x "$LOADER" ]] || [[ ! -f "$OBJ" ]]; then
  log "FAIL: loader or object missing ($LOADER / $OBJ)"
  exit 1
fi

export AEGIS_EBPF_OBJECT="$OBJ"

if ! command -v bpftool >/dev/null 2>&1 && [[ "$REQUIRE_BPFTOOL" == "1" ]]; then
  log "FAIL: bpftool required but not installed"
  exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
  log "WARN: bpftool not found — map entry checks skipped (install linux-tools or package bpftool)"
fi

BASELINE_KB="$(mem_avail_kb)"
log "baseline MemAvailable_kB=$BASELINE_KB"

"$LOADER" "$OBJ" --daemon &
LOADER_PID=$!
cleanup() {
  log "stopping loader pid=$LOADER_PID"
  kill "$LOADER_PID" 2>/dev/null || true
  wait "$LOADER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for maps to appear
sleep 2
MAP_ID="$(find_pending_map_id)"
log "pending_syscalls map id=${MAP_ID:-unknown}"

stress_batch() {
  local batch="$1"
  local i
  # Many short-lived processes: each runs a tiny anonymous mmap then exits immediately.
  # Python is installed by provision-common for this suite.
  for ((i=0; i<batch; i++)); do
    python3 -c 'import mmap; mmap.mmap(-1, 4096)' &
  done
  wait
}

END=$((SECONDS + 120))
while [[ $SECONDS -lt $END ]]; do
  if kill -0 "$LOADER_PID" 2>/dev/null; then
    break
  fi
  sleep 0.2
done
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
  log "FAIL: loader exited early"
  exit 1
fi

for ((b=1; b<=BATCHES; b++)); do
  stress_batch "$CHILDREN"
  if (( b % 5 == 0 )); then
    MAP_ID="$(find_pending_map_id)"
    sample_metrics "batch_${b}" "${MAP_ID:-}"
    CUR="$(mem_avail_kb)"
    DROP=$((BASELINE_KB - CUR))
    if (( DROP > MAX_DROP_KB )); then
      log "FAIL: MemAvailable dropped ${DROP} kB (threshold ${MAX_DROP_KB} kB)"
      FAIL=1
    fi
    if [[ -n "${MAP_ID:-}" ]]; then
      CNT=$(map_entry_count "$MAP_ID")
      if [[ -n "$CNT" ]] && [[ "$CNT" =~ ^[0-9]+$ ]] && (( CNT > 9000 )); then
        log "FAIL: pending_syscalls entry count very high ($CNT) — possible LRU / eviction issue"
        FAIL=1
      fi
    fi
    check_dmesg_noise
  fi
  sleep "$SAMPLE_SEC"
done

cleanup
trap - EXIT

check_dmesg_noise

if [[ "$FAIL" != "0" ]]; then
  log "RESULT: FAIL (TOCTOU/LRU suite — see warnings above)"
  exit 1
fi

log "RESULT: PASS (TOCTOU/LRU suite — bounded memory / no critical dmesg pattern)"
exit 0

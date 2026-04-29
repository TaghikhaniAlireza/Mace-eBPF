#!/usr/bin/env python3
"""Parse Criterion text output and fail if medians exceed ceilings (CI regression gate).

Usage:
  cargo bench -p mace-ebpf --bench arena_benchmark --bench rule_engine_bench -- --noplot 2>&1 \\
    | python3 scripts/ci/criterion_gate.py

Env (optional overrides, nanoseconds):
  MACE_BENCH_MAX_RULE_ENGINE_NS   default 18000  (256-rule mmap evaluate median; CI runners vary)
  MACE_BENCH_MAX_STATE_TRACKER_NS default 220    (single-tgid update median)
  MACE_BENCH_MAX_ARENA_PUSH_NS    default 180    (try_push_non_full median)
"""
from __future__ import annotations

import os
import re
import sys

TIME_RE = re.compile(
    r"^\s*time:\s+\[\s*([0-9.]+)\s*(ns|µs|us|ms)\s+([0-9.]+)\s*\2\s+([0-9.]+)\s*\2\s*\]"
)


def to_ns(value: float, unit: str) -> float:
    if unit == "ns":
        return value
    if unit in ("µs", "us"):
        return value * 1000.0
    if unit == "ms":
        return value * 1_000_000.0
    raise ValueError(unit)


def main() -> int:
    max_rule = float(os.environ.get("MACE_BENCH_MAX_RULE_ENGINE_NS", "18000"))
    max_state = float(os.environ.get("MACE_BENCH_MAX_STATE_TRACKER_NS", "220"))
    max_arena = float(os.environ.get("MACE_BENCH_MAX_ARENA_PUSH_NS", "180"))

    text = sys.stdin.read()
    lines = text.splitlines()
    current = None
    found: dict[str, float] = {}

    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("rule_engine/") or s.startswith("state_tracker/") or s.startswith(
            "single_thread_push_pop/"
        ):
            current = s
            continue
        m = TIME_RE.match(line)
        if m and current:
            lo_s, unit, med_s, hi_s = m.group(1), m.group(2), m.group(3), m.group(4)
            ns = to_ns(float(med_s), unit)
            found[current] = ns
            current = None

    errors = []

    def check(key: str, ceiling: float, label: str) -> None:
        if key not in found:
            errors.append(f"missing benchmark line for {key!r}")
            return
        v = found[key]
        if v > ceiling:
            errors.append(f"{label}: median {v:.1f} ns > ceiling {ceiling:.1f} ns")

    check("rule_engine/evaluate_256_rules_mmap", max_rule, "rule_engine")
    check("state_tracker/update_same_tgid", max_state, "state_tracker")
    check("single_thread_push_pop/try_push_non_full", max_arena, "arena try_push")

    if errors:
        print("criterion_gate: FAIL", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print("criterion_gate: OK")
    for k in sorted(found):
        print(f"  {k}: {found[k]:.2f} ns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

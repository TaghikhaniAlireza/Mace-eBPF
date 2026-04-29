#!/usr/bin/env python3
"""Parse Criterion text output and fail if medians exceed ceilings (CI regression gate).

Usage:
  cargo bench -p mace-ebpf --bench arena_benchmark --bench rule_engine_bench -- --noplot 2>&1 \\
    | python3 scripts/ci/criterion_gate.py

Env (optional overrides, nanoseconds):
  MACE_BENCH_MAX_RULE_ENGINE_NS   default 18000  (256-rule mmap evaluate median; CI runners vary)
  MACE_BENCH_MAX_STATE_TRACKER_NS default 220    (single-tgid update median)
  MACE_BENCH_MAX_ARENA_PUSH_NS    default 180    (try_push_non_full median)

Optional relative regression (Phase 1.3): set MACE_CRITERION_BASELINE_FILE to a JSON file
(see scripts/ci/criterion_baseline.json). Each tracked benchmark median must be
<= baseline_median * (1 + MACE_CRITERION_REGRESSION_MAX / 100). Default regression max is 5 (%).
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

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


def load_baseline(path: str) -> dict[str, float]:
    raw: dict[str, Any]
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    med = raw.get("medians_ns")
    if not isinstance(med, dict):
        raise ValueError("baseline JSON must contain object 'medians_ns'")
    out: dict[str, float] = {}
    for k, v in med.items():
        if not isinstance(k, str):
            raise ValueError("baseline keys must be strings")
        if not isinstance(v, (int, float)):
            raise ValueError(f"baseline value for {k!r} must be a number")
        out[k] = float(v)
    return out


def main() -> int:
    max_rule = float(os.environ.get("MACE_BENCH_MAX_RULE_ENGINE_NS", "18000"))
    max_state = float(os.environ.get("MACE_BENCH_MAX_STATE_TRACKER_NS", "220"))
    max_arena = float(os.environ.get("MACE_BENCH_MAX_ARENA_PUSH_NS", "180"))

    baseline_path = os.environ.get("MACE_CRITERION_BASELINE_FILE", "").strip()
    regression_pct = float(os.environ.get("MACE_CRITERION_REGRESSION_MAX", "5"))
    baseline: dict[str, float] | None = None
    if baseline_path:
        p = Path(baseline_path)
        if not p.is_file():
            print(f"criterion_gate: FAIL baseline file not found: {p}", file=sys.stderr)
            return 1
        try:
            baseline = load_baseline(str(p.resolve()))
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"criterion_gate: FAIL invalid baseline ({e})", file=sys.stderr)
            return 1

    text = sys.stdin.read()
    lines = text.splitlines()
    current = None
    found: dict[str, float] = {}

    for line in lines:
        s = line.strip()
        if s.startswith("rule_engine/") or s.startswith("state_tracker/") or s.startswith(
            "single_thread_push_pop/"
        ):
            current = s
            continue
        m = TIME_RE.match(line)
        if m and current:
            _lo_s, unit, med_s, _hi_s = m.group(1), m.group(2), m.group(3), m.group(4)
            ns = to_ns(float(med_s), unit)
            found[current] = ns
            current = None

    errors: list[str] = []

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

    tracked = (
        "rule_engine/evaluate_256_rules_mmap",
        "state_tracker/update_same_tgid",
        "single_thread_push_pop/try_push_non_full",
    )
    if baseline is not None:
        factor = 1.0 + regression_pct / 100.0
        for key in tracked:
            if key not in found:
                continue
            b = baseline.get(key)
            if b is None:
                errors.append(f"baseline JSON missing key {key!r}")
                continue
            limit = b * factor
            v = found[key]
            if v > limit:
                errors.append(
                    f"{key}: median {v:.1f} ns > baseline {b:.1f} ns + {regression_pct:.1f}% "
                    f"(limit {limit:.1f} ns)"
                )

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

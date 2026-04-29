# Core logging (`MACE_LOG_LEVEL` and Rust diagnostics)

This document explains how **Mace log levels** work in the Rust core, how they differ from **`RUST_LOG`**, and why you may still see **“suppressed”** text when the floor is **`ALERT`**.

## What `MACE_LOG_LEVEL` controls

`MACE_LOG_LEVEL` (or **`mace_set_log_level`** / Go **`SetLogLevel`**) sets a **filter floor** for **Mace-branded diagnostic lines** written by the Rust crate to **stderr**. Those lines look like:

```text
[Mace][EVENT] tgid=123 syscall=Mmap matched_rules=[]
[Mace][SUPPRESSED] tgid=123 syscall=Mmap matched_rules=[...] suppressed_by=[...]
[Mace][ALERT] tgid=123 rule_id=SIM_A_RWX suppressed=true suppression_ids=[...]
```

Implementation: **`mace-ebpf/src/logging.rs`** (`MaceLogLevel`, `is_enabled`, `set_filter_floor`).

### Severity order (numeric floor)

| Level | Ordinal | Meaning in filter |
|-------|---------|-------------------|
| `TRACE` | 0 | Lowest floor — allow everything below too |
| `INFO` | 1 | Allow INFO and above |
| `SUPPRESSED` | 2 | Allow SUPPRESSED, EVENT, ALERT |
| `EVENT` | 3 | Allow EVENT and ALERT |
| `ALERT` | 4 | **Only** lines emitted at severity `ALERT` |

A message at level **L** is printed **if and only if** `L >= floor` (see `logging::is_enabled`).

**Important:** This is **independent** of `RUST_LOG`. Tracing / `log` output from other parts of the stack still follow `RUST_LOG` (or the default subscriber filter).

### When the environment variable is read

`MACE_LOG_LEVEL` is applied when the embedded tracing subscriber is first installed — **`init_logging_for_ffi()`** (typically your first **`mace_engine_init()`**). Set the variable **before** starting the process (or before that call). You can change the floor later with **`mace_set_log_level(0..4)`** without restarting.

## What the pipeline emits at each Rust level

In **`mace-ebpf/src/pipeline/mod.rs`** (`run_partition_worker`):

| Situation | Rust `mace_log!` level | Printed when floor is … |
|-----------|-------------------------|---------------------------|
| No rules matched, no suppression | `Event` | `EVENT` or lower (`TRACE`…`EVENT`) |
| Rules matched + YAML suppression | `Suppressed` (one line) | `SUPPRESSED` or lower |
| **Each matched rule** (audit) | **`Alert`** | **`ALERT` floor only** |

So with **`MACE_LOG_LEVEL=ALERT`**:

- You **do not** get `[Mace][EVENT]` or `[Mace][SUPPRESSED]` lines on stderr.
- You **still get** `[Mace][ALERT] ...` for **every** matching rule, including when **`suppressed=true`** and `suppression_ids=[...]` appear **inside that line**. That is intentional: at “alert-only” noise reduction you still see **that a rule matched**, and whether YAML suppressions would have blocked the **alert callback**.

**If you expected zero output mentioning “suppressed” at `ALERT`:** that only applies to the **`[SUPPRESSED]`** line type. The **`[ALERT]`** line may still contain the substring `suppressed=true` for context.

## This is not the same as the Go example’s `SUPPRESSED_ALERT` label

The **`clients/go/examples`** program prints lines like:

```text
SUPPRESSED_ALERT matched=[SIM_A_RWX] suppressed_by=[SUPP_JIT_...] ...
```

That prefix is **application logic**: it classifies each **JSON event** from **`mace.Client.Events`** (`matched_rules` + `suppressed_by`). It is **not** gated by `MACE_LOG_LEVEL`. So you can see **`SUPPRESSED_ALERT`** on stdout even when Rust stderr `[Mace][SUPPRESSED]` is silenced.

Summary:

| Output | Controlled by |
|--------|----------------|
| `[Mace][*]` on **stderr** | `MACE_LOG_LEVEL` / `mace_set_log_level` |
| `tracing` / `log` on stderr | `RUST_LOG` (and subscriber defaults) |
| Go example `EVENT` / `ALERT` / `SUPPRESSED_*` on **stdout** | Example code — filter there if you want |

## FFI / Go

- C: **`int32_t mace_set_log_level(int32_t level);`** — `0` = TRACE … `4` = ALERT; invalid → error code.
- Go (`clients/go/mace`): **`SetLogLevel(mace.LogLevelAlert)`** and constants **`LogLevelTrace` … `LogLevelAlert`**. **`InitEngineWithConfig(EngineConfig{LogLevel: &lvl})`** calls `mace_engine_init` then applies **`SetLogLevel`** when `LogLevel` is non-nil (useful to override `MACE_LOG_LEVEL` after Rust’s first parse).

## Quick checks

```bash
# From repo root — Rust tests (in-memory capture of [Mace] lines)
cargo test -p mace-ebpf --lib logging::tests::alert_floor_hides_lower_severities
```

```bash
export MACE_LOG_LEVEL=ALERT
sudo -E env MACE_LOG_LEVEL=ALERT RUST_LOG=warn ... ./your-binary
```

For the Go example, call **`mace.SetLogLevel`** after **`InitEngine()`** if you want the process to honor a level without relying solely on env-at-start (the example can also read `MACE_LOG_LEVEL` and call `SetLogLevel`).

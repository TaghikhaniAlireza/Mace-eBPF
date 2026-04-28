# `AEGIS_LOG_LEVEL` and Aegis core logging

This document explains how **Aegis log levels** work in the Rust core, how they differ from **`RUST_LOG`**, and why you may still see **“suppressed”** output when the level is **`ALERT`**.

## What `AEGIS_LOG_LEVEL` controls

`AEGIS_LOG_LEVEL` (or `aegis_set_log_level` / Go `SetLogLevel`) sets a **filter floor** for **Aegis-branded diagnostic lines** written by the Rust crate to **stderr**. Those lines look like:

```text
[Aegis][EVENT] tgid=123 syscall=Mmap matched_rules=[]
[Aegis][SUPPRESSED] tgid=123 syscall=Mmap matched_rules=[...] suppressed_by=[...]
[Aegis][ALERT] tgid=123 rule_id=SIM_A_RWX suppressed=true suppression_ids=[...]
```

Implementation: `aegis-ebpf/src/logging.rs` (`AegisLogLevel`, `is_enabled`, `set_filter_floor`).

### Severity order (numeric floor)

| Level        | Ordinal | Meaning in filter                          |
|-------------|---------|---------------------------------------------|
| `TRACE`     | 0       | Lowest floor — allow everything below too |
| `INFO`      | 1       | Allow INFO and above                        |
| `SUPPRESSED`| 2       | Allow SUPPRESSED, EVENT, ALERT              |
| `EVENT`     | 3       | Allow EVENT and ALERT                       |
| `ALERT`     | 4       | **Only** lines emitted at severity `ALERT`  |

A message at level **L** is printed **iff** `L >= floor` (see `logging::is_enabled`).

**Important:** This is **independent** of `RUST_LOG`. Tracing / `log` output from other parts of the stack still follow `RUST_LOG` (or the default subscriber filter).

### When the env var is read

`AEGIS_LOG_LEVEL` is applied when the embedded tracing subscriber is first installed — **`init_logging_for_ffi()`** (typically your first **`aegis_engine_init()`**). Set the variable **before** starting the process (or before that call). You can change the floor later with **`aegis_set_log_level(0..4)`** without restarting.

## What the pipeline emits at each Rust level

In `aegis-ebpf/src/pipeline/mod.rs` (`run_partition_worker`):

| Situation                         | Rust `aegis_log!` level | Printed when floor is … |
|----------------------------------|-------------------------|-------------------------|
| No rules matched, no suppression | `Event`                 | `EVENT` or lower (`TRACE`…`EVENT`) |
| Rules matched + YAML suppression | `Suppressed` (one line) | `SUPPRESSED` or lower   |
| **Each matched rule** (audit)    | **`Alert`**             | **`ALERT` floor only**  |

So with **`AEGIS_LOG_LEVEL=ALERT`**:

- You **do not** get `[Aegis][EVENT]` or `[Aegis][SUPPRESSED]` lines on stderr.
- You **still get** `[Aegis][ALERT] ...` for **every** matching rule, including when **`suppressed=true`** and `suppression_ids=[...]` appear **inside that line**. That is intentional: at “alert-only” noise reduction you still see **that a rule matched**, and whether YAML suppressions would have blocked the **alert callback**.

**If you expected zero output mentioning “suppressed” at `ALERT`:** that only applies to the **`[SUPPRESSED]`** line type. The **`[ALERT]`** line may still contain the substring `suppressed=true` for context.

## This is not the same as the Go example’s `SUPPRESSED_ALERT` label

The **`clients/go/examples`** program prints lines like:

```text
SUPPRESSED_ALERT matched=[SIM_A_RWX] suppressed_by=[SUPP_JIT_...] ...
```

That prefix is **application logic**: it classifies each **JSON event** from [aegis.Client.Events] (`matched_rules` + `suppressed_by`). It is **not** gated by `AEGIS_LOG_LEVEL`. So you can see **`SUPPRESSED_ALERT`** on stdout even when Rust stderr `[Aegis][SUPPRESSED]` is silenced.

Summary:

| Output | Controlled by |
|--------|----------------|
| `[Aegis][*]` on **stderr** | `AEGIS_LOG_LEVEL` / `aegis_set_log_level` |
| `tracing` / `log` on stderr | `RUST_LOG` (and subscriber defaults) |
| Go example `EVENT` / `ALERT` / `SUPPRESSED_*` on **stdout** | Example code — filter there if you want |

## FFI / Go

- C: `int32_t aegis_set_log_level(int32_t level);` — `0` = TRACE … `4` = ALERT; invalid → error code.
- Go (`clients/go/aegis`): **`SetLogLevel(aegis.LogLevelAlert)`** and constants **`LogLevelTrace` … `LogLevelAlert`**. **`InitEngineWithConfig(EngineConfig{LogLevel: &lvl})`** calls `aegis_engine_init` then applies **`SetLogLevel`** when `LogLevel` is non-nil (useful to override `AEGIS_LOG_LEVEL` after Rust’s first parse).

## Quick checks

```bash
# From repo root — only Rust tests (in-memory capture of [Aegis] lines)
cargo test -p aegis-ebpf --lib logging::tests::alert_floor_hides_lower_severities
```

```bash
# Run with strict stderr filter; you should still see [Aegis][ALERT] for rule hits if any,
# but not [Aegis][EVENT] / [Aegis][SUPPRESSED].
export AEGIS_LOG_LEVEL=ALERT
sudo -E env AEGIS_LOG_LEVEL=ALERT RUST_LOG=warn ... ./your-binary
```

For the Go example, call **`aegis.SetLogLevel`** after **`InitEngine()`** if you want the process to honor a level without relying solely on env-at-start (the example can also read `AEGIS_LOG_LEVEL` and call `SetLogLevel`).

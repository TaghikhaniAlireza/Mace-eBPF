# Architecture

This document describes how the **Mace-eBPF** components fit together: kernel programs, Rust userspace, FFI, and the Go **mace-agent**.

## High-level diagram

```text
┌─────────────────────────────────────────────────────────────────┐
│                        Linux kernel                              │
│  ┌──────────────────┐    ring buffer    ┌─────────────────────┐ │
│  │ eBPF tracepoints │ ─────────────────►│ EVENTS map         │ │
│  │ (aya, no_std)    │    (MemoryEvent)  │ (mace-ebpf-ebpf)  │ │
│  └────────┬─────────┘                   └──────────┬──────────┘ │
└─────────────┼──────────────────────────────────────┼──────────┘
              │                                      │
              │ perf_event_open / BPF link            │ userspace read
              ▼                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ Rust `mace-ebpf` crate (Tokio runtime in embedded/FFI mode)     │
│  · load CO-RE object from OUT_DIR / embedded bytes               │
│  · attach programs (required + optional tracepoints)             │
│  · read ring buffer → enrich → reorder → partition workers       │
│  · evaluate YAML rules + suppressions (`rules/`, `state/`)        │
│  · emit JSON StandardizedEvent → optional callbacks              │
└────────────┬──────────────────────────────────────▲──────────────┘
             │ C ABI (libmace_ebpf)               │ mace_register_event_callback
             ▼                                     │
┌────────────────────────┐              ┌──────────┴───────────┐
│ Go / Python / C       │              │ mace-agent (Go)    │
│ cgo / ctypes          │              │ · cobra CLI         │
│ · NewClient + channel │              │ · file config       │
│ · arena / sensor APIs │              │ · logrus → file     │
└────────────────────────┘              └──────────────────────┘
```

## Kernel: `mace-ebpf-ebpf`

- **`#![no_std]`** eBPF programs under **`mace-ebpf-ebpf/src/`**.
- Attached to **syscall tracepoints** (for example `sys_enter_mmap`, `sys_exit_mprotect`, … depending on configuration).
- Uses **maps**: ring buffer for outbound events, LRU-style maps for pending syscall state, optional allowlists.
- **Verifier constraints** drive design choices (for example limited `execve` argv capture — often **`argv[0]`** only in-kernel; fuller command lines come from userspace `/proc` enrichment).

## Userspace core: `mace-ebpf`

Key modules (under **`mace-ebpf/src/`**):

| Module / area | Role |
|---------------|------|
| **`lib.rs`** | Sensor startup: load BPF, attach, spawn Tokio pipeline, expose types. |
| **`pipeline/`** | Reordering window, partition workers, rule evaluation hook, standardized JSON emission. |
| **`rules/`** | YAML load/validate, regex compilation, suppression evaluation. |
| **`state/`** | Stateful counters for threshold-style rules. |
| **`ffi/`** | C ABI: arena, alert channel, **embedded engine** (`mace_engine_init`, `mace_load_rules`, `mace_load_rules_file`, `mace_start_pipeline`, …), JSON callback registration. |
| **`logging.rs`** | **`[Mace][LEVEL]`** diagnostic lines on stderr (filter floor via `MACE_LOG_LEVEL` / `mace_set_log_level`). |

The BPF object bytes are compiled into the Rust crate output directory and included at link time (`include_bytes_aligned!`).

## FFI boundary

- **Header:** `mace-ebpf/include/mace.h` (generated/merged via `build.rs` + cbindgen).
- **Libraries:** `cdylib` produces **`libmace_ebpf.so`**; **`staticlib`** produces **`libmace_ebpf.a`** for Go static linking.
- **JSON events:** `mace_register_event_callback` receives a **NUL-terminated UTF-8 JSON string** per evaluated event (serde view of `StandardizedEvent`). The Go SDK unmarshals into **`MaceEvent`** and delivers on a channel.

## Go agent: `mace-agent`

Located at **`clients/go/cmd/mace-agent/`**:

- Parses **`--config`** / **`-c`** (required).
- Loads **`packaging`-style YAML** via `internal/agentconfig` (`logging` + `rules` sections).
- Initializes **`mace.NewClient`**, **`InitEngine`**, **`LoadRulesFile`**, **`StartPipeline`**.
- Writes **only** structured security events to the configured **log file** (logrus JSON or text).
- Handles **SIGINT/SIGTERM** for graceful shutdown.

## Python bindings

The **`mace-ebpf/python`** package loads **`libmace_ebpf.so`** via ctypes; it shares the same C ABI but is not required for the Go agent.

## Related reading

- [Rules engine](./rules-engine.md)
- [Events and alerts](./events-and-alerts.md)
- [Agent configuration](../4-configuration/agent-config.md)

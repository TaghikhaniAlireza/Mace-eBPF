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
- **Verifier constraints** drive design choices: **by default** the nested eBPF build uses **`execve_no_user_argv`** (no `bpf_probe_read_user*` on the argv path at **`sys_enter_execve`** / **`sys_enter_execveat`**) so `BPF_PROG_LOAD` succeeds on strict kernels; exec-family rules use **`/proc/<tgid>/cmdline`**. Set **`MACE_EBPF_EXECVE_FULL_ARGV=1`** when building to enable **full** in-kernel capture (ring **v14**: up to **15** argv strings at syscall enter, **800**-byte NUL-separated blob after `ExecveWireHeader`; each arg read with `bpf_probe_read_user_str_bytes` into a **127-byte** slice of a **128-byte** per-CPU temp; **`openat`** path capture uses the same **N − 1** rule for a **64-byte** `OPENAT_PATH_MAX_LEN` scratch prefix). If full argv still fails `BPF_PROG_LOAD`, try **`MACE_EBPF_EXECVE_ARGV0_ONLY=1`** (`Makefile` → `rust-build-ebpf-argv0`) or keep the default no-user build. If `BPF_PROG_LOAD` returns **EACCES (13)** on attach, the program may be rejected by **kernel lockdown** or missing **`CAP_BPF`/`CAP_SYS_ADMIN`** — not necessarily argv logic.

## Where filtering and policy run

| Concern | Kernel (eBPF) | Userspace (Rust pipeline) |
|--------|----------------|----------------------------|
| **Goal** | Cut volume early; verifier-safe checks | Full detection logic, YAML, suppressions, shadow mode |
| **Examples** | TGID **allowlist**, **mmap rate limit**, bounded **execve argv** / **openat path** capture | **RuleSet** evaluation, **regex**, **sequence** / **frequency** rules, **`/proc`** fallbacks when kernel snapshot is empty or truncated |
| **Why split** | Ring buffer and CPU are finite; BPF has stack/insn limits | Rules change often and need rich context (K8s, passwd, cmdline tracker) |

Neither layer alone is “best”: **kernel** reduces cost and closes some TOCTOU windows (syscall-time snapshots); **userspace** carries policy you cannot safely express entirely in BPF.

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

### TOCTOU (time-of-check vs time-of-use)

- **`execve` / `execveat` argv (v11+):** Arguments are read in eBPF at **`sys_enter_execve`** and **`sys_enter_execveat`**, so the primary cmdline snapshot is **not** a post-syscall `/proc/<pid>/cmdline` read. If the snapshot is **truncated** (`ExecveWireHeader.is_truncated` → `MemoryEvent.execve_argv_truncated` and JSON `execve_argv_truncated`), operators may still use the haystack fallbacks documented in the rules guide—those paths can diverge from the true full argv under adversarial conditions.
- **Other `/proc` reads** (e.g. some rule matchers): Still best-effort at evaluation time; document and scope detections accordingly.

### Kubernetes enrichment and slow API

When built with **`--features kubernetes`**, `KubernetesEnricher` uses a **Moka** cache (TTL **60 s**) so repeated cgroup lookups avoid the API. On a cache miss, pod listing uses a **timeout** (default **12 s**); on timeout or error, enrichment is skipped for that event (metadata `None`) rather than blocking the pipeline indefinitely. The list call also uses a **server-side limit** on Pod count per request (see `mace-ebpf/src/enrichment/kubernetes.rs`). For large clusters, replace list-all with **watch/informer** or **field-scoped** APIs in a future change.

### Locking and latency

The live **`Ebpf`** handle is wrapped in **`parking_lot::Mutex`** (shared between the sensor task, periodic kernel-stats refresh, and FFI helpers such as allowlist updates). Contention is usually low but **concurrent FFI + heavy map access** can serialize briefly.

The rule engine and pipeline use **async channels** and partitioned workers to avoid a single global lock on every event.

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

# Events and alerts

After the pipeline evaluates YAML **rules** and **suppressions**, it emits one **JSON object per syscall observation** (per enriched event). In Rust this structure is **`StandardizedEvent`** (`mace-ebpf/src/alert.rs`); in Go the SDK type is **`MaceEvent`** (`clients/go/mace/mace.go`).

## JSON schema (exported event)

The following fields are stable for integration and SIEM mapping:

| Field | JSON key | Type | Description |
|-------|-----------|------|-------------|
| Timestamp | `timestamp` | number | Event time in nanoseconds (kernel timestamp). |
| Process ID | `pid` | number | Kernel PID. |
| User ID | `uid` | number | Effective UID. |
| Username | `username` | string | Resolved from `/etc/passwd` when available. |
| Short name | `process_name` | string | Task `comm` (16-byte style, NUL-trimmed). |
| Syscall | `syscall_name` | string | Logical name: `mmap`, `mprotect`, `execve`, `openat`, `ptrace`, `memfd_create`, … |
| Command line | `cmdline` | string | Best-effort command line (execve snapshot and/or `/proc`). |
| Arguments | `arguments` | array of strings | Syscall-specific formatted arguments (see Rust `format_syscall_arguments`). |
| Matched rules | `matched_rules` | array of strings | Rule **`id`** values that matched (may be empty). |
| Suppressions | `suppressed_by` | array of strings | Suppression **`id`** values when alerts were suppressed; **omitted** when empty. |

### Example (alerts not suppressed)

```json
{
  "timestamp": 1710000000000000000,
  "pid": 12345,
  "uid": 1000,
  "username": "alice",
  "process_name": "bash",
  "syscall_name": "execve",
  "cmdline": "/bin/bash -c whoami",
  "arguments": ["filename_ptr=0x...", "argv_ptr=0x...", "argv_snapshot=..."],
  "matched_rules": ["SIM_INTERACTIVE_WHOAMI"]
}
```

### Example (rule matched but alert suppressed)

```json
{
  "timestamp": 1710000000000000000,
  "pid": 9999,
  "uid": 0,
  "username": "root",
  "process_name": "python3",
  "syscall_name": "mmap",
  "cmdline": "python3 /usr/lib/foo.py",
  "arguments": ["addr=0x...", "len=0x...", "flags=0x..."],
  "matched_rules": ["SIM_A_RWX"],
  "suppressed_by": ["SUPP_PYTHON_STDLIB"]
}
```

## Classification: alert vs telemetry

The JSON **always** includes **`matched_rules`** (possibly empty). Operational meaning:

| `matched_rules` | `suppressed_by` | Typical meaning |
|-----------------|-----------------|-----------------|
| empty | empty | Observation only (telemetry). |
| non-empty | empty | **Alert** — at least one rule matched and no suppression blocked alerting. |
| non-empty | non-empty | **Suppressed alert** — rules matched; YAML suppressions prevented firing alert callbacks, but the event is still exported with both lists populated. |

Downstream consumers (for example **`mace-agent`** or the Go **examples** program) may print human-readable labels such as `ALERT`, `EVENT`, or `SUPPRESSED_ALERT`. Those labels are **application logic**, not the same as Rust **`[Mace][LEVEL]`** stderr diagnostics — see [Core logging](../4-configuration/logging.md).

## Delivery paths

| Consumer | Mechanism |
|----------|-----------|
| **Go SDK** | `mace.NewClient` → `client.Events()` channel of **`MaceEvent`**. |
| **FFI** | `mace_register_event_callback` receives raw JSON string per event. |
| **mace-agent** | unmarshals internally and writes **logrus** JSON or text to **`logging.path`**. |

## Related

- [Rules engine](./rules-engine.md)
- [Architecture](./architecture.md)

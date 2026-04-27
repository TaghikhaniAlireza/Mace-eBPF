# Writing rules for Aegis-eBPF

This document describes the YAML rule format consumed by the userspace rule engine (`aegis-ebpf`). Rules filter enriched memory/syscall events produced by the eBPF sensor and pipeline.

## Loading rules

Rules are validated at load time (syntax, syscall names, regex fields, cross-field constraints).

**Rust SDK:** build a `RuleSet` (`aegis-ebpf/src/rules/loader.rs`) from a string (`from_yaml_str`), a single file (`from_file`), or a directory of `.yaml`/`.yml` files merged in sorted order (`from_dir`).

**Embedded / FFI:**

- Inline YAML: `aegis_load_rules`.
- Filesystem path (with optional hot reload when wired through the pipeline): `aegis_load_rules_file`.

**Go example:** resolves `AEGIS_RULES_FILE`, then `/etc/aegis/rules.yaml` if present, otherwise the repository `tests/simulations/rules.yaml`.

There is no built-in search path list in the core library; embedders choose defaults (CLI flags, env vars, `/etc`, etc.).

## Suppression (trusted processes / false-positive control)

A second top-level key, `suppressions`, lists **suppression entries** that use the **same `conditions` language** as rules (no `stateful` block). When an event matches at least one suppression entry, **alerts are not fired** for that event, but rules are still evaluated. The JSON `StandardizedEvent` (FFI / Go callback) then includes:

- `matched_rules` — same as without suppression (which rules would have fired),
- `suppressed_by` — list of suppression entry `id` values that matched (alerts were suppressed because the process is considered trusted for that event pattern).

If no suppression matches, `suppressed_by` is omitted from the JSON.

**Example** (typical desktop JIT noise: `mprotect` with RWX on a short `comm` like `gnome-she+` may need a pattern you tune for your environment):

```yaml
suppressions:
  - id: "TRUST_GNOME_SHELL_MPROTECT"
    name: "Shell compositor JIT mprotect"
    description: "gnome-shell Mutter Clutter uses executable anonymous regions; suppress mprotect RWX noise."
    conditions:
      syscall: "mprotect"
      process_name_pattern: "gnome-shell|mutter|Mutter"
      flags_contains: ["PROT_READ", "PROT_WRITE", "PROT_EXEC"]
```

## Rule file shape

Top-level key `rules` is an array of rule objects:

```yaml
rules:
  - id: "EXAMPLE_ID"
    name: "Human-readable title"
    severity: "medium"    # low | medium | high | critical
    description: "Why this rule exists."
    conditions:
      syscall: "execve"
      argv_contains:
        - "whoami"
```

Optional `stateful` block (see below) attaches minimum thresholds using process-local counters.

## Events and syscalls

Each rule may set `conditions.syscall` to one of:

| Value | Meaning |
|-------|---------|
| `mmap` | Memory mapping (`mmap`) |
| `mprotect` | Memory protection changes; emitted when the event represents an executable transition (WX-style path in the pipeline) |
| `memfd_create` | Anonymous file descriptors |
| `ptrace` | `ptrace` syscall |
| `execve` | Program execution |
| `openat` | File opens via `openat` |

Matching is case-insensitive for the syscall string.

## Command-line / argv context

The kernel probe captures a **short snapshot** of exec-related text (`argv[0]` from eBPF on strict kernels). For matching, the engine builds a **haystack** string in this order:

1. Non-empty `execve_cmdline` from the event (eBPF snapshot),
2. else pipeline `cmdline_context` (last exec line attributed to the thread group),
3. else a read of `/proc/<pid>/cmdline` (arguments joined with spaces).

Rules that use `argv_contains`, `cmdline_contains_any`, or `cmdline_context_pattern` operate on this normalized haystack—so substring rules still work when full argv is only visible from `/proc`.

## Condition fields (`conditions`)

| Field | Type | Behavior |
|-------|------|----------|
| `syscall` | string | Required for most precise rules; must be a supported syscall name (see table above). |
| `flags_contains` | list of strings | Each named flag must be present on the event (`PROT_*`, `MAP_*`, etc.—validated at load time). |
| `flags_excludes` | list of strings | If any listed flag is present, the rule does not match. |
| `min_size` | integer | Event length field must be ≥ this value (where applicable). |
| `cgroup_pattern` | regex string | Matched against the cgroup path when enrichment provides it. |
| `process_name_pattern` | regex string | Matched against the task `comm` (process name from the kernel). |
| `argv_contains` | list of strings | Every substring must appear in the command-line haystack. |
| `cmdline_contains_any` | list of strings | At least one substring must appear in the haystack. |
| `cmdline_context_pattern` | regex string | Regex against the same haystack (full-line style matching). |
| `uid` | unsigned integer | Effective UID from the event must match. |
| `pathname_pattern` | regex string | **Requires** `syscall: openat`. Matched against a resolved path built from the in-kernel pathname snapshot and `/proc` fd resolution when needed. |
| `ptrace_request` | unsigned integer | **Requires** `syscall: ptrace`. Compared to the ptrace request number on the event (e.g. `16` for `PTRACE_ATTACH`). |

Regex patterns are compiled once at load time, not per event.

## Stateful conditions (`stateful`)

Optional block:

```yaml
stateful:
  min_event_count: 5
  min_mprotect_exec_count: 2
  min_rwx_bytes: 4096
```

If present, the rule only matches when the associated process state counters meet the thresholds (`ProcessState` in `aegis-ebpf/src/state/`). Evaluators pass state when available (pipeline integration).

## Complete examples

**Interactive test — substring in argv/cmdline:**

```yaml
rules:
  - id: "SIM_INTERACTIVE_WHOAMI"
    name: "Interactive whoami (manual test)"
    severity: "medium"
    description: "Matches execve cmdline containing whoami."
    conditions:
      syscall: "execve"
      argv_contains:
        - "whoami"
```

**Sensitive file open:**

```yaml
rules:
  - id: "SHADOW_OPEN"
    name: "Read /etc/shadow via openat"
    severity: "critical"
    description: "openat resolving to /etc/shadow."
    conditions:
      syscall: "openat"
      pathname_pattern: ".*/etc/shadow$"
```

**Ptrace attach:**

```yaml
rules:
  - id: "PTRACE_ATTACH"
    name: "Ptrace attach attempt"
    severity: "critical"
    conditions:
      syscall: "ptrace"
      ptrace_request: 16
```

**Shell one-liner (haystack may include paths and shell words):**

```yaml
rules:
  - id: "SHADOW_EXEC"
    name: "Sensitive read via shell"
    severity: "critical"
    conditions:
      syscall: "execve"
      cmdline_contains_any:
        - "cat /etc/shadow"
```

See `tests/simulations/rules.yaml` for additional samples aligned with `tests/simulations/attack_simulator.py`.

## Troubleshooting

- **No match on execve substrings:** Confirm the haystack with logging; if eBPF only provides `argv[0]`, rely on `/proc` resolution or use `cmdline_contains_any` / `argv_contains` which include that fallback.
- **`pathname_pattern` validation error:** Ensure `syscall: openat` is set.
- **`ptrace_request` validation error:** Ensure `syscall: ptrace` is set.

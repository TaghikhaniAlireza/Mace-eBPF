# Rules engine

This document describes the YAML rule format consumed by the userspace rule engine in **`mace-ebpf`** (`mace-ebpf/src/rules/`). Rules filter **enriched** memory and syscall events produced by the eBPF sensor and pipeline.

## File organization: one file vs directory

- **Single file** (for example `rules.yaml` with both `rules:` and `suppressions:`) is simplest for development and small deployments.
- **Directory of YAML files** is better for production: set **`rules_path`** to a **folder**; the engine loads and merges every **regular file** `*.yaml` / `*.yml` in the **top-level** of that directory (**not recursive**), in **UTF-8 path sort** order. Use a numeric prefix (for example `10-detection.yaml`, `90-suppress.yaml`) so load order and code review stay obvious. `rules` and `suppressions` from each file are concatenated in that file order.
- The repository’s **`tests/simulations/rules.yaml`** keeps both in one file for the attack-simulator workflow; you can split the same content into two files in a directory when you outgrow a single file.

## Loading rules

Rules are validated at load time (syntax, syscall names, regex fields, cross-field constraints).

**Rust SDK:** build a `RuleSet` (`mace-ebpf/src/rules/loader.rs`) from a string (`from_yaml_str`), a single file (`from_file`), or a directory of `.yaml`/`.yml` files merged in sorted order (`from_dir`).

**Embedded / FFI:**

- Inline YAML: **`mace_load_rules`**.
- Filesystem path (with optional hot reload when wired through the pipeline): **`mace_load_rules_file`**.

**Go example** (`clients/go/examples`): resolves **`MACE_RULES_FILE`**, then **`/etc/mace/rules.yaml`** if present, otherwise the repository **`tests/simulations/rules.yaml`**.

There is no built-in search path list in the core library; embedders choose defaults (CLI flags, environment variables, `/etc`, and so on).

**Mace stderr filter:** see [Core logging](../4-configuration/logging.md) — how `MACE_LOG_LEVEL` differs from stdout labels in the Go example and from `RUST_LOG`.

## Suppression (trusted processes / false-positive control)

A second top-level key, **`suppressions`**, lists **suppression entries** that use the **same `conditions` language** as rules (**no** `stateful` block). When an event matches at least one suppression entry, **alerts are not fired** for that event, but rules are still evaluated. The JSON event (FFI / Go) then includes:

- **`matched_rules`** — same as without suppression (which rules would have fired),
- **`suppressed_by`** — list of suppression entry **`id`** values that matched (alerts were suppressed because the process is considered trusted for that event pattern).

If no suppression matches, **`suppressed_by`** is omitted from the JSON.

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

Optional **`enforcement_mode`** (Phase 3 — shadow / dry-run):

| Value | Behavior |
|-------|----------|
| `Enforce` (default) | Matched rules drive alert callbacks and appear in **`matched_rules`** in JSON. |
| `Shadow` | Matches are **not** sent to the alert callback; they appear under **`shadow_matched_rules`** with **`shadow: true`** in the standardized JSON for offline FP analysis. |

```yaml
rules:
  - id: "TRY_NEW_RULE"
    name: "candidate"
    severity: "medium"
    description: "Measure FP rate before enforcing."
    enforcement_mode: Shadow
    conditions:
      syscall: "execve"
      argv_contains: ["curl"]
```

## Offline replay (`mace-replay`)

Workspace binary **`mace-replay`** replays JSON-serialized [`MemoryEvent`](../../mace-ebpf-common) records against a rule file or directory **without** loading eBPF:

```bash
cargo build -p mace-replay --release
./target/release/mace-replay replay --data events.json --rules ./rules.yaml
```

**`--data`** accepts: a single JSON object, a JSON array of events, or `{"events":[...]}`. Events must match the **`MemoryEvent`** JSON shape (see `mace-ebpf-common` with `serde` under the `user` feature).

## Rule evaluation profiling (Prometheus)

When the **`prometheus`** / **`observability`** feature is enabled and a Prometheus recorder is installed, the pipeline records **`mace_rule_eval_ns`** (histogram) per **`rule_id`**.

If a single rule’s `matches_with_state` time exceeds **`MACE_RULE_EVAL_WARN_NS`** (default **50000** ns), a **`[Mace][INFO]`** line is emitted: `rule_eval_slow rule_id=…`.

## Rule file shape

Top-level key **`rules`** is an array of rule objects:

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

Optional **`stateful`** block (see below) attaches minimum thresholds using process-local counters.

## Events and syscalls

Each rule may set **`conditions.syscall`** to one of:

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

**Default build:** the eBPF program does **not** read user argv at `sys_enter_execve` (verifier-friendly); **`execve_cmdline`** in events is usually empty and rules rely on **`/proc/<tgid>/cmdline`** (and **`cmdline_context`**) for substring / regex matching.

**Full kernel capture:** when built with **`MACE_EBPF_EXECVE_FULL_ARGV=1`**, the kernel probe captures **`execve` argv at syscall entry** (ring layout **v13**): up to **4** arguments, each up to **63** bytes of string data per `bpf_probe_read_user_str_bytes` (64-byte temp, helper uses 63-byte destination so NUL fits), packed into a **192-byte** NUL-separated blob with an `ExecveWireHeader` (`args_count`, `args_len`, `is_truncated`). This removes the **TOCTOU** gap where userspace-only `/proc/<pid>/cmdline` reads could disagree with the syscall-time image.

When **`execve_argv_truncated`** is true or the haystack is incomplete, rules that need **full** user text should rely on **`cmdline_contains_any`** / **`argv_contains`** (which consult the pipeline haystack: eBPF snapshot → **`cmdline_context`** → **`/proc/<tgid>/cmdline`**) understanding that the `/proc` path is best-effort after exec for very long commands.

For matching, the engine still builds a **haystack** string in this order:

1. Non-empty **`execve_cmdline`** from the event (eBPF snapshot — space-joined captured argv when present),
2. else pipeline **`cmdline_context`** (last exec line attributed to the thread group),
3. else a read of **`/proc/<tgid>/cmdline`** (arguments joined with spaces).

Rules that use **`argv_contains`**, **`cmdline_contains_any`**, or **`cmdline_context_pattern`** operate on this normalized haystack — so substring rules still work when the in-kernel capture is truncated or empty.

## Condition fields (`conditions`)

| Field | Type | Behavior |
|-------|------|----------|
| `syscall` | string | Required for most precise rules; must be a supported syscall name (see table above). |
| `flags_contains` | list of strings | Each named flag must be present on the event (`PROT_*`, `MAP_*`, and so on — validated at load time). |
| `flags_excludes` | list of strings | If any listed flag is present, the rule does not match. |
| `flags_mask_all` | integer | Bitmask: require `(event.flags & mask) == mask` (use for exact `mprotect` prot combinations, e.g. `PROT_READ \| PROT_WRITE \| PROT_EXEC` = 7). |
| `flags_mask_none` | integer | Bitmask: require `(event.flags & mask) == 0` (none of these bits set). |
| `min_size` | integer | Event length field must be ≥ this value (where applicable). |
| `cgroup_pattern` | regex string | Matched against the cgroup path when enrichment provides it. |
| `process_name_pattern` | regex string | Matched against the task `comm` (process name from the kernel). |
| `argv_contains` | list of strings | Every substring must appear in the command-line haystack. |
| `cmdline_contains_any` | list of strings | At least one substring must appear in the haystack. |
| `cmdline_context_pattern` | regex string | Regex against the same haystack (full-line style matching). |
| `uid` | unsigned integer | Effective UID from the event must match. |
| `pathname_pattern` | regex string | **Requires** `syscall: openat`. Matched against a resolved path built from the in-kernel pathname snapshot and `/proc` fd resolution when needed. |
| `ptrace_request` | unsigned integer | **Requires** `syscall: ptrace`. Compared to the ptrace request number on the event (for example `16` for `PTRACE_ATTACH`). |
| `frequency_window` | object | Sliding-window frequency gate (see below). |
| `syscall_failures_only` | boolean | If true, only syscall **failures** (`ret < 0`) count toward `frequency_window` and the current event must also be a failure. **Requires** `frequency_window`. |

Regex patterns are compiled once at load time, not per event.

## Sliding-window frequency (`frequency_window`)

Detect repeated behavior in a time window **per TGID** (for example many failed `openat` calls):

```yaml
conditions:
  syscall: "openat"
  syscall_failures_only: true
  frequency_window:
    min_occurrences: 10
    syscall: "openat"
    window_secs: 5
```

- **`min_occurrences`**: at least this many matching events in the window.
- **`syscall`**: which syscall name to count in the window (must be a supported syscall).
- **`window_secs`**: sliding window length in seconds (converted to nanoseconds at evaluation time).

The engine maintains a bounded deque of recent syscalls per process for this check. **`suppressions`** cannot use `frequency_window` or `syscall_failures_only`.

## Ordered sequence + noise tolerance (`sequence`)

Optional **per-rule** block (sibling of `conditions`, not inside it). Defines an ordered syscall chain **per TGID**. The rule matches only when:

1. The chain has reached the **last** step (same syscall as `conditions.syscall`), and  
2. All `conditions` (flags, pathname, and so on) match that final event.

```yaml
rules:
  - id: "CHAIN_JIT"
    name: "mmap then mprotect then memfd"
    severity: "high"
    description: "Example: tolerate unrelated syscalls between steps."
    sequence:
      steps: ["mmap", "mprotect", "memfd_create"]
      allow_unmapped_between: true
    conditions:
      syscall: "memfd_create"
```

- **`steps`**: syscall names in order. **`conditions.syscall` must match the last step** (validated at load time).
- **`allow_unmapped_between`**: if true, syscalls **not** listed in `steps` do **not** reset progress. A syscall that **is** in `steps` but appears **out of order** resets the chain (or starts over if it matches step 0).

After a rule **matches**, its sequence progress for that TGID resets so a new chain can begin.

## Stateful conditions (`stateful`)

Optional block:

```yaml
stateful:
  min_event_count: 5
  min_mprotect_exec_count: 2
  min_rwx_bytes: 4096
```

If present, the rule only matches when the associated process state counters meet the thresholds (`ProcessState` in **`mace-ebpf/src/state/`**). Evaluators pass state when available (pipeline integration).

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

See **`tests/simulations/rules.yaml`** for additional samples aligned with **`tests/simulations/attack_simulator.py`**.

## Troubleshooting

- **No match on execve substrings:** Confirm the haystack with logging; if eBPF only provides `argv[0]`, rely on `/proc` resolution or use **`cmdline_contains_any`** / **`argv_contains`** which include that fallback.
- **`pathname_pattern` validation error:** Ensure **`syscall: openat`** is set.
- **`ptrace_request` validation error:** Ensure **`syscall: ptrace`** is set.

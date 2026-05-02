# AGENTS.md

## Overview

**mace-ebpf** is a Linux eBPF security/monitoring tool written in Rust using the [aya](https://github.com/aya-rs/aya) framework. It attaches to the `sched_process_exec` tracepoint to monitor process execution events.

### Workspace crates

| Crate | Purpose |
|---|---|
| `mace-ebpf` | Userspace binary — loads and attaches the eBPF program |
| `mace-ebpf-ebpf` | `#![no_std]` eBPF kernel-side program |
| `mace-ebpf-common` | `#![no_std]` shared types library |

## Cursor Cloud specific instructions

### Toolchain requirements

- **Stable Rust** and **Nightly Rust** (with `rust-src` component) are both required.
- **`bpf-linker`** must be installed (`cargo install bpf-linker`).
- The nightly toolchain is used by the build script to compile the eBPF program with `-Z build-std`.

### eBPF `execve` argv build policy (`mace-ebpf/build.rs`)

- **Default** (`cargo build -p mace-ebpf`, `make build-agent`): compiles **`execve_no_user_argv`** so `sys_enter_execve` **does not** read user argv in BPF (verifier-friendly). Execve rules still work via **`/proc/<tgid>/cmdline`** in userspace.
- **Full kernel argv** (when your kernel accepts it): `MACE_EBPF_EXECVE_FULL_ARGV=1 cargo build -p mace-ebpf` or `make rust-build-ebpf-full-argv` / `make build-agent-ebpf-full-argv`.
- **Explicit argv0-only**: `MACE_EBPF_EXECVE_ARGV0_ONLY=1` (see Makefile `rust-build-ebpf-argv0`).

### Build / Check / Test / Lint

Standard commands (see `README.md` for full details):

- **Build:** `cargo build --release` (also builds the eBPF program via build script)
- **Check:** `cargo check`
- **Test:** `cargo test` (no automated tests currently exist beyond empty test harnesses)
- **Lint:** `cargo clippy --all-targets`
- **Format:** `cargo +nightly fmt --check` (must use nightly — `rustfmt.toml` uses unstable features like `imports_granularity` and `group_imports`)

### Running the binary

The binary must run with **root privileges** (`.cargo/config.toml` sets `runner = "sudo -E"`). Use:

```
sudo RUST_LOG=info ./target/release/mace-ebpf
```

**Mace core log filter (optional):** `MACE_LOG_LEVEL=TRACE|INFO|SUPPRESSED|EVENT|ALERT` filters `[Mace][LEVEL] …` lines on stderr from the Rust pipeline (independent of `RUST_LOG`). Embedded callers can use `mace_set_log_level(0..4)` instead. See [docs/4-configuration/logging.md](docs/4-configuration/logging.md) for behavior (including why `ALERT` can still show `suppressed=true` inside `[Mace][ALERT]` lines, and how that differs from the Go example’s stdout labels).

### Cloud VM limitation

The Cursor Cloud VM runs inside a Firecracker microVM whose kernel does not expose full eBPF tracepoint support. The binary **builds successfully** but fails at runtime with `BPF_PROG_LOAD syscall returned Invalid argument (os error 22)`. This is a kernel environment limitation, not a code bug. Build, check, test, clippy, and fmt all work correctly.

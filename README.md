# Aegis-eBPF

**Aegis-eBPF** is a high-performance, production-oriented **Linux eBPF** security and monitoring SDK. The core is written in **Rust** (userspace + [`aya`](https://github.com/aya-rs/aya) eBPF programs) with **CO-RE** (Compile Once — Run Everywhere) so a single BPF object can load across supported kernels. **Go** and **Python** bindings provide a stable **C ABI** (`libaegis_ebpf.so`) for integrating memory-event pipelines and protobuf alerts into your stack.

---

## Badges

<!-- Replace OWNER/REPO with your GitHub path, e.g. TaghikhaniAlireza/Aegis-eBPF -->

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/OWNER/REPO?label=release&logo=github)](https://github.com/OWNER/REPO/releases)
[![License](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0%20%7C%20GPL--2.0%20(eBPF)-blue.svg)](./LICENSE-MIT)

---

## Key features

| Area | What you get |
|------|----------------|
| **Rust + eBPF** | Userspace loader and logic in Rust; kernel programs as `no_std` eBPF attached to syscall tracepoints (`mmap`, `mprotect`, `memfd_create`, `ptrace`) with ring-buffer delivery to user space. |
| **CO-RE** | BPF programs built for the BPF target with BTF-friendly layouts; validated across kernel families via CI matrix and optional [Vagrant kernel matrix](./scripts/vm/README-kernel-matrix.md). |
| **Bounded kernel state** | `BPF_MAP_TYPE_LRU_HASH` for pending syscall entries helps cap memory under fork/syscall churn; rate limiting on hot paths protects the ring buffer under synthetic “JIT storm” load. |
| **High-throughput user-space path** | The FFI `EventArena` (SPSC ring) is micro-benchmarked for **O(1)** push/pop; stress tests have reported on the order of **~3.2M events/s** for the Rust-driven JIT-storm simulator through the arena (workload- and hardware-dependent). |
| **Multi-language FFI** | **Go** (`cgo`) and **Python** (`ctypes`) wrappers with explicit lifecycle (`Close` / context managers), plus optional **Prometheus** / **OpenTelemetry** feature flags in the Rust crate. |
| **CI/CD** | GitHub Actions: lint, audit, multi-OS build/test, Go/Python binding smoke tests, and **tag-driven releases** shipping `libaegis_ebpf.so` + `aegis.h` (see [`.github/workflows/release.yml`](./.github/workflows/release.yml)). |

---

## Prerequisites

### Linux (recommended for eBPF development and runtime)

- **Kernel**: A recent kernel with **BPF** and **BTF** (`CONFIG_DEBUG_INFO_B=y` style) is expected for CO-RE-style workflows and verifier-friendly builds. Tracepoint programs require appropriate `CONFIG_BPF_*` support; some restricted environments (e.g. certain microVMs) cannot load programs—CI documents this with `#[ignore]` integration tests you can run on a full-capability host.
- **Toolchain**: **Stable** and **Nightly** Rust (nightly needs `rust-src` for the nested eBPF build via `-Z build-std`).
- **System packages** (typical Ubuntu/Debian): `clang`, `llvm`, `libelf-dev`, `zlib1g-dev`, `pkg-config`, `build-essential`, `protobuf-compiler`, kernel headers matching `uname -r` where applicable.
- **bpf-linker**: `cargo install bpf-linker` (see [AGENTS.md](./AGENTS.md) for Cloud/agent notes).

### macOS (cross-compile only)

eBPF does not run on macOS; you can cross-compile the Linux binary and copy artifacts to a Linux host. See the historical notes in older docs or `AGENTS.md` for musl/cross hints.

---

## Installation

### Pre-built FFI bundle (GitHub Releases)

On each **`v*`** tag push, [`.github/workflows/release.yml`](./.github/workflows/release.yml) publishes **`aegis-ebpf-linux-amd64.tar.gz`** containing:

- `libaegis_ebpf.so` — Rust `cdylib` with arena + alert-channel FFI
- `aegis.h` — C header for `cgo` / `ctypes`

Extract and point your linker / `LD_LIBRARY_PATH` / `CGO_LDFLAGS` at the directory containing these files (see **Usage** below).

### Build from source

```bash
# Clone and build the workspace (release recommended for production)
cargo build --release

# Shared library output (Linux x86_64 default target)
ls -la target/release/libaegis_ebpf.so

# Generated C header (from build script / cbindgen)
ls -la aegis-ebpf/include/aegis.h
```

Building **`aegis-ebpf`** triggers compilation of the **`aegis-ebpf-ebpf`** program for `bpfel-unknown-none` via `build.rs` (requires nightly + `bpf-linker` as above).

---

## Usage examples

### Go (`cgo`)

The Go module lives under **`aegis-ebpf/pkg/aegis`** (module path: `github.com/aegis-ebpf/sdk/pkg/aegis`). Set **`CGO_CFLAGS`** to the directory containing **`aegis.h`** and **`CGO_LDFLAGS`** / **`LD_LIBRARY_PATH`** to the directory containing **`libaegis_ebpf.so`**.

```go
package main

import (
	"fmt"
	"log"

	"github.com/aegis-ebpf/sdk/pkg/aegis"
)

func main() {
	a, err := aegis.NewArena(1024)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	ev := aegis.Event{
		TimestampNs: 1,
		TGID:        1000,
		PID:         1001,
		SyscallID:   aegis.SyscallMmap,
		Args:        [6]uint64{0x7fff_0000_0000, 4096, 0, 0, 0, 0},
		CgroupID:    42,
		Comm:        [16]byte{'m', 'y', 'a', 'p', 'p', 0},
	}
	if err := a.TryPush(ev); err != nil {
		log.Fatal(err)
	}

	out, err := a.TryPop()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("popped pid=%d addr=%#x\n", out.PID, out.Args[0])
}
```

Run tests against a locally built `.so` (from repo root):

```bash
cargo build -p aegis-ebpf
./aegis-ebpf/pkg/aegis/run_go_tests.sh
```

For a higher-level API with channels, see **`aegis.NewSensor`** and **`aegis.DefaultConfig()`** in [`aegis-ebpf/pkg/aegis/sensor.go`](./aegis-ebpf/pkg/aegis/sensor.go).

### Python (`ctypes`)

Install the package from **`aegis-ebpf/python`** (requires **`libaegis_ebpf.so`** on **`LD_LIBRARY_PATH`** and `aegis.h` reachable via the package’s expected layout, or run from a checkout with the `.so` next to / discoverable by the loader).

```python
from aegis import Arena, raw_memory_event

with Arena(16) as arena:
    ev = raw_memory_event(
        timestamp_ns=123456789,
        tgid=1000,
        pid=2000,
        syscall_id=1,
        args=(0x7FFF0000, 64, 0, 0, 0, 0),
        cgroup_id=0,
        comm=b"demo",
    )
    arena.push(ev)
    out = arena.pop()
    print(out.tgid, out.pid, out.args[0])
```

```bash
export LD_LIBRARY_PATH=/path/to/dir-with-lib:$LD_LIBRARY_PATH
cd aegis-ebpf/python && pip install -e . && pytest tests/ -v
```

---

## Project structure

```text
.
├── aegis-ebpf/              # Main Rust crate: userspace SDK, FFI (cdylib), optional k8s / observability
│   ├── src/                 # lib.rs, pipeline, rules, ffi/, …
│   ├── include/             # Generated aegis.h (C FFI)
│   ├── pkg/aegis/           # Go module: cgo bindings, Sensor, Arena, protobuf
│   └── python/              # Python package: ctypes wrappers + examples
├── aegis-ebpf-ebpf/         # no_std eBPF programs (tracepoints, maps, ring buffer)
├── aegis-ebpf-common/       # Shared types (user + kernel layouts)
├── aegis-ebpf-loader/       # Minimal loader binary (daemon mode for VM/matrix tests)
├── .github/workflows/       # CI (lint, build, tests, FFI) + release on v* tags
├── scripts/vm/              # Vagrant / kernel-matrix and stress-suite scripts
├── AGENTS.md                # Agent/toolchain notes for contributors
└── README.md                # This file
```

---

## Documentation and testing

- **[AGENTS.md](./AGENTS.md)** — Rust stable/nightly, `bpf-linker`, and common `cargo` commands.
- **[docs/PHASE_1_TO_4_AUDIT_REPORT.md](./docs/PHASE_1_TO_4_AUDIT_REPORT.md)** — Blueprint audit (tests, Miri/ASAN, matrix, FFI).
- **Integration tests** under `aegis-ebpf/tests/` (many require root + full BPF; see test module docs and `sudo` + `--ignored` invocations).

---

## License

- **Userspace Rust and shared tooling** (excluding the eBPF program sources): **MIT OR Apache-2.0**, at your option — see [LICENSE-MIT](./LICENSE-MIT) and [LICENSE-APACHE](./LICENSE-APACHE).
- **eBPF program sources** (`aegis-ebpf-ebpf/`): **GPL-2.0 OR MIT**, at your option — see [LICENSE-GPL2](./LICENSE-GPL2) and [LICENSE-MIT](./LICENSE-MIT).

Unless you explicitly state otherwise, contributions are licensed under the same terms as the respective subtree you modify.

---

*Aegis-eBPF — kernel insight with a stable FFI surface for the languages you already use.*

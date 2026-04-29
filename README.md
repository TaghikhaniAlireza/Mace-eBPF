# Mace-eBPF

**The missing piece in real-time detection of code injection, memory anomalies, and suspicious behavior across Linux, cloud-native deployments, and Kubernetes ecosystems, with multi-language support.**

**Mace-eBPF** is a high-performance, production-oriented **Linux eBPF** security and monitoring SDK. The core is written in **Rust** (userspace + [`aya`](https://github.com/aya-rs/aya) eBPF programs) with **CO-RE** (Compile Once — Run Everywhere) so a single BPF object can load across supported kernels. **Go** (`cgo`) links the Rust userspace core **statically** via `libmace_ebpf.a` (no `LD_LIBRARY_PATH` for the Go path). **Python** (`ctypes`) loads the same FFI through the **`libmace_ebpf.so`** `cdylib` plus `mace.h`.

---

## Badges

[![CI](https://github.com/TaghikhaniAlireza/Mace-eBPF/actions/workflows/ci.yml/badge.svg)](https://github.com/TaghikhaniAlireza/Mace-eBPF/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/TaghikhaniAlireza/Mace-eBPF?label=release&logo=github)](https://github.com/TaghikhaniAlireza/Mace-eBPF/releases)
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
| **CI/CD** | GitHub Actions: lint, audit, multi-OS build/test, Go/Python binding smoke tests, **tag-driven releases** (`.deb` + FFI tarball), **GHCR** images with cosign (see [`.github/workflows/`](./.github/workflows/)). |

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

## Docker (pre-built image)

See **[docs/1-getting-started/quickstart.md](./docs/1-getting-started/quickstart.md)** for `docker run --privileged … ghcr.io/taghikhanialireza/mace-ebpf:latest` (GHCR publishes on pushes to `main` and on `v*` tags).

Full documentation index: **[docs/README.md](./docs/README.md)**.

## Installation

### Pre-built FFI bundle (GitHub Releases)

On each **`v*`** tag push, [`.github/workflows/release.yml`](./.github/workflows/release.yml) publishes **`mace-ebpf-linux-amd64.tar.gz`** containing:

- `libmace_ebpf.so` — Rust `cdylib` (Python `ctypes` and any dynamic consumers)
- `libmace_ebpf.a` — Rust `staticlib` (recommended for **Go** `cgo`; see below)
- `mace.h` — C header for `cgo` / `ctypes`

**Python:** add the extract directory to **`LD_LIBRARY_PATH`** (or install the `.so` into the loader search path). **Go:** point **`CGO_CFLAGS`** at the directory with **`mace.h`** and **`CGO_LDFLAGS`** at **`libmace_ebpf.a`** plus `-ldl -lpthread -lm -lgcc_s`, or use the in-repo packages which already embed those flags (debug vs release is selected with the **`mace_static_release`** build tag — see **Usage** below).

### Build from source

```bash
# Clone and build the workspace (release recommended for production)
cargo build --release

# Shared + static library output (Linux x86_64 default target)
ls -la target/release/libmace_ebpf.so target/release/libmace_ebpf.a

# Generated C header (from build script / cbindgen)
ls -la mace-ebpf/include/mace.h
```

Building **`mace-ebpf`** triggers compilation of the **`mace-ebpf-ebpf`** program for `bpfel-unknown-none` via `build.rs` (requires nightly + `bpf-linker` as above).

---

## Usage examples

### Go (`cgo`)

The Go module lives under **`mace-ebpf/pkg/mace`** (module path: `github.com/mace-ebpf/sdk/pkg/mace`). The package **`#cgo`** directives link **`libmace_ebpf.a`** from **`target/debug`** by default. After **`cargo build --release -p mace-ebpf`**, build or test Go with **`-tags mace_static_release`** so the linker uses **`target/release/libmace_ebpf.a`**. You do **not** set **`LD_LIBRARY_PATH`** for this Go path. To override paths in your own module, set **`CGO_CFLAGS=-I.../mace-ebpf/include`** and **`CGO_LDFLAGS=.../libmace_ebpf.a -ldl -lpthread -lm -lgcc_s`**.

```go
package main

import (
	"fmt"
	"log"

	"github.com/mace-ebpf/sdk/pkg/mace"
)

func main() {
	a, err := mace.NewArena(1024)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	ev := mace.Event{
		TimestampNs: 1,
		TGID:        1000,
		PID:         1001,
		SyscallID:   mace.SyscallMmap,
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

Run tests against a locally built static library (from repo root):

```bash
cargo build -p mace-ebpf
./mace-ebpf/pkg/mace/run_go_tests.sh
# Or: make go-test
# After `cargo build --release -p mace-ebpf`: MACE_GO_STATIC_RELEASE=1 ./mace-ebpf/pkg/mace/run_go_tests.sh
```

For a higher-level API with channels, see **`mace.NewSensor`** and **`mace.DefaultConfig()`** in [`mace-ebpf/pkg/mace/sensor.go`](./mace-ebpf/pkg/mace/sensor.go).

### Python (`ctypes`)

Install the package from **`mace-ebpf/python`** (requires **`libmace_ebpf.so`** on **`LD_LIBRARY_PATH`** and `mace.h` reachable via the package’s expected layout, or run from a checkout with the `.so` next to / discoverable by the loader).

```python
from mace import Arena, raw_memory_event

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
cd mace-ebpf/python && pip install -e . && pytest tests/ -v
```

---

## Project structure

```text
.
├── mace-ebpf/              # Main Rust crate: userspace SDK, FFI (cdylib/staticlib), optional k8s / observability
│   ├── src/                 # lib.rs, pipeline, rules, ffi/, …
│   ├── include/             # Generated mace.h (C FFI)
│   ├── pkg/mace/           # Go module: cgo bindings, Sensor, Arena, protobuf
│   └── python/              # Python package: ctypes wrappers + examples
├── mace-ebpf-ebpf/         # no_std eBPF programs (tracepoints, maps, ring buffer)
├── mace-ebpf-common/       # Shared types (user + kernel layouts)
├── mace-ebpf-loader/       # Minimal loader binary (daemon mode for VM/matrix tests)
├── clients/go/              # Go SDK (`mace`), mace-agent, examples
├── docs/                    # Structured technical documentation (see docs/README.md)
├── packaging/               # nfpm (.deb), systemd unit, default config/rules
├── .github/workflows/       # CI, release (tarball + .deb), Docker (GHCR)
├── scripts/vm/              # Vagrant / kernel-matrix and stress-suite scripts
├── AGENTS.md                # Agent/toolchain notes for contributors
└── README.md                # This file
```

---

## Documentation and testing

- **[docs/README.md](./docs/README.md)** — Documentation map (getting started, installation, concepts, configuration, developer guide, references).
- **[AGENTS.md](./AGENTS.md)** — Rust stable/nightly, `bpf-linker`, and common `cargo` commands.
- **[docs/6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md](./docs/6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md)** — Blueprint audit (tests, Miri/ASAN, matrix, FFI).
- **Integration tests** under `mace-ebpf/tests/` (many require root + full BPF; see test module docs and `sudo` + `--ignored` invocations).

---

## License

- **Userspace Rust and shared tooling** (excluding the eBPF program sources): **MIT OR Apache-2.0**, at your option — see [LICENSE-MIT](./LICENSE-MIT) and [LICENSE-APACHE](./LICENSE-APACHE).
- **eBPF program sources** (`mace-ebpf-ebpf/`): **GPL-2.0 OR MIT**, at your option — see [LICENSE-GPL2](./LICENSE-GPL2) and [LICENSE-MIT](./LICENSE-MIT).

Unless you explicitly state otherwise, contributions are licensed under the same terms as the respective subtree you modify.

---

*Mace-eBPF — kernel insight with a stable FFI surface for the languages you already use.*

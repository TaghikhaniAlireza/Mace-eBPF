# Aegis eBPF

A Linux **userspace security monitoring SDK** built in Rust. It uses **eBPF** (via [Aya](https://github.com/aya-rs/aya)) to observe memory-related syscalls, streams events through a **Tokio pipeline** with optional **Kubernetes enrichment**, a **YAML rule engine** (with hot-reload), **stateful detection**, and **alerts**. The same core library exposes a **C ABI** (shared library + `aegis.h`), **optional Prometheus and OpenTelemetry** exporters, and **Go** and **Python** language bindings for integration with other runtimes.

---

## Core features

**Section 1 — eBPF and event capture**

- Kernel programs attached to **syscalls** for memory-relevant activity: `mmap`, `mprotect`, `memfd_create`, `ptrace` (enter/exit tracepoints).
- **Ring buffer** map for high-throughput event delivery to userspace; shared **POD types** in `aegis-ebpf-common` (`MemoryEvent`, syscall / `EventType` mapping).
- **Optional BTF** handling: use vmlinux BTF when present, or **download** a BTFHub archive when needed (see `load_btf` in the library).
- **PID allowlist** map and configurable **userspace channel** capacity.

**Section 2 — Enrichment**

- Pluggable **`ContextEnricher`** trait; **no-op** and **Kubernetes** (optional `kubernetes` feature) enrichers with **Moka**-backed caching for pod/namespace-style metadata.

**Section 3 — Pipeline, rules, and state**

- **Async pipeline**: raw events → enrich → **time-windowed reorder** buffer → **hash-based partition router** → per-partition workers.
- **YAML rules** with `arc-swap` and a **file watcher** for **hot-reload**; conditions include syscall name, memory **flags**, size, cgroup path patterns, and **stateful** thresholds.
- **`StateTracker`** for per-TGID behavior; **alerts** via async callbacks with structured `Alert` data.
- **Protobuf** schema for alerts (`proto/alert.proto`); code generated with **prost** at build time.

**Section 4 — FFI, multi-language bindings, and observability**

- **C-compatible types** and **cbindgen**-generated `aegis-ebpf/include/aegis.h` (patched in the build script for complete FFI declarations).
- **FFI arena** (lock-free ring of `RawMemoryEvent`) and **alert channel** (protobuf over a bounded async path) with **panic boundaries** (`catch_unwind`) on the C API.
- **Go** package: `aegis-ebpf/pkg/aegis` (cgo, channels, protobuf, `runtime.SetFinalizer`); see that directory’s README for build paths.
- **Python** package: `aegis-ebpf/python` (ctypes, `alert_pb2` from the same proto, context managers); `pip install -e` supported.
- **Optional observability** (`prometheus`, `otel`, or `observability` features): **metrics** facade, **Prometheus** HTTP scrape endpoint, **OTLP/gRPC** tracing; **Docker Compose** example under `aegis-ebpf/examples/observability/` (Prometheus, Grafana, Jaeger).

---

## Tech stack

| Area | Technologies |
|------|----------------|
| **Language** | Rust 2024 edition; eBPF programs `#![no_std]` |
| **eBPF** | [Aya](https://github.com/aya-rs/aya) (git), `aya-build`, `aya-ebpf`, `aya-log` / `aya-log-ebpf` |
| **Async runtime** | **Tokio** (full in the main crate) |
| **Serialization** | **serde** / **serde_yaml** / **serde_json**; **prost** + **prost-build** (build) for protobuf |
| **Rules & config** | **regex**; **notify** for file watching; **arc-swap** for atomic rule set swaps |
| **Kubernetes (optional)** | **kube**, **k8s-openapi**, **moka** |
| **HTTP / TLS** | **reqwest** (blocking, rustls) for BTF downloads and tooling |
| **Tracing (Rust)** | **tracing**; dev: **tracing-subscriber** |
| **Observability (optional)** | **metrics**, **metrics-exporter-prometheus**; **opentelemetry**, **opentelemetry_sdk**, **opentelemetry-otlp** (gRPC / tonic stack) |
| **FFI / codegen** | **cbindgen** (build); **libc** |
| **Other** | **anyhow**, **uuid**, **futures**, **async-trait**, **tempfile** (tests/temp paths) |

**Bindings**

- **Go**: Module `github.com/aegis-ebpf/sdk/pkg/aegis`, **protobuf** Go runtime, cgo against `libaegis_ebpf`.
- **Python**: **protobuf** Python package; **ctypes** against the same shared library.

**Tooling (host)**

- **Stable + Nightly** Rust; nightly **`rust-src`** for `-Z build-std` eBPF builds.
- **`bpf-linker`** for linking eBPF objects.
- **`protoc`** for protobuf generation (Rust build script and Python regeneration).
- Formatting: **`cargo +nightly fmt`** (`rustfmt.toml` uses unstable options).

---

## Architecture overview

The workspace is a **Cargo workspace** with three crates:

| Crate | Role |
|-------|------|
| **`aegis-ebpf`** | Primary library and CLI binary: loads eBPF, runs **`start_sensor`**, **`start_pipeline`**, modules **`alert`**, **`enrichment`**, **`pipeline`**, **`rules`**, **`state`**, **`ffi`**, **`proto`**, **`observability`**. Builds as **`cdylib` + `rlib`** for C/Go/Python. |
| **`aegis-ebpf-common`** | **`#![no_std]`** shared structs and enums (`MemoryEvent`, kernel raw layout, syscall IDs) used in both kernel and userspace (`user` feature). |
| **`aegis-ebpf-ebpf`** | eBPF crate compiled via **aya-build** (nightly **build-std**); emits events into maps consumed by userspace. |

**Data flow (simplified):** eBPF → ring buffer → **`MemoryEvent`** stream → enrichment → reorder → partitioned rule evaluation + state → optional **`Alert`** callbacks and/or FFI alert channel; metrics and traces hook into arena, pipeline workers, and alert paths when features are enabled.

Language bindings link against **`libaegis_ebpf`** produced in the workspace **`target/`** directory (paths differ slightly per binding; see `pkg/aegis` and `python` READMEs).

---

## Getting started

### Prerequisites

1. **Rust**: stable and nightly toolchains; add **`rust-src`** to nightly:  
   `rustup toolchain install nightly --component rust-src`
2. **`bpf-linker`**: `cargo install bpf-linker` (on macOS use `--no-default-features` if needed).
3. **`protoc`**: required for prost during **`aegis-ebpf`** builds (e.g. `protobuf-compiler` on Debian/Ubuntu).

### Build and test

```bash
cargo build --release
cargo test --all-features
cargo clippy --all-features --all-targets
cargo +nightly fmt --check
```

The build script compiles the eBPF program and refreshes **`aegis-ebpf/include/aegis.h`** where applicable.

### Run the binary

The program loads eBPF programs and must run with **sufficient privileges** (typically **root**) on a kernel that supports the attached tracepoints and maps.

```bash
sudo RUST_LOG=info ./target/release/aegis-ebpf
```

Some restricted environments (e.g. certain microVMs) may not expose full eBPF tracepoint support; load failures there are often **environment limits**, not application bugs.

### Optional features

```bash
# Kubernetes enrichment
cargo build -p aegis-ebpf --features kubernetes

# Prometheus metrics HTTP + OTLP traces
cargo build -p aegis-ebpf --features observability
```

Start the observability stack from **`aegis-ebpf/examples/observability/`** with Docker Compose when using metrics/traces (see **`README.md`** in that folder).

### Cross-compilation (Linux target from macOS)

```bash
CC=${ARCH}-linux-musl-gcc cargo build --package aegis-ebpf --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

Copy the resulting binary to a Linux machine that matches your deployment kernel/eBPF capabilities.

---

## Project roadmap

| Phase | Scope | Status |
|-------|--------|--------|
| **1** | eBPF syscall monitoring, ring buffer, shared types, userspace sensor | **Done** |
| **2** | Context enrichment (K8s optional) | **Done** |
| **3** | Pipeline, YAML rules, hot-reload, state, alerts, protobuf alerts | **Done** |
| **4** | FFI (arena, alert channel, panic-safe API), C header, Go/Python bindings, observability (Prometheus + OTLP), compose example | **Done** |
| **Future** | Additional integrations, dashboards, deployment guides, extended rule packs, CI hardening — as needed by downstream consumers | **Planned** |

---

## License

Userspace Rust code is licensed under **MIT OR Apache-2.0** (see `LICENSE-MIT`, `LICENSE-APACHE`).

eBPF kernel-side code is licensed under **GPL-2.0 OR MIT** (see `LICENSE-GPL2`, `LICENSE-MIT`).

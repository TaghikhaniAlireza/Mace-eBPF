# Building from source

This document covers building the **Rust** workspace (including the eBPF object), the **Go** agent/SDK with CGO, and optional **`.deb`** packaging.

## Toolchains

| Component | Requirement |
|-----------|-------------|
| **Rust stable** | Workspace `edition = "2024"`; use a current stable toolchain. |
| **Rust nightly** | **`rust-src`** component for `aegis-ebpf/build.rs` nested eBPF build (`-Z build-std`). |
| **`bpf-linker`** | `cargo install bpf-linker` (pinned in CI, e.g. `0.10.3`). |
| **System packages** (Debian/Ubuntu) | `clang`, `llvm`, `libelf-dev`, `zlib1g-dev`, `pkg-config`, `build-essential`, `protobuf-compiler`, kernel headers matching the build host where applicable. |
| **Go** | **1.21+** for `clients/go` (module `github.com/aegis-ebpf/sdk/clients/go`). |

See **[AGENTS.md](../../AGENTS.md)** for contributor-focused notes and Cloud VM BPF limitations.

## Rust workspace (release)

From the repository root:

```bash
cargo build --release
```

This builds **`aegis-ebpf`** (userspace) and, via **`aegis-ebpf/build.rs`**, the **`aegis-ebpf-ebpf`** BPF object for the `bpfel-unknown-none` target.

Artifacts of interest:

| Output | Location |
|--------|----------|
| Static + shared Rust FFI | `target/release/libaegis_ebpf.a`, `target/release/libaegis_ebpf.so` |
| C header | `aegis-ebpf/include/aegis.h` |
| eBPF object (embedded + under `target/.../out/`) | Used at runtime via `include_bytes_aligned!` in `aegis-ebpf/src/lib.rs` |

## Go agent (`aegis-agent`)

**Debug** Rust + **debug** static library (default CGO paths in `clients/go/aegis/aegis.go`):

```bash
make build-agent
# binary: ./build/aegis-agent
```

**Release** Rust + **release** static library (required for production and for `make pack-deb`):

```bash
make build-agent-release
```

This runs `go build -tags aegis_static_release` so the linker picks **`target/release/libaegis_ebpf.a`**.

Environment:

```bash
cd clients/go
CGO_ENABLED=1 go test -race -v ./...
```

## Debian package (optional)

```bash
VERSION_TAG=1.2.3 make pack-deb
```

Requires **nFPM** installed. See [Linux .deb](./linux-deb.md).

## OCI image (optional)

Multi-stage **`Dockerfile`** at the repository root builds Rust (release), then the Go agent, then copies binaries and config into a **distroless** runtime. See [Quickstart](../1-getting-started/quickstart.md).

## Verification commands (short)

```bash
cargo check
cargo test -p aegis-ebpf --lib
cargo clippy --all-targets --all-features -- -D warnings
cargo +nightly fmt --check
```

Full CI behavior is described in [Testing and CI](../5-developer-guide/testing-and-ci.md).

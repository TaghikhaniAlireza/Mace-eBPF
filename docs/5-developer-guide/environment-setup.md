# Environment setup

This guide lists what you need on a **Linux** workstation to build and hack on Aegis-eBPF.

## Operating system

- **Debian / Ubuntu** (recommended) for parity with CI and straightforward `apt` packages.
- Other distributions work if you provide **`clang`**, **`llvm`**, **`libelf`**, **`zlib`**, **`pkg-config`**, and matching **kernel headers** for local BPF development.

## Rust

| Requirement | Notes |
|-------------|--------|
| **Stable Rust** | Workspace `edition = "2024"`; use current stable. |
| **Nightly Rust** | With **`rust-src`** for `aegis-ebpf/build.rs` nested eBPF build (`-Z build-std`). |
| **`bpf-linker`** | `cargo install bpf-linker` (CI pins a version such as `0.10.3`). |

Install toolchains (example):

```bash
rustup toolchain install stable --component clippy rustfmt
rustup toolchain install nightly --component rust-src rustfmt
```

## System packages (Debian/Ubuntu example)

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config clang llvm \
  libelf-dev zlib1g-dev protobuf-compiler \
  linux-headers-$(uname -r)
```

## Go (optional, for `clients/go`)

- **Go 1.21+**
- **`CGO_ENABLED=1`** when building or testing **`aegis`** / **`aegis-agent`**
- **`gcc`** available on `PATH` (bookworm-derived CI images work well)

## Python (optional, for `aegis-ebpf/python`)

- Python **3.11+** recommended (matches CI)
- **`libaegis_ebpf.so`** on the loader search path or **`LD_LIBRARY_PATH`**

## BPF program loading caveats

Some environments (for example **Firecracker** microVMs or minimal CI kernels) **cannot attach** tracepoint programs even when userspace compiles cleanly. Symptoms include **`BPF_PROG_LOAD`** / attach errors at runtime. This is an **environment** limitation, not necessarily a bug in the tree — see **[AGENTS.md](../../AGENTS.md)** for Cloud agent notes.

## Next steps

- [Building from source](../2-installation/from-source.md)
- [Testing and CI](./testing-and-ci.md)

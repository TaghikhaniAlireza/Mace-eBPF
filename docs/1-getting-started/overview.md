# Overview

**Mace-eBPF** is a security-focused **Linux eBPF** monitoring stack. It attaches **syscall tracepoint** programs (for example `mmap`, `mprotect`, `execve`, `openat`, `ptrace`, `memfd_create`), streams observations to userspace through a **ring buffer**, and evaluates **YAML** rules against enriched events.

## What you get

| Layer | Technology | Responsibility |
|-------|------------|----------------|
| **Kernel** | Rust + [Aya](https://github.com/aya-rs/aya), `no_std` | Capture syscall arguments, pending/exit correlation, rate limiting, allowlists. |
| **Userspace core** | Rust (`mace-ebpf` crate) | Load CO-RE BPF object, reorder/enrich events, run rule engine and suppressions, optional k8s enrichment. |
| **FFI** | C ABI (`mace.h`, `libmace_ebpf.so` / static `.a`) | Embedded engines, Go `cgo`, Python `ctypes`. |
| **Agent** | Go (`mace-agent`) | CLI, file-backed config, structured event log, systemd integration. |
| **Distribution** | `.deb` (nFPM), OCI (GHCR), tarball | Pre-built binaries and libraries for integrators. |

## Design principles (as implemented)

- **CO-RE–friendly layouts** in `mace-ebpf-common` so a single built BPF object can target multiple kernels when BTF and verifier constraints allow.
- **Bounded kernel state** (for example LRU maps for pending syscalls) to cap memory under fork churn.
- **Separation of detection and noise control**: YAML **rules** fire alerts; **suppressions** can silence alerts while still recording matched rule IDs in the exported event JSON.
- **Stable event export**: after evaluation, the pipeline emits a **JSON** view (`StandardizedEvent` in Rust, `MaceEvent` in Go) suitable for SIEM pipelines and agents.

## What this is not

- A full **EDR** product UI or cloud backend (those are integration points).
- A guarantee that every **GitHub Actions** or **Firecracker** host can **load** BPF programs (kernel and LSM policy vary). The project documents these limits in [Environment setup](../5-developer-guide/environment-setup.md) and [Testing and CI](../5-developer-guide/testing-and-ci.md).

## Next steps

1. **[Who uses Mace, and how?](./audiences.md)** — choose your path: operator, analyst/researcher, or developer (Go / Python).
2. **[Quickstart](./quickstart.md)** — run the published container image with Docker.
3. **[Installation: Linux .deb](../2-installation/linux-deb.md)** — install the packaged agent on Debian/Ubuntu.
4. **[Architecture](../3-concepts/architecture.md)** — understand components before customizing rules.

# Mace-eBPF documentation

Welcome to the technical documentation for **Mace-eBPF**: a Linux **eBPF**–based security monitoring stack with a **Rust** userspace core, **YAML** rule engine, **Go** SDK and standalone **mace-agent**, and optional **Python** bindings.

**New here?** Start with **[Who uses Mace, and how?](./1-getting-started/audiences.md)** — paths for **users**, **analysts/researchers**, and **developers** (Go full pipeline vs lower-level API vs Python).

This library is designed for operators and integrators who need **CO-RE**-style eBPF programs, a stable **C ABI**, and production-oriented packaging (`.deb`, OCI images, GitHub Releases).

---

## Documentation map

| Section | Contents |
|--------|----------|
| **[1 — Getting started](./1-getting-started/overview.md)** | What Mace is, scope, and how it fits in your stack. |
| | **[Audiences: user, analyst, developer](./1-getting-started/audiences.md)** — how to run standalone, consume events, embed Go, use Python. |
| | [Quickstart (Docker)](./1-getting-started/quickstart.md) — run a pre-built image in minutes. |
| **[2 — Installation](./2-installation/linux-deb.md)** | Debian `.deb` (nFPM), systemd, and [building from source](./2-installation/from-source.md). |
| **[3 — Concepts](./3-concepts/architecture.md)** | Sensor, pipeline, FFI, agent, and data flow. |
| | [Rules engine](./3-concepts/rules-engine.md) — YAML rules and suppressions. |
| | [Events and alerts](./3-concepts/events-and-alerts.md) — `MaceEvent` JSON and classification. |
| **[4 — Configuration](./4-configuration/agent-config.md)** | Agent `config.yaml` and rules layout. |
| | [Core logging](./4-configuration/logging.md) — `MACE_LOG_LEVEL` and `[Mace][LEVEL]` lines. |
| **[5 — Developer guide](./5-developer-guide/environment-setup.md)** | Toolchains, bpf-linker, local builds. |
| | [Testing and CI](./5-developer-guide/testing-and-ci.md) — GitHub Actions, releases, containers. |
| **[6 — References](./6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md)** | Phase 1–4 audit / traceability report. |
| | [Version notes — 0.1.x](./6-references/versions/v0.1.x.md) | Changelog-style notes for the 0.1.x line. |

---

## Repository map (quick)

| Path | Role |
|------|------|
| `mace-ebpf-ebpf/` | `no_std` eBPF programs (tracepoints, maps, ring buffer). |
| `mace-ebpf-common/` | Shared wire formats and types (kernel + userspace). |
| `mace-ebpf/` | Rust SDK: loader, pipeline, rules, FFI (`cdylib` / `staticlib`), optional observability. |
| `clients/go/` | Go module: `mace` SDK, `mace-agent`, examples. |
| `mace-ebpf/pkg/mace/` | Legacy / alternate Go module path (arena, sensor, protobuf). |
| `packaging/` | nFPM (`nfpm.yaml`), systemd unit, lifecycle scripts, default config. |
| `.github/workflows/` | CI, release (tarball + `.deb`), Docker (GHCR + cosign). |

---

## Contributing

Use **[AGENTS.md](../AGENTS.md)** for agent-specific toolchain notes (nightly, `bpf-linker`, Cloud VM BPF limitations). For prose and structure changes, follow the numbered sections above so navigation stays predictable.

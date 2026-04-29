# Mace-eBPF — Project state (single source of truth)

**Purpose:** This document is the canonical snapshot of the **Mace-eBPF** codebase (formerly branded *Aegis-eBPF* in some remotes and history). Use it as **shared context** for future engineering work, security review, and AI-assisted development.

**Scope:** Rust eBPF programs and userspace core, FFI, Go/Python clients, rule engine, CLIs, CI/CD, packaging, and observability—as implemented in this repository at the time of authoring.

**Non-goals:** This file does not replace runbooks for your production environment, kernel-specific tuning guides, or threat-model documents unless those concerns are explicitly reflected in code or checked-in docs.

---

## 1. Project overview and architecture

### 1.1 What the project does

Mace-eBPF is a **Linux security / monitoring sensor** built in **Rust** on **[Aya](https://github.com/aya-rs/aya)**. It attaches **BPF tracepoint** programs to selected **syscall** enter/exit pairs (for example `execve`, `openat`, `ptrace`, and optional memory-related syscalls such as `mmap`, `mprotect`, `memfd_create`). The eBPF side samples syscall context, correlates enter/exit where needed, and ships compact records to userspace through a **ring buffer**.

Userspace (`mace-ebpf` crate as a **library**) loads the pre-built **CO-RE-style** eBPF ELF, manages maps, drains the ring buffer, **enriches** events (optional Kubernetes metadata, `/proc` and passwd-derived fields), maintains **per-process behavioral state**, evaluates a **YAML rule engine**, emits **alerts** and **structured JSON events**, and exposes optional **Prometheus / OpenTelemetry** metrics.

A **C ABI (`cdylib` / `staticlib`)** allows embedding the engine in **Go** (`cgo`) or **Python** (`ctypes`). The primary shipping artifact for operators is the **`mace-agent`** Go binary (config-driven daemon with `run` / `status` subcommands).

### 1.2 Architectural layers

| Layer | Location (typical) | Responsibility |
|-------|-------------------|------------------|
| **Kernel / eBPF** | `mace-ebpf-ebpf/` | `#![no_std]` programs: tracepoints, **RingBuf** output, **LRU** maps for pending syscalls / allowlist / rate limiting, fixed-size scratch for argv/path capture, **`KERNEL_STATS`** counters for ringbuf/LRU pressure. |
| **Shared wire types** | `mace-ebpf-common/` | `#![no_std]` structs, constants, parsing of ring samples into `MemoryEvent` (with optional `serde` in `user` feature). |
| **Userspace core** | `mace-ebpf/` | Aya loader (`lib.rs`), **pipeline** (ingest → enrich → reorder → partition workers → rule eval), **state tracker**, **rules** (YAML → `RuleSet`), **alerts**, **audit** log, **kernel_health** scrapers, **FFI** surface, optional **metrics** / **OTel**. |
| **FFI** | `mace-ebpf/src/ffi/`, `mace-ebpf/include/mace.h` | Engine lifecycle, rules load, pipeline start/stop, arena helpers, JSON event callbacks, health JSON, allowlist updates, log level, staged rule count. Generated header via **cbindgen** in `build.rs`. |
| **Agents / SDKs** | `clients/go/`, `mace-ebpf/pkg/mace/`, `mace-ebpf/python/` | Go **cgo** SDK + **`mace-agent`** CLI; alternate Go module path for packaging; Python bindings and high-level helpers. |
| **Tooling** | `mace-ebpf-loader/`, `mace-replay/` | Minimal loader for matrix tests; **offline** JSON → rule replay CLI. |
| **Distribution** | `Dockerfile`, `packaging/`, `.github/workflows/release.yml` | Multi-stage OCI image (Rust → Go static agent → distroless), **nFPM** `.deb`, GitHub Releases. |

### 1.3 Primary data flow (runtime)

1. **Syscall** fires on CPU → eBPF tracepoint handler reads args / UID / comm, manages **pending** maps for split enter/exit events, applies **allowlist** and **rate limits**, writes **`RingBufferSample`** to **`EVENTS`** ringbuf (incrementing **`KERNEL_STATS`** on reserve/output failures).
2. **Userspace sensor** (`start_sensor` in `mace-ebpf/src/lib.rs`) attaches programs (required vs optional tracepoints differentiated), exposes raw `MemoryEvent` stream via channel.
3. **`start_pipeline`** orchestrates Tokio tasks: enrichment (`ContextEnricher`), cmdline/username augmentation, **reorder heap** for timestamp ordering, worker pool, **RuleSet** evaluation with suppressions, **shadow vs enforce** split, **sequence** state, metrics and optional callbacks.

### 1.4 Repository layout (workspace members)

| Crate / dir | Role |
|-------------|------|
| `mace-ebpf` | Main library + optional `mace-ebpf` binary; **FFI** export; benches. |
| `mace-ebpf-common` | Shared types; `user` feature enables serde/alloc helpers. |
| `mace-ebpf-ebpf` | eBPF program crate (built with nightly / `bpf-linker` / `-Z build-std` via `mace-ebpf/build.rs`). |
| `mace-ebpf-loader` | Small loader binary for attach/load testing. |
| `mace-replay` | `mace-replay replay` CLI for offline evaluation. |
| `clients/go` | Go module for **`mace-agent`** and SDK (`module github.com/mace-ebpf/sdk/clients/go`). |
| `mace-ebpf/pkg/mace` | Additional Go module used in some packaging paths. |
| `mace-ebpf/python` | Installable Python package with ctypes FFI. |
| `docs/` | Operator and developer documentation (this file included). |
| `scripts/`, `scripts/vm/` | CI helpers, Criterion gate, optional **Vagrant** kernel matrix. |
| `packaging/` | `nfpm` manifest, systemd unit, example config/rules. |

---

## 2. Technology stack

### 2.1 Languages

- **Rust** (workspace `edition = "2024"`): userspace, build scripts, tests, benches; eBPF program in `mace-ebpf-ebpf` with **`#![no_std]`**.
- **Go** 1.21+: **`mace-agent`**, SDK tests, static linking path via build tags.
- **Python** 3.11+ (CI): bindings tests.
- **Shell**: `run_memory_checks.sh`, VM matrix scripts.
- **YAML**: rule files; **JSON**: structured events, audit log, replay input.
- **Protobuf**: `prost` / `prost-build`; `proto/alert.proto` → generated `mace.rs` included from `mace-ebpf/src/proto/mod.rs`.

### 2.2 Core Rust dependencies (`mace-ebpf`)

- **eBPF / loader:** `aya`, `aya-log` (workspace-pinned git versions).
- **Async runtime:** `tokio` (full feature set in library).
- **Serialization:** `serde`, `serde_yaml`, `serde_json`.
- **Rules / text:** `regex`.
- **HTTP (blocking):** `reqwest` with **rustls** (pinned `rustls-webpki` for advisory hygiene).
- **Logging / tracing:** `log`, `tracing`, `tracing-subscriber`, `tracing-log`.
- **Concurrency / caching:** `arc-swap`, `futures`, **`notify`** (rule file watcher).
- **IDs:** `uuid`.
- **Optional Kubernetes (`feature = "kubernetes"`):** `kube`, `k8s-openapi`, **`moka`** sync cache.
- **Optional observability:** `metrics`, `metrics-exporter-prometheus`, OpenTelemetry crates (`otel` feature bundle in `Cargo.toml`).

### 2.3 eBPF program (`mace-ebpf-ebpf`)

- **`aya-ebpf`**, **`aya-log-ebpf`**: tracepoint programs, maps (`RingBuf`, `LruHashMap`, `PerCpuArray`, `Array`), helpers (`bpf_probe_read_user*`, time, PID/TGID).

### 2.4 FFI and native tooling

- **`cbindgen`**: C header generation (patched list in `mace-ebpf/build.rs`).
- **`libc`**: syscalls and C interop.
- **Go `cgo`**: links `libmace_ebpf` (static release tag `mace_static_release` in release/Docker paths).
- **Python `ctypes`**: `_ffi.py` + `engine.py` helpers.

### 2.5 Build and quality toolchain

- **Rust stable + nightly** (nightly for eBPF `build-std`, `rustfmt` with unstable options in `rustfmt.toml`, Miri).
- **`bpf-linker`** (pinned in CI, e.g. `0.10.3`).
- **`clang` / `llvm` / `libelf` / kernel headers**: verifier and BTF-aware builds.
- **`cargo clippy`**, **`cargo fmt`** (nightly check).
- **`criterion`**: `arena_benchmark`, `rule_engine_bench`.
- **Miri + AddressSanitizer**: `run_memory_checks.sh` (FFI + arena focused; ASAN on `mace-ebpf` lib tests).

### 2.6 CI/CD and release tooling

- **GitHub Actions:** `ci.yml`, `core-compat.yml`, `ffi-assurance.yml`, `release.yml`, `docker-publish.yml`.
- **Docker Buildx** + **QEMU** (multi-arch per `docker-publish.yml`).
- **Cosign** (keyless image signing in docker workflow).
- **nFPM** for Debian packages in `release.yml`.
- **`Swatinem/rust-cache`**, **`dtolnay/rust-toolchain`**, **`actions/setup-go`**, **`actions/setup-python`**.

### 2.7 Notable absent or “BYO” items

- **Formal code coverage gates** (e.g. `tarpaulin` / `llvm-cov` thresholds) are **not** enforced in CI today—see audit notes in `docs/6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md`.

---

## 3. Phases and progress report

This section maps the repository to **your** phased roadmap (phrasing adjusted for clarity). Percentages are **engineering judgments** based on implemented features vs stated intent and known gaps (they are **not** mathematical completeness proofs).

| Phase (your model) | Theme | Approx. completion | Notes / gaps |
|--------------------|-------|----------------------|--------------|
| **Phase 1** | In-kernel memory observation, bounded maps, CO-RE-oriented workflow | **~92%** | eBPF: ringbuf, LRU pending maps, allowlist, rate limit, kernel stat counters. CO-RE: prebuilt ELF + BTF-driven load; **hosted CI** runs verifier/attach smoke on multiple Ubuntu images; **Vagrant** matrix remains optional operator tooling. **Gap:** “O(1)” is validated by **microbenches and map sizing**, not formal complexity proofs; some tracepoints are **optional** on restrictive kernels. |
| **Phase 2** | Context enrichment (Kubernetes, cache) | **~85%** | Trait `ContextEnricher`, `NoopEnricher`, optional **`KubernetesEnricher`** behind feature flag; **moka** cache when enabled. Additional enrichment: cmdline tracker, passwd username, cgroup id carried on events. **Gap:** K8s path requires cluster credentials and feature build; enrichment quality depends on cgroup mapping correctness in target environments. |
| **Phase 3** | Behavioral engine (state, shadow, replay) | **~90%** | `StateTracker` + YAML `stateful` / **sequence** rules (including noise tolerance options), **frequency windows**, bitmask / env / comm / memfd matchers, **`EnforcementMode::Shadow`**, per-rule eval timing metrics + warn threshold, **`mace-replay`**. **Gap:** Sequence and frequency semantics should stay documented per edge case (clock skew, multi-worker ordering); replay uses JSON `MemoryEvent`—not a byte-identical ringbuf dump format. |
| **Phase 4** | FFI and interoperability | **~88%** | Stable C ABI, Go and Python bindings, JSON event callback channel (Go), protobuf types for alert delivery, static linking story for Go. Audit logging for engine APIs, health JSON, staged rule count FFI. **Gap:** FFI path is **not strict zero-copy** (events are copied into Rust-owned structures—by design for safety); protobuf is used for **alert** shapes, not as the primary ringbuf wire format. |

**Cross-phase documentation:** `docs/6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md` uses a **different internal step numbering** (1.x–4.x blueprint). Treat **this** `PROJECT_STATE.md` as the **narrative** source of truth; use the audit file for **traceability** and **gap analysis** against the older blueprint.

---

## 4. Current rule engine capabilities

### 4.1 Loading and staging

- **Sources:** `RuleSet::from_file`, `from_yaml_str`, **`from_dir`** (non-recursive `*.yaml` / `*.yml`, sorted merge).
- **Hot reload:** `RuleWatcher` (`notify`) reloads from configured path when using file-based pipeline config.
- **Staged count:** After successful parse, **`engine_stage`** records rule count for **O(1)** FFI read (`mace_engine_staged_rule_count`) without re-parsing YAML.

### 4.2 Schema (high level)

Rules are **`serde_yaml`**-deserialized into **`Rule`** (`mace-ebpf/src/rules/mod.rs`) with:

- **Identity / metadata:** `id`, `name`, `severity`, `description`, optional **`tags`**, **`mitre_tactics`**, **`mitre_techniques`**, **`references`**.
- **Enforcement:** **`enforcement_mode`**: `Enforce` (alerts) vs **`Shadow`** (evaluate-only; surfaced in standardized events / shadow metadata).
- **Conditions:** syscall and return semantics, address/length/fd thresholds, **`flags_mask_all` / `flags_mask_none`**, optional **`frequency_window`** + **`syscall_failures_only`**, **`target_process_pattern`**, **`env_contains`**, **`memfd_name_pattern`**, and related structured fields; regexes compiled at load time where applicable.
- **Stateful behavior:** optional **`stateful`** transitions and **`sequence`** blocks (with options for tolerating unmapped intermediate syscalls—**noise** tolerance).
- **Suppressions:** separate list with validation (cannot combine certain frequency-only fields).

Validation runs at load time (`validate_rule`, `validate_conditions_structured`, etc.).

### 4.3 Evaluation model

- **`RuleSet::evaluate`** / **`evaluate_with_suppressions_profiled`** (`mace-ebpf/src/rules/loader.rs`): given an **`EnrichedEvent`** and optional **`ProcessState`**, returns matches for **enforce** vs **shadow**, suppression hits, and **per-rule** evaluation durations (nanoseconds) for metrics.
- **Pipeline** (`mace-ebpf/src/pipeline/mod.rs`): applies suppressions, splits shadow vs enforce paths, records **`mace_rule_eval_ns`** histogram (per `rule_id`), logs slow rules above **`MACE_RULE_EVAL_WARN_NS`** (default 50µs).
- **Complexity:** Rules are evaluated in userspace over a **finite ruleset**; benchmarks target **hot-path latency** (see Criterion). Worst-case cost grows with **rule count** and **condition cost** (regex, `/proc` reads for env/comm matchers)—**not** a constant-time guarantee for arbitrary YAML.

### 4.4 Alerts and structured output

- **`Alert`** / **`StandardizedEvent`** (`mace-ebpf/src/alert.rs`): JSON-friendly structures with suppression info, shadow match lists, **`RuleMatchMetadata`**, and propagation of MITRE/threat fields to downstream consumers.

### 4.5 Offline replay

- **`mace-replay replay`**: loads JSON array or wrapper object of **`MemoryEvent`**, builds **`StateTracker`**, evaluates **`RuleSet`**—useful for CI fixtures and operator sandboxing without BPF.

---

## 5. CI/CD and deployment

### 5.1 GitHub Actions workflows (summary)

| Workflow | Role |
|----------|------|
| **`ci.yml`** | **lint-and-audit** (nightly `fmt`, clippy, `cargo audit`), **ffi-bindings-test** (Rust debug lib + Go tests with **`-race`** for `mace-ebpf/pkg/mace` and `clients/go` + Python pytest), **build-and-test** matrix on **ubuntu-22.04** / **ubuntu-24.04** (workspace build, prometheus integration test, **Criterion gate**, `cargo test --workspace -- --include-ignored` with sudo for BPF tests). |
| **`core-compat.yml`** | Mandatory **eBPF smoke** on **ubuntu-22.04**, **ubuntu-24.04**, **ubuntu-latest**: release build, `verifier_load_test` + `tracepoint_attach_test` with `sudo` and `--ignored`; logs `uname -a` per job. |
| **`ffi-assurance.yml`** | **`run_memory_checks.sh`**: Miri on selected modules + ASAN lib tests. |
| **`release.yml`** | On tag **`v*`**: release build, static **`mace-agent`**, nFPM `.deb`, tarball with `libmace_ebpf.so` / `.a` / `mace.h`, GitHub Release upload. |
| **`docker-publish.yml`** | Build/push multi-arch image to `ghcr.io` (see workflow for naming), Cosign sign. |

### 5.2 Performance gates

- **`scripts/ci/criterion_gate.py`**: Parses `cargo bench` text output; enforces **absolute ceilings** on key medians (configurable via env vars).
- When **`MACE_CRITERION_BASELINE_FILE`** is set (as in CI), also enforces **relative regression** vs committed medians in **`scripts/ci/criterion_baseline.json`** (default **+5%** via `MACE_CRITERION_REGRESSION_MAX`).

### 5.3 Docker image

- **Stage 1:** `rust:bookworm` — installs nightly+stable, `bpf-linker`, builds **`cargo build --release -p mace-ebpf`**, copies built BPF object to `/out/bpf`.
- **Stage 2:** `golang:1.21-bookworm` — **`go build -tags mace_static_release`** for **`mace-agent`** into `/out`.
- **Stage 3:** `gcr.io/distroless/cc-debian12:nonroot` — ships agent + `/etc/mace` config + BPF artifact under `/opt/mace/bpf`. **Note:** distroless non-root cannot load BPF; **privileged** runs are documented for real sensor use.

### 5.4 Packaging

- **`packaging/nfpm.yaml`**, maintainer scripts, **`mace.service`** (ExecStart uses **`mace-agent run`**).
- **Makefile** targets: `rust-build`, `build-agent`, `pack-deb`, `build-replay`, etc.

### 5.5 Testing coverage (conceptual)

- **Unit / integration:** extensive `#[cfg(test)]` across rules, pipeline, FFI, state, proto, observability.
- **Kernel tests:** ignored by default except when CI passes `--include-ignored` / dedicated workflows; **Cursor Cloud / Firecracker** environments may lack full BPF tracepoint support—treat failures there as **environment** issues, not necessarily code defects.
- **VM matrix (`scripts/vm/`):** optional deeper kernel coverage for operators.

---

## 6. Next steps and technical debt

Prioritized themes (short):

1. **Coverage and evidence:** Add an automated **coverage report** (and optional threshold) for `mace-ebpf` core modules; today coverage % is not a merge gate.
2. **FFI semantics documentation:** Clearly distinguish **“safe copy-in/copy-out”** from **zero-copy** in public docs if external stakeholders still use Phase-4 zero-copy language.
3. **Execve argv depth:** eBPF captures **`argv[0]` only** (verifier instruction budget tradeoff, documented in `mace-ebpf-common`); full cmdline relies on userspace enrichment—ensure policies account for that.
4. **Criterion variance:** Concurrent bench groups (e.g. SPSC throughput) can show high variance on shared CI runners; gates intentionally focus on **stable single-thread medians**; revisit if stricter SPSC regression detection is required.
5. **Kubernetes operational hardening:** RBAC, timeout behavior, and cache staleness policies for `KubernetesEnricher` in large clusters.
6. **Matrix ownership:** Keep **`ubuntu-latest`** kernel drift in mind for `core-compat`; document how often baselines should be refreshed.
7. **Debt register:** Continue to use `docs/6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md` for **line-by-line** blueprint gap tracking; keep **this file** updated when major subsystems change.

---

## Document maintenance

When you merge materially new behavior (new syscalls, maps, FFI, CI gates, or rule schema fields), update:

- This **`docs/PROJECT_STATE.md`** (architecture + phases + rule section), and
- The relevant user-facing doc under `docs/` (installation, configuration, rules).

**Owners:** repository maintainers; **consumers:** humans and automated agents needing repository-wide context.

# Aegis-eBPF — Phases 1–4 Blueprint Audit Report

**Document type:** Technical audit and traceability matrix  
**Scope:** Repository state after Phase 4 (pre–Phase 5 pause)  
**Method:** Static review of `tests/`, `src/`, `benches/`, Go/Python bindings, VM scripts, and automation scripts against the original 5-phase blueprint (Phases 1–4 only).

---

## Executive Summary

The codebase implements a **credible, layered validation strategy** for a Rust eBPF SDK with userspace FFI, Go/Python bindings, optional observability, and VM-based kernel matrix tooling. **Most blueprint intent is reflected in concrete artifacts** (unit tests, Miri/ASAN automation, Criterion benches, ignored-but-real eBPF integration tests, Vagrant matrix, LRU stress shell suite, Go GC/protobuf tests, syscall stress and overhead benchmarks).

However, several blueprint **success criteria were stated in absolute or quantitative terms** that the repository **does not strictly prove** in automation today:

| Area | Blueprint claim | Audit finding |
|------|-----------------|---------------|
| **1.1 Coverage** | “>90% coverage for core logic” | No `tarpaulin` / `llvm-cov` configuration or checked-in coverage reports; coverage **not measured or enforced** in CI. |
| **1.2 UB** | “Zero UB” | Miri + ASAN target **selected** surfaces (`ffi`, `arena`, `--lib`); strong signal, not a **whole-program** UB proof. |
| **1.3 O(1)** | Formal constant-time under load | Criterion benches exercise hot paths and concurrent SPSC load; **throughput and latency stats**, not asymptotic proofs. |
| **2.2 Matrix** | CO-RE verification across kernels | **Vagrant + prebuilt ELF** is the right architecture; matrix is **opt-in** (host + provider), guest kernels are **approximate** by box choice unless pinned. |
| **2.3 LRU** | LRU map verification | **`scripts/vm/suites/step-2.3-toctou-lru.sh`** uses heuristics (`MemAvailable`, optional `bpftool`, dmesg grep); **does not assert per-entry eviction semantics** at the BPF API level. |
| **3.1 Zero-copy** | Zero-copy boundary tests | FFI path **copies** `Event` into Rust (`TryPush` / C struct); **not zero-copy** in the strict sense; stress tests validate **safety**, not zero-copy. |
| **4.2 Throughput** | “100,000+ events/sec” | **User-space** arena / JIT-storm path can exceed this (e.g. **~3.2M events/s** reported in Phase 4.1 work); **not** asserted as a hard CI threshold; ring-buffer **saturation** is tested in stress semantics, not a single canonical “events/sec” gate in Rust CI. |
| **4.3 Latency** | “Overhead < 1000 ns per syscall” | **Not** the default gate: **`ebpf_overhead_bench.rs`** uses **multiplicative slowdown** vs baseline (default ≤ **3×**) because debug builds and eight tracepoints make sub-µs absolute deltas **unrealistic**; optional `AEGIS_MPROTECT_OVERHEAD_NS_MAX` for strict absolute checks (typically with **`cargo test --release`**). |

**Bottom line:** The project is **engineering-complete** for Phases 1–4 in the sense of **breadth** (tests and tooling exist for nearly every step). Gaps are mainly **evidence rigor** (coverage numbers, absolute latency, strict zero-copy, LRU formalism) and **CI enforcement** (ignored eBPF tests, Vagrant off by default).

---

## Detailed Mapping: Blueprint → Repository

### Phase 1: Foundation & Memory Safety

#### Step 1.1 — Comprehensive unit testing (>90% core coverage)

| Artifact | Role |
|----------|------|
| `aegis-ebpf-common/src/lib.rs` | Unit tests: `MemorySyscall`, `EventType`, `KernelMemoryEvent::from_bytes`, `MemoryEvent::from_bytes`, golden-byte helpers. |
| `aegis-ebpf/src/lib.rs` | Tests for `parse_os_release_field`, `btfhub_arch`. |
| `aegis-ebpf/src/**/*.rs` (multiple `#[cfg(test)]` modules) | Domain tests: `ffi/` (arena, alert channel, handle, types, jit_storm), `state/`, `rules/`, `pipeline/`, `alert`, `enrichment`, `proto`, `observability/metrics`, etc. |
| `aegis-ebpf/tests/observability_integration.rs` | Prometheus scrape integration (`--features prometheus`). |

**Gap:** No workspace-level **coverage threshold** (90%) or report artifact; “>90%” is **not verifiable** from the repo alone.

---

#### Step 1.2 — Memory leak & pointer safety (Miri, ASAN)

| Artifact | Role |
|----------|------|
| `run_memory_checks.sh` | Automates nightly **Miri** on `ffi` + `arena` tests and **ASAN** (`-Z sanitizer=address`) on `aegis-ebpf --lib`. |
| `.cargo/linux-test-runner.sh` + `.cargo/config.toml` | Conditional runner: `sudo` vs Miri runner to avoid conflicts. |
| `aegis-ebpf/build.rs` | Skips/adapts eBPF build under Miri/ASAN to avoid incompatible build paths. |
| `aegis-ebpf/src/ffi/arena.rs` | `UnsafeCell` in ring buffer slots to satisfy Miri Stacked Borrows for concurrent tests. |

**Strength:** Practical automation for high-risk FFI/arena code.  
**Gap:** “Zero UB” for the **entire** crate/workspace is **not** claimed by Miri scope; eBPF object code and all `unsafe` blocks are not uniformly under Miri.

---

#### Step 1.3 — O(1) data structure mocking & benchmarking

| Artifact | Role |
|----------|------|
| `aegis-ebpf/benches/arena_benchmark.rs` | Criterion: `try_push` / `try_pop` (non-full, full, non-empty, empty) and **concurrent** SPSC `10_000` round-trips (`spsc_scope_10k_roundtrip`). |
| `aegis-ebpf/Cargo.toml` | `[[bench]] name = "arena_benchmark"` + `criterion` dev-dependency. |

**Proof style:** Microbenchmark **throughput** and stable hot-path timing; industry-standard substitute for formal Big-O proofs.  
**Gap:** No automated regression bound on ns/op in CI; O(1) is **interpretive**, not mathematically certified.

---

### Phase 2: In-Kernel Integration & Matrix

#### Step 2.1 — Local integration (load & tracepoints)

| Artifact | Role |
|----------|------|
| `aegis-ebpf/tests/verifier_load_test.rs` | Load prebuilt object; verifier log; ensure expected tracepoint programs exist (`#[ignore]`). |
| `aegis-ebpf/tests/tracepoint_attach_test.rs` | Attach tracepoints, trigger `mprotect`, read `EVENTS` ring buffer (`#[ignore]`). |
| `aegis-ebpf/tests/common/mod.rs` | Root check, memlock rlimit, resolve newest `aegis-ebpf` ELF under `target/` or `AEGIS_EBPF_OBJECT`. |
| `aegis-ebpf-loader/` | Minimal loader + **`--daemon`** for long-running attach scenarios. |
| `aegis-ebpf-ebpf/src/main.rs` | Explicit `#[tracepoint(category = "syscalls", name = "...")]` per syscall. |

**Gap:** Tests are **`#[ignore]`** by design (Firecracker / restricted BPF); **default `cargo test` does not execute** kernel proof on typical CI.

---

#### Step 2.2 — Kernel compatibility matrix (CO-RE)

| Artifact | Role |
|----------|------|
| `Vagrantfile` | Matrix VMs (`k510`, `k515`, `k61`, `k66`) with documented kernel *intent*. |
| `scripts/vm/prepare-artifact.sh` | Host build + copy **prebuilt** `aegis-ebpf` + `aegis-ebpf-loader` into `scripts/vm/artifacts/`. |
| `scripts/vm/run-test.sh`, `scripts/vm/run-matrix.sh`, `scripts/vm/provision-*.sh` | Provision and run tests in guests. |
| `scripts/vm/README-kernel-matrix.md` | Operator documentation. |

**Strength:** Correct pattern for **one ELF, many kernels** (CO-RE style workflow).  
**Gaps:** Not part of **default** CI; kernel versions depend on **box image revisions** unless explicitly pinned in provisioning; no single Rust test named “CO-RE” that asserts BTF relocations—validation is **load + run** in VM.

---

#### Step 2.3 — TOCTOU & orphan eviction (LRU)

| Artifact | Role |
|----------|------|
| `scripts/vm/suites/step-2.3-toctou-lru.sh` | Daemon loader + many short-lived children + `MemAvailable` / optional `bpftool map` / dmesg heuristics. |
| `aegis-ebpf-ebpf/src/main.rs` | `pending_syscalls`: `LruHashMap`, ring buffer reserve failure logging. |

**Strength:** Stresses realistic adversarial fork/mmap churn with BPF attached.  
**Gaps:** Pass/fail is **heuristic**; `bpftool` optional by default; **no direct test** that a specific insert evicted a specific key; **not** run in plain `cargo test`.

---

### Phase 3: FFI Boundary & Interoperability

#### Step 3.1 — “Zero-copy” boundary tests (Go/C hammering FFI)

| Artifact | Role |
|----------|------|
| `aegis-ebpf/pkg/aegis/arena_handle.go`, `alert_handle.go`, `sensor.go` | cgo wrappers, mutex + finalizers. |
| `aegis-ebpf/pkg/aegis/arena_gc_test.go` | `TestCGOBoundaryAndGCStress` (10k arena cycles + `TryPush`), `TestAlertChannelHandleGCStress`. |
| `aegis-ebpf/python/aegis/*.py`, `python/tests/test_bindings.py` | ctypes lifecycle, push/pop, GC stress (`test_gc_del_stress_*`). |

**Gap vs blueprint wording:** Bindings **marshal** structs across the boundary; this is **not** a zero-copy shared-memory API. Success is better described as **“no UAF/double-free under aggressive client + GC”** than zero-copy.

---

#### Step 3.2 — Garbage collection conflict tests

| Artifact | Role |
|----------|------|
| `aegis-ebpf/pkg/aegis/arena_gc_test.go` | Go `runtime.GC()` interleaved with FFI. |
| `aegis-ebpf/pkg/aegis/throughput_stress_test.go` | Concurrent drain goroutine + Rust-side storm (contention). |
| `aegis-ebpf/python/tests/test_bindings.py` | GC stress for `Arena` / `AlertChannel`. |
| `aegis-ebpf/python/aegis/arena.py`, `alert.py` | Defensive `close` / `__del__` patterns. |

**Assessment:** **Well covered** for Go and Python; C client tests are not a first-class duplicate (Rust is the primary “C” ABI).

---

#### Step 3.3 — Protobuf serialization integrity

| Artifact | Role |
|----------|------|
| `aegis-ebpf/pkg/aegis/alert_integrity_test.go` | `FeedTestAlert` from Rust FFI → `TryRecvNonBlocking` → `proto.Unmarshal` → field-level asserts. |
| `aegis-ebpf/src/ffi/alert_channel.rs` | `inject_test_proto` / `aegis_alert_channel_feed_test_alert` (test hook + safety docs). |
| `aegis-ebpf/include/aegis.h` | Generated declarations (via `build.rs`). |

**Gap:** **Python** bindings tests cover lifecycle and basic recv; **no** parallel “maximal alert” protobuf integrity test in `python/tests/` comparable to Go.

---

### Phase 4: Chaos, Performance & Stress

#### Step 4.1 — JIT storm survival (kernel rate limiting)

| Artifact | Role |
|----------|------|
| `aegis-ebpf/tests/ebpf_syscall_stress_test.rs` | Concurrent `mprotect` storm + ring buffer drain; documents **100 ms TGID rate limit** in eBPF; logs implied drop % vs successful syscalls. |
| `aegis-ebpf-ebpf/src/main.rs` | `RATE_LIMIT_INTERVAL_NS`, `RATE_LIMIT_*` maps, conditional emit on `PROT_EXEC`. |

**Assessment:** **Aligned** with “survival” and rate-limit semantics; does not assert equality of syscall count vs events (correct given program logic).

---

#### Step 4.2 — High-throughput stress (100k+ events/s, ring buffer)

| Artifact | Role |
|----------|------|
| `aegis-ebpf/src/ffi/jit_storm.rs` | `aegis_simulate_jit_storm` — scoped producer/consumer into `EventArena`. |
| `aegis-ebpf/pkg/aegis/arena_handle.go` | `SimulateJitStorm` / `SimulateJitStormDuration` (deadlock fix: release lock before FFI). |
| `aegis-ebpf/pkg/aegis/throughput_stress_test.go` | 100k storm + optional concurrent Go `TryPop`; logs events/s. |
| `aegis-ebpf/python/aegis/_ffi.py` | ctypes bindings for storm API. |

**Reported numbers (from project narrative / local runs, not CI-enforced):** User-space path on the order of **millions of events/sec** (e.g. **~3.2M events/s**) for the Rust-driven JIT storm through the arena; **kernel** ring buffer throughput is a **different** dimension (rate-limited + smaller map).

**Gaps:** No checked-in **minimum throughput assertion** at 100k+ in Rust CI; kernel ring buffer saturation is **indirectly** explored via stress + drop logging, not a single canonical “saturate safely” metric in `cargo test`.

---

#### Step 4.3 — Latency & CPU overhead (< 1000 ns / syscall)

| Artifact | Role |
|----------|------|
| `aegis-ebpf/tests/ebpf_overhead_bench.rs` | Baseline vs attached: **100k** RWX→RW cycles; logs avg ns/syscall, overhead, slowdown factor; default gate **`ebpf/baseline ≤ 3.0`** (`AEGIS_MPROTECT_SLOWDOWN_MAX`); optional **`AEGIS_MPROTECT_OVERHEAD_NS_MAX`** for absolute ns/syscall when set. |

**Gap vs original blueprint text:** Default is **not** “< 1000 ns extra per syscall”; that proved **infeasible** on typical debug + multi-tracepoint setups. The implementation **documents** `--release` and optional absolute caps for strict environments.

---

## Proof Summary (What the Repo Actually Demonstrates)

| Criterion (as implemented) | Evidence |
|-----------------------------|----------|
| Unit tests for shared types & parsing | `aegis-ebpf-common` tests; `MemoryEvent::from_bytes` mapping tests. |
| Miri + ASAN for FFI/arena | `run_memory_checks.sh`; targeted `cargo +nightly miri test` modules. |
| Arena hot-path benchmarks | `cargo bench -p aegis-ebpf --bench arena_benchmark` (Criterion groups `single_thread_push_pop`, `concurrent_push_pop`). |
| eBPF load / attach / ringbuf | Ignored integration tests + loader daemon for suites. |
| Multi-kernel smoke | Vagrant matrix + artifact copy workflow. |
| LRU / TOCTOU stress | `step-2.3-toctou-lru.sh` under VM harness. |
| Go FFI + GC + protobuf | `arena_gc_test.go`, `throughput_stress_test.go`, `alert_integrity_test.go`. |
| Python FFI + GC | `test_bindings.py`. |
| Kernel storm + rate limit story | `ebpf_syscall_stress_test.rs` + eBPF source comments/constants. |
| Overhead profiling | `ebpf_overhead_bench.rs` (baseline comparison + slowdown ratio). |

**Numerical claims:** Throughput and per-host overhead numbers **vary by machine and build profile**. The repo encodes **structure and gates** (slowdown ratio, stress loops, logging); **publish** environment-specific numbers in CI logs or release notes rather than treating a single constant as repo truth.

---

## Gaps & Technical Debt Before Phase 5

1. **Coverage measurement:** Add `llvm-cov` or `tarpaulin` in CI and a **documented threshold** (or explicitly drop the “>90%” requirement from the blueprint language).
2. **eBPF tests in CI:** Decide between **privileged runners**, **scheduled** ignored-test jobs, or **VM-only** verification so Phase 2/4 kernel claims are **continuously** exercised, not only on developer laptops.
3. **LRU test rigor:** Optionally require `bpftool` in strict mode, snapshot map stats over time, and/or add a **small** BPF-side statistic map for dropped/reserve failures (if acceptable for prod object).
4. **Blueprint wording vs design:** Replace “zero-copy” with **“copy-safe FFI”** or document any future **true** zero-copy ring (shared mmap) separately.
5. **Python protobuf parity:** Add a **Rust-fed maximal alert** test mirroring Go’s `TestProtobufAlertIntegrity`.
6. **Phase 4.2 vs 4.3 separation:** Keep **userspace throughput** (JIT storm) and **kernel syscall overhead** (overhead bench) clearly labeled in docs to avoid comparing incompatible numbers.
7. **Overhead benchmark:** Treat **slowdown ratio** as the portable default; use **`--release` + `AEGIS_MPROTECT_OVERHEAD_NS_MAX`** only where sub-µs absolute SLAs are real for your deployment kernel and attachment set.

---

## Appendix — Primary File Index

| Path | Phase / step |
|------|----------------|
| `aegis-ebpf-common/src/lib.rs` | 1.1 |
| `run_memory_checks.sh`, `.cargo/linux-test-runner.sh` | 1.2 |
| `aegis-ebpf/benches/arena_benchmark.rs` | 1.3 |
| `aegis-ebpf/tests/verifier_load_test.rs`, `tracepoint_attach_test.rs` | 2.1 |
| `Vagrantfile`, `scripts/vm/*` | 2.2, 2.3 |
| `aegis-ebpf/pkg/aegis/*.go`, `*_test.go` | 3.x |
| `aegis-ebpf/python/` | 3.x |
| `aegis-ebpf/tests/ebpf_syscall_stress_test.rs` | 4.1 |
| `aegis-ebpf/src/ffi/jit_storm.rs`, `pkg/aegis/throughput_stress_test.go` | 4.2 |
| `aegis-ebpf/tests/ebpf_overhead_bench.rs` | 4.3 |

---

*End of report.*

# Testing and continuous integration

This page summarizes how **GitHub Actions** validates the repository and how **releases** and **container images** are produced.

## Workflow: `CI` (`.github/workflows/ci.yml`)

**Triggers:** `push` and `pull_request` to **`main`**.

**Highlights:**

| Job / area | What it does |
|------------|----------------|
| **lint-and-audit** | `cargo fmt` (nightly), `clippy`, `cargo audit`; installs **clang/llvm/libelf**, **bpf-linker**, kernel headers so `mace-ebpf/build.rs` can run under clippy. |
| **build-and-test** | Matrix of **Ubuntu** versions; `cargo build`, `cargo test` (workspace), optional **`--include-ignored`** integration tests on a subset configuration. |
| **ffi-bindings-test** | Builds **`mace-ebpf`** (debug), runs **Go** tests with **`-race`** under **`mace-ebpf/pkg/mace`** and **`clients/go`** (both **`CGO_ENABLED=1`**) plus **Python** tests under `mace-ebpf/python`. |

**Design notes (from workflow comments):**

- Do **not** use `cargo ... --all-features` on the **entire** workspace: that can enable **`mace-ebpf-ebpf/ebpf-bin`**, which builds the `no_std` BPF binary for the host and hits duplicate `panic_impl` with `std`.
- Many **eBPF integration tests** are `#[ignore]` by default because hosted runners may lack full BPF support; privileged or self-hosted jobs can run them explicitly.

## Workflow: `Release` (`.github/workflows/release.yml`)

**Triggers:** push of tags matching **`v*`** (for example `v1.2.3`).

**Steps (summary):**

1. Install **nightly** (with `rust-src`) + **stable**, **bpf-linker**, and eBPF build dependencies.
2. **`cargo build --release`** for the full workspace.
3. Build **`mace-agent`** with **`CGO_ENABLED=1`** and **`-tags mace_static_release`**, output **`build/mace-agent`**.
4. Run **nFPM** with **`VERSION_TAG`** derived from the tag (`v1.2.3` → `1.2.3`) to produce **`mace-agent_<version>_amd64.deb`**.
5. Stage **`libmace_ebpf.so`**, **`libmace_ebpf.a`**, **`mace.h`** into **`mace-ebpf-linux-amd64.tar.gz`**.
6. **`softprops/action-gh-release`** uploads the **`.deb`** and **`.tar.gz`** to the GitHub Release for that tag.

## Workflow: `Core compat` (`.github/workflows/core-compat.yml`)

**Triggers:** same as CI (`main` / PRs).

**Purpose:** **Mandatory** eBPF smoke on **ubuntu-22.04**, **ubuntu-24.04**, and **ubuntu-latest** runners (distinct kernel lines over time, including newer 6.x images on **latest**): release build, then **`verifier_load_test`** and **`tracepoint_attach_test`** with **`sudo`** and **`--ignored`**. This catches CO-RE / verifier regressions on real GitHub-hosted kernels without relying on the optional Vagrant matrix alone.

> GitHub no longer provides **`ubuntu-20.04`** reliably; the matrix uses **22.04+** (5.15+ style kernels) for cross-generation coverage. **`ubuntu-latest`** tracks the default Linux image as GitHub updates it (often aligned with **24.04** today, but not guaranteed).

## Workflow: `FFI assurance` (`.github/workflows/ffi-assurance.yml`)

**Triggers:** `main` / PRs.

Runs **`./run_memory_checks.sh`**: **Miri** on `ffi` + `arena` modules and **AddressSanitizer** on `cargo test -p mace-ebpf --lib` for the `x86_64-unknown-linux-gnu` target.

## Criterion regression gate (in `CI` job)

After building with the **prometheus** feature, **`scripts/ci/criterion_gate.py`** parses **`cargo bench`** output for **`arena_benchmark`** and **`rule_engine_bench`** and fails if median times exceed configurable **absolute ceilings** (defaults include slack over typical CI medians for 256-rule evaluation, arena `try_push`, and state tracker updates).

The workflow also sets **`MACE_CRITERION_BASELINE_FILE`** to **`scripts/ci/criterion_baseline.json`**, which stores committed **baseline medians in nanoseconds**. The gate then requires each median to stay within **`MACE_CRITERION_REGRESSION_MAX`** percent above that baseline (default **5**), in addition to the absolute ceilings. Update the JSON when a deliberate performance change lands, after validating medians on a representative runner.

## Workflow: `Docker` (`.github/workflows/docker-publish.yml`)

**Triggers:** `push` to **`main`** and tags **`v*`**.

**Behavior:**

- **QEMU** + **Docker Buildx** for **`linux/amd64`** and **`linux/arm64`**.
- Builds the multi-stage **`Dockerfile`** (Rust release → Go static agent → distroless runtime).
- Pushes to **`ghcr.io/<lowercase_github_owner>/mace-ebpf`** with tags **`latest`** (main only) and the **git tag** for `v*` pushes.
- **Cosign** (keyless) signs the pushed image **digest**.

## Local verification (short)

```bash
cargo check
cargo test -p mace-ebpf --lib
( cd clients/go && CGO_ENABLED=1 go test -race -v ./... )
```

For packaging:

```bash
VERSION_TAG=0.1.0 make pack-deb
```

## Related documentation

- [Linux .deb installation](../2-installation/linux-deb.md)
- [Quickstart (container)](../1-getting-started/quickstart.md)
- [Phase 1–4 audit report](../6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md)

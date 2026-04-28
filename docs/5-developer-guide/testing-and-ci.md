# Testing and continuous integration

This page summarizes how **GitHub Actions** validates the repository and how **releases** and **container images** are produced.

## Workflow: `CI` (`.github/workflows/ci.yml`)

**Triggers:** `push` and `pull_request` to **`main`**.

**Highlights:**

| Job / area | What it does |
|------------|----------------|
| **lint-and-audit** | `cargo fmt` (nightly), `clippy`, `cargo audit`; installs **clang/llvm/libelf**, **bpf-linker**, kernel headers so `aegis-ebpf/build.rs` can run under clippy. |
| **build-and-test** | Matrix of **Ubuntu** versions; `cargo build`, `cargo test` (workspace), optional **`--include-ignored`** integration tests on a subset configuration. |
| **ffi-bindings-test** | Builds **`aegis-ebpf`** (debug), runs **Go** tests under `aegis-ebpf/pkg/aegis` and **Python** tests under `aegis-ebpf/python` with **`CGO_ENABLED=1`**. |

**Design notes (from workflow comments):**

- Do **not** use `cargo ... --all-features` on the **entire** workspace: that can enable **`aegis-ebpf-ebpf/ebpf-bin`**, which builds the `no_std` BPF binary for the host and hits duplicate `panic_impl` with `std`.
- Many **eBPF integration tests** are `#[ignore]` by default because hosted runners may lack full BPF support; privileged or self-hosted jobs can run them explicitly.

## Workflow: `Release` (`.github/workflows/release.yml`)

**Triggers:** push of tags matching **`v*`** (for example `v1.2.3`).

**Steps (summary):**

1. Install **nightly** (with `rust-src`) + **stable**, **bpf-linker**, and eBPF build dependencies.
2. **`cargo build --release`** for the full workspace.
3. Build **`aegis-agent`** with **`CGO_ENABLED=1`** and **`-tags aegis_static_release`**, output **`build/aegis-agent`**.
4. Run **nFPM** with **`VERSION_TAG`** derived from the tag (`v1.2.3` → `1.2.3`) to produce **`aegis-agent_<version>_amd64.deb`**.
5. Stage **`libaegis_ebpf.so`**, **`libaegis_ebpf.a`**, **`aegis.h`** into **`aegis-ebpf-linux-amd64.tar.gz`**.
6. **`softprops/action-gh-release`** uploads the **`.deb`** and **`.tar.gz`** to the GitHub Release for that tag.

## Workflow: `Docker` (`.github/workflows/docker-publish.yml`)

**Triggers:** `push` to **`main`** and tags **`v*`**.

**Behavior:**

- **QEMU** + **Docker Buildx** for **`linux/amd64`** and **`linux/arm64`**.
- Builds the multi-stage **`Dockerfile`** (Rust release → Go static agent → distroless runtime).
- Pushes to **`ghcr.io/<lowercase_github_owner>/aegis-ebpf`** with tags **`latest`** (main only) and the **git tag** for `v*` pushes.
- **Cosign** (keyless) signs the pushed image **digest**.

## Local verification (short)

```bash
cargo check
cargo test -p aegis-ebpf --lib
cd clients/go/aegis && CGO_ENABLED=1 go test -race -v ./...
```

For packaging:

```bash
VERSION_TAG=0.1.0 make pack-deb
```

## Related documentation

- [Linux .deb installation](../2-installation/linux-deb.md)
- [Quickstart (container)](../1-getting-started/quickstart.md)
- [Phase 1–4 audit report](../6-references/audits/PHASE_1_TO_4_AUDIT_REPORT.md)

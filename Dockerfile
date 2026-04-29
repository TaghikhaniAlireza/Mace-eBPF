# =============================================================================
# OCI image: mace-agent (Rust static lib + eBPF baked in) + default config + BPF object copy
# =============================================================================
# Build (from repo root, release Rust + static Go):
#   docker build -f Dockerfile -t mace-ebpf:local .
#
# Run (requires privileged/capabilities for BPF):
#   docker run --rm --privileged mace-ebpf:local
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Rust release build (userspace lib + embedded eBPF via build.rs)
# -----------------------------------------------------------------------------
FROM rust:bookworm AS rust-builder

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
		clang llvm libelf-dev zlib1g-dev pkg-config protobuf-compiler \
		build-essential ca-certificates curl \
	&& rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal --component rust-src \
	&& rustup toolchain install stable --profile minimal \
	&& rustup default stable

RUN cargo install bpf-linker --version 0.10.3 --locked

COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY mace-ebpf-common mace-ebpf-common
COPY mace-ebpf-ebpf mace-ebpf-ebpf
COPY mace-ebpf mace-ebpf
COPY mace-ebpf-loader mace-ebpf-loader

RUN cargo build --release -p mace-ebpf

# CO-RE eBPF object (for inspection / tooling — also embedded in libmace_ebpf.a userspace)
RUN mkdir -p /out/bpf && \
	f=$(find target/release/build -path '*/mace-ebpf-*/out/mace-ebpf' -type f | head -1) && \
	test -n "$f" && cp -v "$f" /out/bpf/mace-ebpf

# -----------------------------------------------------------------------------
# Stage 2: Go agent (CGO + static Rust core)
# -----------------------------------------------------------------------------
FROM golang:1.21-bookworm AS go-builder

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
		clang llvm libelf-dev zlib1g-dev pkg-config build-essential \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /src /src

# Go module + agent (not part of the Rust workspace tree copied above)
COPY clients/go /src/clients/go

WORKDIR /src/clients/go

ENV CGO_ENABLED=1

RUN go build -tags mace_static_release -ldflags="-s -w" -trimpath \
		-o /out/mace-agent ./cmd/mace-agent

# -----------------------------------------------------------------------------
# Stage 3: Minimal runtime (glibc; agent is dynamically linked to libc)
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

# distroless/nonroot cannot load BPF; default image is for *artifact distribution*.
# Quick-start overrides user to root — see docs/1-getting-started/quickstart.md.
COPY --from=go-builder /out/mace-agent /usr/bin/mace-agent
COPY packaging/config.yaml /etc/mace/config.yaml
COPY packaging/rules.yaml /etc/mace/rules.yaml
COPY --from=rust-builder /out/bpf/mace-ebpf /opt/mace/bpf/mace-ebpf

USER root

ENTRYPOINT ["/usr/bin/mace-agent"]
CMD ["--config", "/etc/mace/config.yaml"]

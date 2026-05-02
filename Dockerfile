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
# Requires kernel UAPI headers for bpf_helpers / vmlinux.h during nested bpf build.
# -----------------------------------------------------------------------------
FROM rust:bookworm AS rust-builder

WORKDIR /src

# Debian CDN can occasionally serve wrong-sized objects during mirror sync ("unexpected size");
# retry with a clean lists/cache between attempts (common CI/Docker Buildx mitigation).
RUN printf '%s\n' \
	'Acquire::Retries "6";' \
	'Acquire::http::Timeout "120";' \
	'Acquire::https::Timeout "120";' \
	> /etc/apt/apt.conf.d/80-docker-retry

# Cross GNU linkers for multi-arch Buildx (e.g. arm64 stage building x86_64 Rust artifacts).
# UAPI headers: use Debian's arch packages — never linux-headers-$(uname -r) here (BuildKit can
# inject the *host* kernel version, e.g. 6.17-azure, which does not exist in bookworm).
ARG TARGETARCH
RUN set -eux; \
	hdr="linux-headers-amd64"; \
	if [ "${TARGETARCH}" = "arm64" ]; then hdr="linux-headers-arm64"; fi; \
	success=0; \
	for attempt in 1 2 3 4 5; do \
		apt-get clean || true; \
		rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/partial || true; \
		apt-get update && \
		DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
			clang llvm libelf-dev zlib1g-dev pkg-config protobuf-compiler \
			build-essential ca-certificates curl \
			gcc-x86-64-linux-gnu gcc-aarch64-linux-gnu \
			"${hdr}" && \
		success=1 && break; \
		echo "apt attempt ${attempt} failed; sleeping before retry..." >&2; \
		sleep "$((attempt * 15))"; \
	done; \
	test "${success}" = 1; \
	rm -rf /var/lib/apt/lists/*

ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

RUN rustup toolchain install nightly --profile minimal --component rust-src \
	&& rustup toolchain install stable --profile minimal \
	&& rustup default stable

RUN cargo install bpf-linker --version 0.10.3 --locked

COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY mace-ebpf-common mace-ebpf-common
COPY mace-ebpf-ebpf mace-ebpf-ebpf
COPY mace-ebpf mace-ebpf
COPY mace-ebpf-loader mace-ebpf-loader
COPY mace-replay mace-replay

# Full in-kernel execve argv capture (CI / image kernels accept this; strict hosts use default build).
ENV MACE_EBPF_EXECVE_FULL_ARGV=1
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

RUN printf '%s\n' \
	'Acquire::Retries "6";' \
	'Acquire::http::Timeout "120";' \
	'Acquire::https::Timeout "120";' \
	> /etc/apt/apt.conf.d/80-docker-retry

RUN set -eux; \
	success=0; \
	for attempt in 1 2 3 4 5; do \
		apt-get clean || true; \
		rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/partial || true; \
		apt-get update && \
		DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
			clang llvm libelf-dev zlib1g-dev pkg-config build-essential && \
		success=1 && break; \
		echo "apt attempt ${attempt} failed; sleeping before retry..." >&2; \
		sleep "$((attempt * 15))"; \
	done; \
	test "${success}" = 1; \
	rm -rf /var/lib/apt/lists/*

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
CMD ["run", "--config", "/etc/mace/config.yaml"]

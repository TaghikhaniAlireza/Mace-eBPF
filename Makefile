# Convenience targets from the repository root (see also mace-ebpf/Makefile).
#
# eBPF execve argv policy (see `mace-ebpf/build.rs`): plain `cargo build -p mace-ebpf` defaults to
# **no in-kernel argv reads** so `sys_enter_execve` loads on strict verifiers; rules use `/proc` cmdline.
# Set **`MACE_EBPF_EXECVE_FULL_ARGV=1`** when building for kernels that accept full argv capture.

.PHONY: rust-build rust-build-release rust-build-ebpf-full-argv rust-build-release-ebpf-full-argv rust-build-ebpf-argv0 rust-build-release-ebpf-argv0 rust-build-ebpf-no-user-argv rust-build-release-ebpf-no-user-argv go-test go-test-release clients-go-test build-agent build-agent-ebpf-full-argv build-agent-ebpf-argv0 build-agent-ebpf-no-user-argv build-agent-release build-replay pack-deb fmt clippy

rust-build:
	cargo build -p mace-ebpf

# Full in-kernel execve argv capture (opt-in for capable kernels).
rust-build-ebpf-full-argv:
	MACE_EBPF_EXECVE_FULL_ARGV=1 cargo build -p mace-ebpf

# Minimal execve BPF (argv[0] only): smaller verifier footprint for strict kernels.
rust-build-ebpf-argv0:
	MACE_EBPF_EXECVE_ARGV0_ONLY=1 cargo build -p mace-ebpf

# Execve enter skips all bpf_probe_read_user* argv capture (explicit; same as default build today).
rust-build-ebpf-no-user-argv:
	MACE_EBPF_EXECVE_NO_USER_ARGV=1 cargo build -p mace-ebpf

rust-build-release:
	cargo build --release -p mace-ebpf

rust-build-release-ebpf-full-argv:
	MACE_EBPF_EXECVE_FULL_ARGV=1 cargo build --release -p mace-ebpf

rust-build-release-ebpf-argv0:
	MACE_EBPF_EXECVE_ARGV0_ONLY=1 cargo build --release -p mace-ebpf

rust-build-release-ebpf-no-user-argv:
	MACE_EBPF_EXECVE_NO_USER_ARGV=1 cargo build --release -p mace-ebpf

# Go SDK in-tree (static debug lib); requires CGO + same libc as Rust build.
go-test: rust-build
	cd mace-ebpf/pkg/mace && CGO_ENABLED=1 go test -race -v ./...

go-test-release: rust-build-release
	cd mace-ebpf/pkg/mace && CGO_ENABLED=1 go test -race -v -tags mace_static_release ./...

clients-go-test: rust-build
	cd clients/go/mace && CGO_ENABLED=1 go test -race -v ./...

# Standalone agent (CGO + static Rust lib from debug build).
build-agent: rust-build
	mkdir -p build
	cd clients/go && CGO_ENABLED=1 go build -o ../../build/mace-agent ./cmd/mace-agent

# Agent linked against eBPF built with full kernel argv capture (for capable kernels only).
build-agent-ebpf-full-argv: rust-build-ebpf-full-argv
	mkdir -p build
	cd clients/go && CGO_ENABLED=1 go build -o ../../build/mace-agent ./cmd/mace-agent

# Same as `build-agent` but links against eBPF built with `MACE_EBPF_EXECVE_ARGV0_ONLY=1`.
build-agent-ebpf-argv0: rust-build-ebpf-argv0
	mkdir -p build
	cd clients/go && CGO_ENABLED=1 go build -o ../../build/mace-agent ./cmd/mace-agent

build-agent-ebpf-no-user-argv: rust-build-ebpf-no-user-argv
	mkdir -p build
	cd clients/go && CGO_ENABLED=1 go build -o ../../build/mace-agent ./cmd/mace-agent

build-agent-release: rust-build-release
	mkdir -p build
	cd clients/go && CGO_ENABLED=1 go build -tags mace_static_release -o ../../build/mace-agent ./cmd/mace-agent

build-replay: rust-build
	cargo build -p mace-replay

# Requires nfpm on PATH and VERSION_TAG (e.g. 0.1.0). Example: VERSION_TAG=0.1.0 make pack-deb
pack-deb: build-agent-release
	test -n "$(VERSION_TAG)" || (echo "set VERSION_TAG, e.g. VERSION_TAG=0.1.0" && false)
	VERSION_TAG=$(VERSION_TAG) nfpm package --config packaging/nfpm.yaml --packager deb --target .

fmt:
	cargo +nightly fmt --all --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

# Convenience targets from the repository root (see also aegis-ebpf/Makefile).

.PHONY: rust-build rust-build-release go-test go-test-release clients-go-test fmt clippy

rust-build:
	cargo build -p aegis-ebpf

rust-build-release:
	cargo build --release -p aegis-ebpf

# Go SDK in-tree (static debug lib); requires CGO + same libc as Rust build.
go-test: rust-build
	cd aegis-ebpf/pkg/aegis && CGO_ENABLED=1 go test -race -v ./...

go-test-release: rust-build-release
	cd aegis-ebpf/pkg/aegis && CGO_ENABLED=1 go test -race -v -tags aegis_static_release ./...

clients-go-test: rust-build
	cd clients/go/aegis && CGO_ENABLED=1 go test -race -v ./...

fmt:
	cargo +nightly fmt --all --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

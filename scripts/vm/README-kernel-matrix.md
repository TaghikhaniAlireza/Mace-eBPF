# Kernel compatibility matrix (Vagrant)

This directory supports **Step 2.2**: run one **pre-built** `aegis-ebpf` ELF across several Linux guests (CO-RE / verifier / attach smoke) without recompiling BPF inside each VM.

## Quick start (Linux host)

```bash
./scripts/vm/prepare-artifact.sh
vagrant up k61 --provision
```

Run all definitions sequentially:

```bash
./scripts/vm/run-matrix.sh
```

Artifacts live in `scripts/vm/artifacts/` (`aegis-ebpf`, `aegis-ebpf-loader`). They are **gitignored**.

## Requirements

- [Vagrant](https://www.vagrantup.com/) + a provider (**VirtualBox** by default in `Vagrantfile`).
- Build on **Linux x86_64** so `aegis-ebpf-loader` is a Linux ELF. If your host is macOS, build artifacts in CI or a Linux container, then copy `scripts/vm/artifacts/` into the repo tree before `vagrant up`.

## Kernel versions

Images are chosen to approximate **5.10 / 5.15 / 6.1 / 6.6+** kernel families. Official boxes move forward over time — always confirm with `uname -r` inside each guest. To pin exact `linux-image-*` packages, set `AEGIS_PIN_KERNEL_PACKAGE` and extend `provision-kernel.sh`.

## Step 2.3 extension

`run-test.sh` runs every **executable** `*.sh` in `scripts/vm/suites/` (skipping `*.example`).

- **`suites/step-2.3-toctou-lru.sh`** (committed, executable): starts `aegis-ebpf-loader --daemon`, spawns many short-lived `python3 -c 'mmap...'` children, periodically logs `MemAvailable` and (if `bpftool` is present) `pending_syscalls` entry counts, and fails on large `MemAvailable` drops or suspicious `dmesg` lines.
- **`aegis-ebpf-loader --daemon`**: holds BPF attached until SIGTERM so the suite can run while programs are live.

Tune with env vars documented at the top of `step-2.3-toctou-lru.sh`.

## CI note

Nested virtualization is often disabled on cloud runners; run this matrix on a developer workstation or a self-hosted runner with KVM/VirtualBox enabled.

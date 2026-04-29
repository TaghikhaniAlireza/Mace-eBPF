#!/usr/bin/env bash
# =============================================================================
# Optional kernel pinning (disabled by default)
# =============================================================================
# Debian/Ubuntu images move forward over time; the Vagrantfile picks *families* of distros
# that historically track 5.10 / 5.15 / 6.1 / 6.6+.
#
# To force a specific linux-image package, set before `vagrant provision`:
#   export MACE_PIN_KERNEL_PACKAGE='linux-image-6.6.13-cloud-amd64'
#
# Then implement the install block below (uncomment and adjust for your mirror).
# =============================================================================
set -euo pipefail

echo "[provision-kernel] VM=${MACE_VM_NAME:-unknown} note=${MACE_KERNEL_NOTE:-}"
echo -n "[provision-kernel] running kernel: "
uname -r

if [[ -n "${MACE_PIN_KERNEL_PACKAGE:-}" ]]; then
  echo "[provision-kernel] MACE_PIN_KERNEL_PACKAGE=${MACE_PIN_KERNEL_PACKAGE}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  # Example — adjust for your distro codename / backports:
  # apt-get install -y "$MACE_PIN_KERNEL_PACKAGE"
  echo "[provision-kernel] ERROR: kernel pinning requested but not implemented in this template." >&2
  exit 1
fi

echo "[provision-kernel] skip (no MACE_PIN_KERNEL_PACKAGE)"

# frozen_string_literal: true

# =============================================================================
# Mace-eBPF — Kernel compatibility matrix (CO-RE smoke test)
# =============================================================================
#
# Runs the *same* pre-built BPF object (`mace-ebpf`) + userspace loader on several
# guest kernels without recompiling eBPF inside the VM.
#
# Prerequisites (host):
#   - Vagrant + VirtualBox (or change `vm.provider` below to libvirt / vmware)
#   - `cargo build -p mace-ebpf` and `cargo build --release -p mace-ebpf-loader` on Linux,
#     then `./scripts/vm/prepare-artifact.sh` to copy artifacts into scripts/vm/artifacts/
#
# Usage:
#   ./scripts/vm/prepare-artifact.sh
#   vagrant up k510 --provision          # one VM
#   ./scripts/vm/run-matrix.sh         # all VMs (sequential)
#
# Box choice rationale (approximate kernel families — verify with `uname -r` in each guest):
#   k510  Debian 11 (bullseye)  → 5.10.x LTS track on official images
#   k515  Ubuntu 22.04 (jammy)  → 5.15 / 6.x HWE depending on image revision
#   k61   Debian 12 (bookworm)  → 6.1.x LTS track
#   k66   Ubuntu 24.04 (noble)  → 6.6+ / 6.8+ depending on image revision
#
# To pin *exact* kernel versions, replace `vm.box` / `vm.box_version` per definition or
# add an `apt install linux-image-...` block in scripts/vm/provision-kernel.sh (template included).
# =============================================================================

Vagrant.configure("2") do |config|
  # Default provider: VirtualBox (widely available). Switch to `:libvirt` if you use KVM.
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
    vb.customize ["modifyvm", :id, "--uartmode1", "file", File::NULL]
  end

  # Hash of VM name => { box, human-readable kernel note }
  matrix = {
    "k510" => {
      box: "debian/bullseye64",
      note: "Debian 11 (bullseye) — expect ~5.10 LTS; verify: uname -r",
    },
    "k515" => {
      box: "ubuntu/jammy64",
      note: "Ubuntu 22.04 (jammy) — expect ~5.15 or HWE 6.x; verify: uname -r",
    },
    "k61" => {
      box: "debian/bookworm64",
      note: "Debian 12 (bookworm) — expect ~6.1 LTS; verify: uname -r",
    },
    "k66" => {
      box: "ubuntu/noble64",
      note: "Ubuntu 24.04 (noble) — expect ~6.6+; verify: uname -r",
    },
  }

  matrix.each do |name, meta|
    config.vm.define name, autostart: false do |node|
      node.vm.box = meta[:box]
      node.vm.hostname = "mace-#{name}"

      # Sync the repo so /vagrant/scripts/vm/... is available in the guest.
      # Omit `type:` to use the provider default (VirtualBox shared folders, libvirt 9p, etc.).
      node.vm.synced_folder ".", "/vagrant"

      # Optional: pin exact kernel packages (disabled by default — edit script to enable).
      node.vm.provision "shell", path: "scripts/vm/provision-kernel.sh", env: {
        "MACE_VM_NAME" => name,
        "MACE_KERNEL_NOTE" => meta[:note],
      }

      node.vm.provision "shell", path: "scripts/vm/provision-common.sh", env: {
        "MACE_VM_NAME" => name,
        "MACE_KERNEL_NOTE" => meta[:note],
      }

      # Load + attach eBPF (requires root). Extension hooks for Step 2.3 live in run-test.sh.
      node.vm.provision "shell", path: "scripts/vm/run-test.sh", privileged: true, env: {
        "MACE_VM_NAME" => name,
      }
    end
  end
end

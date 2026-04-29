# Linux installation: Debian package (`.deb`)

The repository ships an **`mace-agent`** Debian package built with **[nFPM](https://github.com/goreleaser/nfpm)**. The package definition lives at **`packaging/nfpm.yaml`**.

The **`.deb`** installs **`mace-agent`**, default **`/etc/mace/config.yaml`** and **`/etc/mace/rules.yaml`**, **`libmace_ebpf.so`** (for Python/dynamic users), and **`mace.service`**. See [Who uses Mace](../1-getting-started/audiences.md) for operator vs developer paths.

## Package contents

| Installed path | Source | Notes |
|----------------|--------|--------|
| `/usr/bin/mace-agent` | `build/mace-agent` | Go binary, CGO-linked against **static** `libmace_ebpf.a` at build time. |
| `/usr/lib/libmace_ebpf.so` | `target/release/libmace_ebpf.so` | Shared library for **Python** / dynamic FFI consumers (the agent binary does not require this at runtime). |
| `/etc/systemd/system/mace.service` | `packaging/mace.service` | systemd unit. |
| `/etc/mace/config.yaml` | `packaging/config.yaml` | **Conffile** — dpkg treats updates carefully. |
| `/etc/mace/rules.yaml` | `packaging/rules.yaml` | Default rules (customize for production). |

Lifecycle scripts (`packaging/postinst.sh`, `prerm.sh`, `postrm.sh`) run **`systemctl daemon-reload`**, **enable/start** on install, **stop** on remove, **disable** after removal.

## Obtaining the `.deb`

1. **GitHub Release** (tag `v*`): workflow **Release** builds `mace-agent_<version>_amd64.deb` (alongside `mace-ebpf-linux-amd64.tar.gz`). Download the `.deb` from the release assets.
2. **Local build** (see [From source](./from-source.md)):

```bash
VERSION_TAG=0.1.0 make pack-deb
```

Requires **nFPM** on `PATH` and a prior **`make build-agent-release`** (the `pack-deb` target runs it).

## Installing

```bash
sudo dpkg -i ./mace-agent_<version>_amd64.deb
sudo apt-get install -f   # if dependencies were missing (usually not needed)
```

The post-install script enables and starts **`mace.service`**.

## systemd service

Unit file excerpt (see `packaging/mace.service` for the canonical copy):

```ini
[Service]
ExecStart=/usr/bin/mace-agent --config /etc/mace/config.yaml
Restart=always
User=root
```

**Root is required** because loading BPF programs and attaching tracepoints need appropriate capabilities.

Useful commands:

```bash
sudo systemctl status mace.service
sudo journalctl -u mace.service -f
sudo systemctl restart mace.service
```

## Configuration after install

Edit **`/etc/mace/config.yaml`** (see [Agent configuration](../4-configuration/agent-config.md)), then:

```bash
sudo systemctl restart mace.service
```

Security events are written to the path in **`logging.path`** (default `/var/log/mace/events.log`), not to journald by default.

## Removal

```bash
sudo apt-get remove mace-agent
```

Pre/post scripts stop and disable the service. Config files installed as **conffiles** may remain on disk until purge, depending on your `dpkg` choices.

## Architecture note

Published packages in CI are currently built for **`amd64`** per `packaging/nfpm.yaml`. Multi-arch `.deb` builds would require additional nfpm/arch matrix work or separate packages per architecture.

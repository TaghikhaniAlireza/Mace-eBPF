# Linux installation: Debian package (`.deb`)

The repository ships an **`aegis-agent`** Debian package built with **[nFPM](https://github.com/goreleaser/nfpm)**. The package definition lives at **`packaging/nfpm.yaml`**.

The **`.deb`** installs **`aegis-agent`**, default **`/etc/aegis/config.yaml`** and **`/etc/aegis/rules.yaml`**, **`libaegis_ebpf.so`** (for Python/dynamic users), and **`aegis.service`**. See [Who uses Aegis](../1-getting-started/audiences.md) for operator vs developer paths.

## Package contents

| Installed path | Source | Notes |
|----------------|--------|--------|
| `/usr/bin/aegis-agent` | `build/aegis-agent` | Go binary, CGO-linked against **static** `libaegis_ebpf.a` at build time. |
| `/usr/lib/libaegis_ebpf.so` | `target/release/libaegis_ebpf.so` | Shared library for **Python** / dynamic FFI consumers (the agent binary does not require this at runtime). |
| `/etc/systemd/system/aegis.service` | `packaging/aegis.service` | systemd unit. |
| `/etc/aegis/config.yaml` | `packaging/config.yaml` | **Conffile** — dpkg treats updates carefully. |
| `/etc/aegis/rules.yaml` | `packaging/rules.yaml` | Default rules (customize for production). |

Lifecycle scripts (`packaging/postinst.sh`, `prerm.sh`, `postrm.sh`) run **`systemctl daemon-reload`**, **enable/start** on install, **stop** on remove, **disable** after removal.

## Obtaining the `.deb`

1. **GitHub Release** (tag `v*`): workflow **Release** builds `aegis-agent_<version>_amd64.deb` (alongside `aegis-ebpf-linux-amd64.tar.gz`). Download the `.deb` from the release assets.
2. **Local build** (see [From source](./from-source.md)):

```bash
VERSION_TAG=0.1.0 make pack-deb
```

Requires **nFPM** on `PATH` and a prior **`make build-agent-release`** (the `pack-deb` target runs it).

## Installing

```bash
sudo dpkg -i ./aegis-agent_<version>_amd64.deb
sudo apt-get install -f   # if dependencies were missing (usually not needed)
```

The post-install script enables and starts **`aegis.service`**.

## systemd service

Unit file excerpt (see `packaging/aegis.service` for the canonical copy):

```ini
[Service]
ExecStart=/usr/bin/aegis-agent --config /etc/aegis/config.yaml
Restart=always
User=root
```

**Root is required** because loading BPF programs and attaching tracepoints need appropriate capabilities.

Useful commands:

```bash
sudo systemctl status aegis.service
sudo journalctl -u aegis.service -f
sudo systemctl restart aegis.service
```

## Configuration after install

Edit **`/etc/aegis/config.yaml`** (see [Agent configuration](../4-configuration/agent-config.md)), then:

```bash
sudo systemctl restart aegis.service
```

Security events are written to the path in **`logging.path`** (default `/var/log/aegis/events.log`), not to journald by default.

## Removal

```bash
sudo apt-get remove aegis-agent
```

Pre/post scripts stop and disable the service. Config files installed as **conffiles** may remain on disk until purge, depending on your `dpkg` choices.

## Architecture note

Published packages in CI are currently built for **`amd64`** per `packaging/nfpm.yaml`. Multi-arch `.deb` builds would require additional nfpm/arch matrix work or separate packages per architecture.

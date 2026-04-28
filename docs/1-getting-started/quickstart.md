# Quick start: container image

Run the pre-built **aegis-agent** from GitHub Container Registry (GHCR) without compiling from source.

## Prerequisites

- **Docker** (or a compatible runtime).
- **Linux** host with BPF/tracepoint support (the agent loads eBPF programs).
- **Privileged** container (or equivalent capabilities such as `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON` depending on your kernel and Docker version).

## One command

GHCR image path (**GitHub owner must be lowercase**):

```bash
docker run --rm -it --privileged \
  ghcr.io/taghikhanialireza/aegis-ebpf:latest
```

The container entrypoint is **`aegis-agent`** with default args **`--config /etc/aegis/config.yaml`**.

## What is inside the image

| Path | Purpose |
|------|---------|
| `/usr/bin/aegis-agent` | Standalone agent (Go + statically linked Rust core). |
| `/etc/aegis/config.yaml` | Logging path + format + rules path. |
| `/etc/aegis/rules.yaml` | Default placeholder rules (customize or mount your own). |
| `/opt/aegis/bpf/aegis-ebpf` | CO-RE eBPF object on disk (the library also embeds a copy at build time). |

## Minimal configuration (optional override)

Mount your own config instead of the baked-in defaults:

```bash
docker run --rm -it --privileged \
  -v "$(pwd)/my-config.yaml:/etc/aegis/config.yaml:ro" \
  -v "$(pwd)/my-rules.yaml:/etc/aegis/rules.yaml:ro" \
  ghcr.io/taghikhanialireza/aegis-ebpf:latest
```

Example `my-config.yaml`:

```yaml
logging:
  path: /var/log/aegis/events.log
  format: json

rules:
  path: /etc/aegis/rules.yaml
```

Security events are written **only** to `logging.path` inside the container filesystem unless you mount a host directory there, for example:

```bash
mkdir -p ./aegis-logs
docker run --rm -it --privileged \
  -v "$(pwd)/aegis-logs:/var/log/aegis" \
  ghcr.io/taghikhanialireza/aegis-ebpf:latest
```

Then inspect events:

```bash
tail -f ./aegis-logs/events.log
```

## Expected output

On **stderr** you should see agent lifecycle lines, for example:

```text
aegis-agent: logging security events to /var/log/aegis/events.log (format=json)
aegis-agent: engine running (rules="/etc/aegis/rules.yaml"); send SIGTERM or SIGINT to stop
```

If the kernel or environment cannot load BPF programs, **`StartPipeline`** fails and the process exits with an error (common on some microVMs or locked-down hosts).

When the engine is running, **`events.log`** receives JSON lines (one per observed syscall after rule evaluation) with fields such as `syscall_name`, `matched_rules`, and `suppressed_by`. See [Events and alerts](../3-concepts/events-and-alerts.md).

## Stop the container

- **Foreground:** press `Ctrl+C` (sends **SIGINT**); the agent stops the pipeline and exits cleanly.
- **Detached:** `docker stop <container_id>` (sends **SIGTERM**).

## Tags

- **`latest`** — built from the **`main`** branch (GitHub Actions workflow **Docker**).
- **`v1.2.3`** etc. — built from matching Git tags; images are **cosign-signed** (keyless). Verify with the [Cosign documentation](https://docs.sigstore.dev/cosign/overview/).

## Image size

The default image uses a small **distroless** runtime (glibc). The image may exceed 50MB because the static agent embeds a large Rust core; further shrinking would require a dedicated musl or split-artifact layout.

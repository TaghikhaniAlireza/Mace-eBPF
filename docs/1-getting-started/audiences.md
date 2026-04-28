# Who uses Aegis, and how

Aegis-eBPF serves three overlapping audiences. Pick the path that matches **what you want to run** and **how much code you write**.

| Audience | Typical goal | Recommended path |
|----------|--------------|-------------------|
| **User / operator** | Run monitoring on a host with minimal setup | [`.deb` + systemd](../2-installation/linux-deb.md) or [Docker / GHCR](./quickstart.md) |
| **Security analyst / researcher** | Observe syscall activity, tune rules, export JSON for SIEM or notebooks | **`aegis-agent`** log file, or **Option B** (Go example) below for interactive stdout |
| **Developer (integrator)** | Embed Aegis in an application | [Go embedded SDK](#go-embedded-sdk-full-pipeline) or [lower-level Go](#go-lower-level-arena--sensor-api); [Python](#python-bindings-arena--alert-channel) for FFI testing |

---

## User / operator: standalone agent on Linux

The supported **production-style** standalone is **`aegis-agent`** (`clients/go/cmd/aegis-agent`): one binary, YAML config, structured events to a log file, **systemd** integration.

1. **Install** the [Debian package](../2-installation/linux-deb.md) *or* build from source (`make build-agent-release`) and install the binary yourself.
2. Edit **`/etc/aegis/config.yaml`** ([configuration reference](../4-configuration/agent-config.md)): set **`logging.path`** (where JSON/text lines go) and **`rules.path`** (YAML file or directory).
3. **Root / capabilities** are required for BPF tracepoints (`aegis.service` runs as root).
4. **Start / enable** the service (`systemctl enable --now aegis.service` after package install).

**Container users:** see [Quickstart (Docker)](./quickstart.md) — `docker run --privileged … ghcr.io/taghikhanialireza/aegis-ebpf:latest` for a pre-built image; mount host paths for config, rules, and logs if needed.

---

## Security analyst / researcher

### Option A — Use the packaged agent (best for log files)

Same as **User / operator** above. Events land in **`logging.path`** as **JSON** (default) or **text** — one line per evaluated observation after the rule engine runs.

**Workflow tips**

- Point **`rules.path`** at a copy of [`tests/simulations/rules.yaml`](https://github.com/TaghikhaniAlireza/Aegis-eBPF/blob/main/tests/simulations/rules.yaml) while learning, then fork into fleet-specific **`rules:`** and **`suppressions:`** (see [Rules engine](../3-concepts/rules-engine.md)).
- Read [Events and alerts](../3-concepts/events-and-alerts.md) to interpret **`matched_rules`** vs **`suppressed_by`**.
- Tune Rust stderr noise with **`AEGIS_LOG_LEVEL`** ([Core logging](../4-configuration/logging.md)); that does **not** filter the agent’s **event log file** — only `[Aegis][LEVEL]` diagnostics on stderr.

### Option B — Run the in-repo Go example (good for interactive demos)

From the repository (after `cargo build -p aegis-ebpf`):

```bash
cd clients/go/examples
sudo env PATH="$PATH" CGO_ENABLED=1 go run .
```

The example resolves rules from **`AEGIS_RULES_FILE`**, then **`/etc/aegis/rules.yaml`**, else **`tests/simulations/rules.yaml`**. It prints classified lines to **stdout** while the engine emits **`[Aegis][*]`** on stderr when enabled.

Use **`AEGIS_RULES_DEMO=1`** for a minimal embedded rule (whoami) without a rules file.

---

## Developer: Go embedded SDK (full pipeline)

Use this when you want **YAML rules + suppressions + eBPF sensor** inside **your own Go process** (same engine as **`aegis-agent`**).

**Module:** `github.com/aegis-ebpf/sdk/clients/go` — import **`github.com/aegis-ebpf/sdk/clients/go/aegis`**.

**Prerequisites**

1. Build the Rust library from the **repository root** (the `aegis` package links **`libaegis_ebpf.a`** by path):
   - Debug: `cargo build -p aegis-ebpf`
   - Release: `cargo build --release -p aegis-ebpf` and compile Go with **`-tags aegis_static_release`** so CGO picks `target/release/libaegis_ebpf.a`.
2. **`CGO_ENABLED=1`** and a C toolchain on **`PATH`**.

**Minimal pattern** (mirror of `clients/go/examples` and `aegis-agent`):

```go
package main

import (
	"fmt"
	"log"

	"github.com/aegis-ebpf/sdk/clients/go/aegis"
)

func main() {
	client, err := aegis.NewClient(4096)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	go func() {
		for ev := range client.Events() {
			// ev is aegis.AegisEvent — send to SIEM, filter, aggregate, etc.
			fmt.Printf("syscall=%s matched=%v suppressed_by=%v\n",
				ev.SyscallName, ev.MatchedRules, ev.SuppressedBy)
		}
	}()

	if err := aegis.InitEngine(); err != nil {
		log.Fatal(err)
	}
	if err := aegis.LoadRulesFile("/etc/aegis/rules.yaml"); err != nil {
		log.Fatal(err)
	}
	if err := aegis.StartPipeline(); err != nil {
		log.Fatal(err)
	}

	// Keep the process alive; on SIGINT/SIGTERM call aegis.StopPipeline() then client.Close().
	// See clients/go/examples/main.go for a complete signal-handling example.
	select {}
}
```

**API surface** (package `aegis`): `NewClient`, `Client.Events`, `Client.Close`, `InitEngine` / `InitEngineWithConfig`, `LoadRules`, `LoadRulesFile`, `StartPipeline`, `StopPipeline`, `SetLogLevel`, `LogLevel*`. See package docs in [`clients/go/aegis/aegis.go`](https://github.com/TaghikhaniAlireza/Aegis-eBPF/blob/main/clients/go/aegis/aegis.go).

**In-tree reference:** [`clients/go/examples/main.go`](https://github.com/TaghikhaniAlireza/Aegis-eBPF/blob/main/clients/go/examples/main.go) (signal handling, rules path resolution, log level from env).

---

## Developer: Go lower-level (Arena + Sensor API)

The module **`github.com/TaghikhaniAlireza/aegis-ebpf/sdk/pkg/aegis`** under **`aegis-ebpf/pkg/aegis/`** exposes **Arena**, **Sensor**, **AlertChannel**, and protobuf alerts — oriented toward **pushing raw memory events** and consuming **alerts** over cgo. It is the right choice when you integrate with **existing** event sources or tests that use the arena FFI, **not** when you only need the **YAML + eBPF** pipeline (use **`clients/go/aegis`** above).

See the [README usage section](https://github.com/TaghikhaniAlireza/Aegis-eBPF/blob/main/README.md#usage-examples) for a minimal Arena example and `go test` invocation.

---

## Developer: Python bindings (Arena + Alert Channel)

Python bindings live under **`aegis-ebpf/python/`**. They use **`ctypes`** against **`libaegis_ebpf.so`** (dynamic library — set **`LD_LIBRARY_PATH`** or install the `.so` where the loader can find it).

**Today’s scope:** the Python package exposes **Arena** (raw memory event push/pop), **AlertChannel**, and related FFI — suitable for **testing the C ABI**, **stress harnesses**, and **education**. It does **not** expose the same **embedded engine + YAML pipeline + `StartPipeline`** workflow as the Go **`clients/go/aegis`** package. For **full syscall monitoring with rules**, run **`aegis-agent`**, the **Go example**, or embed **Go** / **Rust**.

**Quick start**

```bash
# From repository root
cargo build -p aegis-ebpf
export LD_LIBRARY_PATH="$PWD/target/debug:$LD_LIBRARY_PATH"
pip install -e ./aegis-ebpf/python/
python -m pytest ./aegis-ebpf/python/tests/ -v
```

**Minimal usage** (from `aegis-ebpf/python/README.md`):

```python
from aegis import Arena, raw_memory_event

with Arena(16) as arena:
    ev = raw_memory_event(
        timestamp_ns=123456789,
        tgid=1000,
        pid=2000,
        syscall_id=1,
        args=(0x7FFF0000, 64, 0, 0, 0, 0),
        cgroup_id=0,
        comm=b"demo",
    )
    arena.push(ev)
    out = arena.pop()
    print(out.tgid, out.pid, out.args[0])
```

More detail: **`aegis-ebpf/python/README.md`**.

---

## Summary table

| I am… | I want… | Use |
|-------|---------|-----|
| Operator | systemd service + log file | **`aegis-agent`** `.deb` or equivalent install |
| Analyst | JSON lines to `tail` / ELK / Splunk | **`aegis-agent`** `logging.path` + **`rules.path`** |
| Researcher | Quick experiments, repo rules | **Docker** or **`clients/go/examples`** |
| Go developer | Full rules + BPF in my app | **`clients/go/aegis`** + `cargo build` for static lib |
| Go developer | Arena / sensor / protobuf FFI | **`aegis-ebpf/pkg/aegis`** |
| Python developer | ctypes FFI to library | **`aegis-ebpf/python`** (arena / alerts) |

---

## Next documents

- [Architecture](../3-concepts/architecture.md) — how kernel, Rust, FFI, and agent connect  
- [Rules engine](../3-concepts/rules-engine.md) — YAML reference  
- [Installation](../2-installation/from-source.md) — build all artifacts from source  

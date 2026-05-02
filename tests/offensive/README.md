# Offensive simulations (`tests/offensive/`)

Standalone scripts that **safely** reproduce public **GTFOBins**-style patterns so you can validate Mace-eBPF rules without a full red-team harness.

## GTFOBins: `node` + `child_process` → shell

**Script:** `gtfobins_node_shell.sh`  
**Rules:** `rules_node_gtfobins.yaml`  
**Fixture (replay):** `fixtures/node_gtfobins_execve.json`  
**Reference:** [GTFOBins — node](https://gtfobins.org/gtfobins/node/)

### Prerequisites

- `node` on `PATH` (script exits 0 with `SKIP` message if missing).
- **`protoc`** on `PATH` when building `mace-replay` / `mace-ebpf` (prost-build).
- Mace sensor + pipeline running **as root** with rules loaded from this directory (or merge `rules_node_gtfobins.yaml` into your ruleset).

### Verification (exact commands)

From the **repository root**.

**A — Rule match only (no eBPF, no root): `mace-replay`**

```bash
cargo build -p mace-replay
cargo run -p mace-replay -- replay \
  --data tests/offensive/fixtures/node_gtfobins_execve.json \
  --rules tests/offensive/rules_node_gtfobins.yaml
```

Expect stdout to mention matched rule **`OFFENSE_GTFONODE_CHILD_PROCESS_SHELL`**.

**B — Live sensor + `mace-agent` (real execve from Node; requires root for BPF)**

```bash
cargo build -p mace-ebpf
make build-agent
mkdir -p /tmp/mace-offensive-test
cp tests/offensive/rules_node_gtfobins.yaml /tmp/mace-offensive-test/rules.yaml

sudo tee /tmp/mace-offensive-test/config.yaml >/dev/null <<'EOF'
logging:
  path: /tmp/mace-offensive-test/mace.log
  format: json

rules:
  path: /tmp/mace-offensive-test/rules.yaml
EOF

sudo RUST_LOG=info ./build/mace-agent run --config /tmp/mace-offensive-test/config.yaml &
AGENT_PID=$!
sleep 2
bash tests/offensive/gtfobins_node_shell.sh
sleep 2
sudo kill -INT "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

grep -F 'OFFENSE_GTFONODE_CHILD_PROCESS_SHELL' /tmp/mace-offensive-test/mace.log
```

**C — Simulation script alone (no Mace)**

```bash
bash tests/offensive/gtfobins_node_shell.sh
```

Expect **`MACE_OFFENSIVE_GTFONODE_OK`**, or **`SKIP`** if `node` is missing.

### Complexity note

Per-event rule evaluation cost grows with the **number of rules** and **condition cost** (see `docs/PROJECT_STATE.md`). This rules file adds **one** high-signal rule; the pipeline’s hot paths (channels, reorder heap, worker routing) remain **bounded** by fixed capacities — there is no unbounded queue growth per syscall in the steady-state design.

### Cleanup

```bash
rm -rf /tmp/mace-offensive-test
```

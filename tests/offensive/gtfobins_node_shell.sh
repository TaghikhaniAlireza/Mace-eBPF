#!/usr/bin/env bash
# =============================================================================
# Offensive simulation: GTFOBins-style abuse of `node` to invoke a shell helper
# =============================================================================
# Reference: https://gtfobins.org/gtfobins/node/ (Shell / child_process patterns)
#
# This does NOT open an interactive shell by default. It runs a short-lived
# `/bin/sh -c` that exits immediately, then exits Node. Safe for CI/lab hosts
# that have `node` installed.
#
# Usage (from repo root):
#   bash tests/offensive/gtfobins_node_shell.sh
#   # or: chmod +x ... && ./tests/offensive/gtfobins_node_shell.sh
# =============================================================================
set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
	echo "SKIP: node is not installed or not in PATH" >&2
	exit 0
fi

# Same structural pattern as public GTFOBins examples: require('child_process')
# and invoke a shell binary (here via spawnSync + immediate exit).
node -e '
const cp = require("child_process");
const r = cp.spawnSync("/bin/sh", ["-c", "exit 0"], { stdio: "ignore" });
process.exit(r.status === 0 ? 0 : 1);
'

echo "MACE_OFFENSIVE_GTFONODE_OK"

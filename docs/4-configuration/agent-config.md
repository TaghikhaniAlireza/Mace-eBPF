# Agent configuration (`config.yaml` and rules)

The standalone **`mace-agent`** (`clients/go/cmd/mace-agent`) reads a single YAML file passed with **`mace-agent run --config`** / **`--config`** (root command without subcommand also accepts **`--config`** for backward compatibility). Parsing and validation are implemented in **`clients/go/internal/agentconfig/config.go`**.

## Agent `config.yaml` schema

Top-level keys:

### `logging` (required)

| Field | Type | Description |
|-------|------|-------------|
| **`path`** | string | Filesystem path for the **security event log** (agent creates parent directories with `0755` on startup). |
| **`format`** | string | **`json`** or **`text`** (case-insensitive; normalized at load). |

The agent uses **logrus** with **`JSONFormatter`** or **`TextFormatter`** writing **only** security events to this file. Lifecycle messages (for example shutdown) go to **stderr**.

### `audit` (optional, Phase 4.1)

| Field | Type | Description |
|-------|------|-------------|
| **`path`** | string | Absolute path for an **append-only JSON audit log** of engine FFI actions (`load_rules`, `start_pipeline`, hot-reload, `set_log_level`, etc.). The agent sets **`MACE_AUDIT_LOG_PATH`** before **`mace.InitEngine()`** so Rust can append lines. |

### `rules` (required)

| Field | Type | Description |
|-------|------|-------------|
| **`path`** | string | Passed to **`mace.LoadRulesFile`** in the Go SDK — may be a **file** or a **directory** of `.yaml`/`.yml` (same semantics as the Rust rule loader: non-recursive directory merge in sorted path order). |

### CLI

| Command | Purpose |
|---------|---------|
| **`mace-agent run --config /path/config.yaml`** | Run the agent (default when **`--config`** is passed without a subcommand). |
| **`mace-agent status --config /path/config.yaml`** | Print **`mace_engine_health_json`** (pipeline state, rule counts, kernel counters) to stdout. Does **not** start the sensor. **`rule_count`** prefers the in-memory staged count from the last successful **`LoadRules`** / **`LoadRulesFile`** (or hot-reload); **`staged_rule_count`** is always that value; **`mace_engine_staged_rule_count()`** returns it without parsing YAML. |

### Example (matches `packaging/config.yaml`)

```yaml
logging:
  path: /var/log/mace/events.log
  format: json

audit:
  path: /var/log/mace/audit.log

rules:
  path: /etc/mace/rules.yaml
```

## Rules YAML (`rules.yaml`)

Shipped defaults live in **`packaging/rules.yaml`**; production systems should replace them with fleet-specific **detection** and **suppression** content.

The full rule language is documented in [Rules engine](../3-concepts/rules-engine.md). In short:

- Top-level **`rules:`** — detection entries with **`id`**, **`severity`**, **`conditions`**, optional **`stateful`**.
- Top-level **`suppressions:`** — same **`conditions`** vocabulary without **`stateful`**; used to suppress alerts while retaining **`matched_rules`** in exported JSON.

## systemd and `/etc`

The **`.deb`** installs:

- **`/etc/mace/config.yaml`** — conffile; edit and `systemctl restart mace.service`.
- **`/etc/mace/rules.yaml`** — starter rules; replace or point **`rules.path`** at a directory.

## Environment variables (optional)

The **agent** itself does not read `MACE_RULES_FILE` (that is specific to **`clients/go/examples`**). For Rust **core diagnostics** on stderr, see [Core logging](./logging.md) (`MACE_LOG_LEVEL`, `mace_set_log_level`). **`audit.path`** in config sets **`MACE_AUDIT_LOG_PATH`** for append-only audit lines from the Rust FFI layer.

## Related

- [Linux .deb installation](../2-installation/linux-deb.md)
- [Events and alerts](../3-concepts/events-and-alerts.md)

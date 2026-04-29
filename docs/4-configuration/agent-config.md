# Agent configuration (`config.yaml` and rules)

The standalone **`mace-agent`** (`clients/go/cmd/mace-agent`) reads a single YAML file passed with **`--config`** / **`-c`**. Parsing and validation are implemented in **`clients/go/internal/agentconfig/config.go`**.

## Agent `config.yaml` schema

Top-level keys:

### `logging` (required)

| Field | Type | Description |
|-------|------|-------------|
| **`path`** | string | Filesystem path for the **security event log** (agent creates parent directories with `0755` on startup). |
| **`format`** | string | **`json`** or **`text`** (case-insensitive; normalized at load). |

The agent uses **logrus** with **`JSONFormatter`** or **`TextFormatter`** writing **only** security events to this file. Lifecycle messages (for example shutdown) go to **stderr**.

### `rules` (required)

| Field | Type | Description |
|-------|------|-------------|
| **`path`** | string | Passed to **`mace.LoadRulesFile`** in the Go SDK — may be a **file** or a **directory** of `.yaml`/`.yml` (same semantics as the Rust rule loader: non-recursive directory merge in sorted path order). |

### Example (matches `packaging/config.yaml`)

```yaml
logging:
  path: /var/log/mace/events.log
  format: json

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

The **agent** itself does not read `MACE_RULES_FILE` (that is specific to **`clients/go/examples`**). For Rust **core diagnostics** on stderr, see [Core logging](./logging.md) (`MACE_LOG_LEVEL`, `mace_set_log_level`).

## Related

- [Linux .deb installation](../2-installation/linux-deb.md)
- [Events and alerts](../3-concepts/events-and-alerts.md)

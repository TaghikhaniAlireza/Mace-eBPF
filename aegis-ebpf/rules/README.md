# Aegis Rule Files

Rule files in this directory are YAML documents with a top-level `rules` array.

Each rule supports:

- `id`, `name`, `severity`, `description`
- `conditions.syscall`
- `conditions.flags_contains`
- `conditions.flags_excludes`
- `conditions.min_size`
- `conditions.cgroup_pattern`

Example:

```yaml
rules:
  - id: "MEM-001"
    name: "W^X Transition Detected"
    severity: "high"
    description: "Process attempted to make writable memory executable"
    conditions:
      syscall: "mprotect"
      flags_contains: ["PROT_EXEC", "PROT_WRITE"]
```

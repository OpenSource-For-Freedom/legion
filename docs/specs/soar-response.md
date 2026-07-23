# SOAR response

**Status: Advisory by design.** `crates/legion-core/src/soar.rs`, `quarantine.rs`

Response actions are allowlisted, human-approved, privilege-gated and fully
audited. **ARES proposes; the operator approves; Legion executes.** Nothing
destructive happens on its own.

## Actions

| Action | Applies to | Effect |
|---|---|---|
| **Quarantine** | Any alert naming a file | Moves it to a locked, owner-only store with a SHA-256 and a `meta.json`. Reversible. |
| **Restore** | A quarantined file | Returns it to its original path. |
| **Get fix** | A vulnerable package | Generates the exact upgrade command. Copied to clipboard, never run. |
| **Remove** | A confirmed-malicious package | Same, but framed as removal — there is no good version to upgrade to. |

Every action writes a `respond.*` audit row. Quarantine is path-confined: the
target must be flagged by an alert or sit under the scan root, else it is
refused with a 403 and the refusal is audited.

## Verify

```bash
cargo test -p legion-core --lib soar
curl -s localhost:3000/api/respond/quarantine
```

## Limits

- **Only regular files are quarantined.** A directory target (DPRK-1 can flag a
  staging *directory*) is refused with a 400 explaining why, rather than a bare
  500.
- Package "quarantine" in `quarantine.rs` writes a database row and generates
  commands; it does not uninstall anything. That is deliberate.
- No IP blocking, no process kill. Both are roadmap, not present.

## Fixed here, worth knowing

The pending-actions list gated quarantine on `source === 'YARA'`, but **the
backend never had that restriction** — it accepts any path an alert flagged. So
a DPRK malware artifact, which carries a `file_path` but no `package_name`,
matched neither branch and **vanished from the SOAR panel entirely**. The most
serious finding Legion can raise was the one with no response attached to it.

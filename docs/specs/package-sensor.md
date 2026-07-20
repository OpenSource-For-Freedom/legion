# Package attack sensor

**Status: Real, alert-only by design.** `crates/legion-core/src/pkg_sensor.rs`

A continuous watcher that raises a desktop pop-up and a Critical alert the
moment a confirmed-malicious dependency appears.

## What it does

- Polls every **60 seconds** from the web binary (the only recurring package
  timer in the workspace).
- Gates each tick on a **lockfile fingerprint** (path, size, mtime) so an
  unchanged tree costs a cheap walk instead of a full rescan plus a `pip list`
  subprocess.
- Fires only on `confirmed_malicious` hits. Vulnerable-but-legitimate SDKs,
  inventory notes and every heuristic are excluded.
- Deduplicates by `ecosystem|name`, **seeded from the database at startup**, so a
  restart does not re-pop the operator's whole backlog.
- Best-effort `notify-send` on Linux; the dashboard alert is raised regardless.

## Explicitly does not quarantine

This is a deliberate product decision, not an unfinished feature. A false
quarantine can break a working system, so the destructive response stays a
separate, later opt-in. `quarantine.rs` states the same: removal commands are
generated for the operator to review and run, never executed.

## Verify

```bash
cargo test -p legion-core --lib pkg_sensor
```

Plant a lockfile containing `openai-node` under the scan root; it fires once,
Critical, and does not fire again on the next tick or after a restart.

## Limits

- Desktop pop-up is Linux-only. Windows and macOS get the dashboard alert.
- Scans the configured scan root, while `/api/scan` walks the whole system, so
  the two can legitimately disagree.
- No suppression list. An operator who deliberately installed a flagged package
  cannot silence it permanently.

# Alerts and reconciliation

**Status: Real.** `crates/legion-core/src/alerts.rs`, `db.rs`

## Alert kinds

`CveMatch`, `IpBlacklist`, `SuspiciousPackage`, `SystemAnomaly`, `YaraMatch`,
`BaselineDrift`, `DprkIndicator`.

Every queued alert carries an **artifact** — a file path, package name, IP, CVE
list or event title. An alert with nothing to act on is noise, which is why
framework rule hits are kept out of the queue entirely (see
[ares-agent](ares-agent.md)).

## Reconciliation

Each scan recomputes the complete current finding set for a detector, and
reconciling **replaces that detector's unacked alerts** with the fresh set. A
finding that no longer holds — peer gone, file no longer matching, IP off the
blocklist, DPRK artifact cleaned up — simply disappears instead of lingering.

Scopes: `Yara`, `Heuristic`, `Drift`, `AbuseIntel`, `PackageCve`, `PackageVuln`,
`Dprk`. Scopes match on the alert `source` via SQL `LIKE`, so the AbuseIntel
pattern is deliberately a prefix — rows written under an older source string
still reconcile rather than being orphaned.

## Verify

```bash
cargo test -p legion-core --test audit_remediation
cargo test -p legion-core --test integration
```

## Limits

- `save_alerts` deletes only **unacked** duplicates before inserting, so a
  re-detected alert the operator already acked reappears as a fresh unacked row.
  The package sensor works around this with database-backed dedup.
- Alert hygiene prunes legacy and aged-out rows at startup; there is no operator
  control over the retention window.

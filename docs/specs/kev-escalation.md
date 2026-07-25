# KEV escalation

**Status: Real.** `threat_intel::kev_cross_ref`, `AlertEngine::apply_kev`

Raises any finding whose CVE appears in CISA's Known Exploited Vulnerabilities
catalog. The distinction is between "someone could exploit this" and "this is
being exploited right now".

## What it does

- Joins OSV findings against the KEV catalog on CVE id.
- Scopes the match to the package the KEV entry was matched against, so a shared
  CVE cannot bleed onto an unrelated alert.
- Sets the alert to **Critical**, prefixes the detail with `ACTIVELY EXPLOITED`,
  the catalog date, and a ransomware note where applicable.
- Fetches the catalog during a scan if the table is empty, rather than silently
  doing nothing.

It is a pure join. It invents no severity of its own and cannot produce a false
positive the underlying OSV finding did not already have.

## Verify

```bash
cargo test -p legion-core --test audit_remediation kev_
```

## Limits

- **Depends entirely on hydration.** No CVE ids means no join. See
  [osv-correlation](osv-correlation.md).
- KEV is fetched over TLS with an optional operator-pinned SHA-256
  (`LEGION_KEV_SHA256`), fail-closed when set and transport-trusted otherwise.

## Fixed here, worth knowing

This was written, correct, and had **zero callers** for its entire life. The
catalog was fetched, stored, and never joined to anything — so "a dependency of
yours is under active attack" was known to Legion and never said. Wiring it up
then exposed the deeper problem: it joins on CVE ids that hydration was not
providing, so even once called it could not fire.

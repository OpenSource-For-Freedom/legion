# OSV correlation

**Status: Real.** `crates/legion-core/src/threat_intel.rs`

Turns an installed package list into vulnerability findings with real
severities, CVE identifiers and fix versions.

## What it does

1. Deduplicate scanned packages by `(name, ecosystem)`.
2. `POST /v1/querybatch` in chunks of 500 to get advisory IDs.
3. **Hydrate** each unique ID via `GET /v1/vulns/{id}`, 8 concurrent, capped at
   600 per scan.
4. Extract severity (from the CVSS vector), CVE and GHSA aliases, the fixed
   version, and the summary.
5. Alert only on packages that are actually in scope; the full set is kept for
   the threat panel.

An advisory whose ID starts with `MAL-` is a **confirmed malicious-code report**,
not a vulnerability in a legitimate package. Those become Critical
`SuspiciousPackage` alerts telling the operator to remove, not upgrade.

## Verify

```bash
cargo test -p legion-core --test audit_remediation osv_
```

Against the live API, a package set that previously produced 153 findings with
nothing populated now returns severity, CVE ids, fix version and summary on
**all** of them.

## Limits

- **Hydration costs a request per advisory.** A large dependency tree makes a
  scan noticeably slower than the old instant-but-empty behaviour. That is the
  price of having severities at all.
- **No rate-limit handling.** A 429 chunk is logged and dropped; there is no
  backoff or `Retry-After` support.
- **Severity comes from substring-matching the CVSS vector**, not from parsing
  the score. It is coarse.
- **Failures are silent by design.** A network error yields an empty result,
  which is indistinguishable from "no vulnerabilities" to the caller.

## Fixed here, worth knowing

`querybatch` returns **`{id, modified}` and nothing else**. The code read
`severity`, `aliases`, `summary` and `affected` straight off that response, so
every finding arrived with `severity: null`, `cve_ids: []` and the summary
"No description" — which is why a console showed 153 findings uniformly rated
Medium. It also silently disabled KEV escalation entirely, because that joins on
CVE id and the CVE id only exists on the per-advisory document.

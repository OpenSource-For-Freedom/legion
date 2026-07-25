# Threat feeds

**Status: Real.** `crates/legion-core/src/feeds.rs`, `threat_intel.rs`

| Feed | Source | Auth |
|---|---|---|
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | None |
| Feodo Tracker botnet C2 | `feodotracker.abuse.ch/downloads/ipblocklist.csv` | None |
| Cyber events | `defcondatabase.com/data/events_cyber_attack.json` | None |

No API keys anywhere in the product. Bodies are size-capped and streamed
(`http.rs`), KEV supports an operator-pinned SHA-256 (`LEGION_KEV_SHA256`,
fail-closed when set).

Feodo entries carry the **botnet family** (Emotet, QakBot, Dridex) and the C2
status. An active connection to a listed C2 is Critical on its own merits.

## Verify

```bash
cargo test -p legion-core --lib feeds
curl -X POST localhost:3000/api/feeds/refresh
```

## Limits

- Feeds degrade silently: a fetch failure is a logged warning and a count of
  zero, which is indistinguishable from "nothing to report".
- The cyber-events feed could not be reached from one sandboxed environment;
  worth confirming on an unrestricted host.

## Fixed here, worth knowing

Two honesty defects, both user-visible:

1. **The alert text invented data.** It rendered `country: unknown, abuse score:
   100/100`. Feodo publishes *neither*. The score was synthesized from C2 status
   (online → 100, offline → 90) and the country was a hardcoded placeholder —
   and severity was then derived from the invented number. Meanwhile the parser
   was reading past and discarding the malware family, the most useful field the
   feed actually publishes.
2. **The wrong provider was named** in seven places across the dashboard, CLI
   and the alert `source` field — including a documented URL
   (`defcondatabase.com/data/abuseipdb.json`) that nothing ever fetched. Legion
   uses abuse.ch's Feodo Tracker. Internal names (`fetch_abuseips`,
   `AbuseIpPayload`, the `abuse_ips` table) survive as legacy.

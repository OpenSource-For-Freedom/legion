# Malicious package detection

**Status: Real.** `crates/legion-core/src/ai_detector.rs`

A curated list of packages that are known-malicious or known-unofficial, matched
exactly by `(name, ecosystem)`.

## What it does

34 entries, each carrying a severity, what it impersonates, a description, a
MITRE ATLAS technique, and a **`confirmed_malicious`** flag:

| Tier | Count | Meaning | May page? |
|---|---|---|---|
| `confirmed_malicious: true` | 23 | Known-malicious: key exfiltration, keyloggers, backdoors. | Yes |
| `confirmed_malicious: false` | 11 | Unofficial or unaudited wrapper. A policy judgement. | **No** |

Also detects vulnerable versions of legitimate AI SDKs (15 entries), inventories
known SDKs (48), and matches running agent-framework processes (16 signatures).

## Verify

```bash
cargo test -p legion-core --lib ai_detector
cargo test -p legion-core --lib pkg_sensor
```

## Limits

- **Exact match only.** No edit distance, no homoglyph detection, no
  keyboard-adjacency. The entries *are* typosquats, but detection is string
  equality — a novel squat is invisible until someone edits this file.
- **The list is compiled in.** It changes only when a new binary ships. There is
  no feed. [osv-correlation](osv-correlation.md)'s `MAL-` ingestion is the live
  complement and is where new coverage actually comes from.
- **Nothing for crates.io.** 29 pypi, 5 npm, 0 cargo.
- `VulnerableAiSdk` treats an unknown version as vulnerable, which is a
  deliberate dashboard-noise tradeoff and is excluded from anything that pages.

## Fixed here, worth knowing

The list blended two very different claims. 11 of 34 entries were `High`
severity *opinions* — "unofficial wrapper, unaudited" — and several name real,
legitimate open-source projects (`chatgpt-wrapper`, `claude-api`, `langchain-js`,
`huggingface`). Every match, including those, told the operator to "REMOVE
IMMEDIATELY and audit secrets". The sensor gated on the *kind*, so it would have
paged Critical on legitimately installed software. Severity was not a usable
discriminator — it grades impact-if-real, not confidence-that-it-is-real — so
the flag is explicit.

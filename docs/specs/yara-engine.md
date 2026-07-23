# YARA engine

**Status: Partial — real engine, throughput is the limit.** `crates/legion-core/src/yara.rs`

A hand-written, pure-Rust YARA subset. No `yara` crate, no libyara, no C
dependency: lexer, parser, hex patterns with wildcards and jumps, and condition
evaluation, in about 1,800 lines.

## What it does

- Loads rules per OS from `rules-feed/`, cached under `data_dir()/rules/<os>/`,
  falling back to rules compiled into the binary when offline.
- Unsupported constructs are skipped with a warning rather than failing the
  whole rule set.
- Scans are bounded by file size (16 MB default), file count, and a **wall-clock
  budget** (`max_scan_seconds`, default 90s, `0` disables).
- Reports how the scan ended — `Complete`, `FileLimit` or `TimeLimit` — and
  surfaces partial coverage to the operator instead of letting a truncated scan
  look clean.

## Verify

```bash
cargo test -p legion-core --lib yara
```

20 tests cover rule parsing, hex wildcards, condition evaluation and the budget.

## Limits

**Throughput is roughly 1.5 MB/s on real source content.** That is the headline
limitation and it is not subtle: a whole-system scan raises the file cap to
200,000, which is why a scan could run past ten minutes before the time budget
was added.

Profiling attributes the cost evenly — the three slowest rules are only ~19% of
the total — so there is no pathological rule to fix. The remaining work is
**multi-pattern matching**: scanning the buffer once for all patterns instead of
once per pattern. That is a matcher rewrite touching `nocase`, `fullword`, hex
wildcards and exact match counts, and getting it subtly wrong in a security tool
is worse than it being slow. It has deliberately not been rushed.

A first-byte reject was added, which roughly halved the cost, but the structure
is still O(patterns x bytes).

Scanning also excludes package-manager metadata (`/var/backups`,
`/var/lib/dpkg`, `/var/lib/apt`). A `dpkg.status` backup is a catalogue of
software *descriptions*, so malware-keyword rules matched the prose and reported
the Debian package database as a Critical reverse-shell finding — five separate
rules on one file.

Also: `rule_sha256` is empty in the shipped config, so fetched rules take the
transport-trusted path. The pinning machinery works; nothing is pinned.

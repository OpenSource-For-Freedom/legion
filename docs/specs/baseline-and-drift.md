# Baseline and drift

**Status: Real.** `crates/legion-core/src/baseline.rs`, `heuristics.rs`

Captures what the host looked like on first run, then reports what changed.

## What it does

On first launch, snapshots process names, remote IPs, installed packages and
YARA rule hits. Every later scan diffs against that snapshot and emits `Drift`
entries for new processes, new public peers and newly installed packages.

`heuristics.rs` scores provenance (a binary running from an unusual location),
threat-intel peers, and process-count spikes.

On the very first run the reference *is* the just-captured snapshot, so the
"new public peer" rule self-suppresses rather than flagging the whole machine.

## Verify

```bash
cargo test -p legion-core --lib heuristics
curl -s localhost:3000/api/baseline    # or the Show Baseline action
```

## Limits

- **Package drift is name-only.** A version bump, or a swapped `resolved` URL —
  the dependency-confusion shape — produces no drift at all.
- The baseline is captured once and not re-based automatically; there is no
  "accept current state as the new normal" control in the UI.

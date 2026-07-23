# Resource budget

**Status: Real.** Legion is a background monitor, not the workload.

A security tool that starves the machine gets uninstalled. These limits are
deliberate and measured.

## Limits

| Resource | Limit | Why |
|---|---|---|
| **VRAM** | Reserves the greater of 768 MB or **20% of the card**; declines to offload if the model will not fit in what is left | Full offload measured 2918 MB of a 4096 MB card — 71% — held for the server's whole life |
| **CPU** | Model server capped at **half the cores**, run at **`nice 10`** | It otherwise took 760% CPU on a 16-core host and made the desktop stutter |
| **Scan time** | YARA bounded to **90 seconds** (`max_scan_seconds`, `0` disables) | A whole-system scan raises the file cap to 200,000 and ran past ten minutes |
| **Sensor tick** | 60s, gated on a lockfile fingerprint | An unchanged tree costs a cheap walk, not a rescan plus a `pip list` subprocess |
| **Model pull** | 8 concurrent hydration requests, 600 advisories per scan | Polite to a free public API |
| **Tree sweeps** | 20,000 file cap, 2 MB per-file cap | Bounds the worst case |

## Verify

```bash
ps -o ni=,cmd= -C llama-server          # nice 10, --threads N
nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader
cargo test -p legion-ares --lib citizenship
```

## Limits

- The model server **holds its VRAM between hunts** rather than releasing when
  idle. Known, unfixed.
- A truncated YARA scan reports partial coverage but does not resume where it
  stopped; the next scan starts over.

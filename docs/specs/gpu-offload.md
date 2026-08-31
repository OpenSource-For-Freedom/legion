# GPU offload

**Status: Real, measured.** `legion-ares/src/llama.rs` — `plan_offload`

Decides where inference runs, sized to the actual machine.

## Measured, not assumed

On a Quadro T2000 (4 GB) with an Intel UHD iGPU, 16 cores, and a realistic
4,490-token hunt prompt:

| Config | Prompt | Generate |
|---|---|---|
| CPU only | 446 tok/s | 4.0 tok/s |
| **Intel iGPU** | **28 tok/s** | 6.4 tok/s |
| Quadro, full offload | **835 tok/s** | **59.0 tok/s** |
| Quadro, half offload | 582 tok/s | 5.9 tok/s |

## Three rules that follow from those numbers

1. **Integrated GPUs are never used.** The iGPU is *16x worse than the CPU it
   shares memory with*. It also reports shared system RAM as free — advertising
   42 GB against the discrete card's 4 GB — so any largest-free-memory heuristic
   picks exactly the wrong device.
2. **The model is offloaded whole or not at all.** A half offload measured 5.9
   tok/s against 4.0 on CPU. Partial offload buys nothing and risks an
   allocation failure mid-load.
3. **Context is sized to what remains** after the weights and the reserve, then
   clamped. On the test machine that lands at ctx 13727 rather than the
   requested 16384.

## Which build gets staged

Linux **and Windows** both use the **Vulkan** build: llama.cpp publishes no
Linux CUDA release, but Vulkan reaches the same NVIDIA/AMD/Intel hardware
through the driver ICD.

Windows was left on the CPU build for the whole time Linux ran Vulkan. Nothing
caught it, because a CPU build is not broken, only slow: on the same 4,490-token
hunt prompt the CPU build does 16.8 tok/s of prompt processing against Vulkan's
271.3, so that prompt spends 267 seconds being read before a single token comes
back, and chat times out on a database with enough context to be worth
summarising. Identical hardware, an order of magnitude apart, decided by nothing
but which arm of `asset_for_host` a host landed on.

A CPU build is the fallback, and now exists on both platforms. It is chosen by
**running** the staged binary (`--list-devices`, which must exit cleanly), not by
guessing at the host's drivers: a missing Vulkan loader passes both the SHA-256
check and the extractor, so a host without one used to stage a server that could
never start and then degrade every hunt to `engine-only` with nothing in the log
to say why. Windows fails process creation outright on a missing `vulkan-1.dll`;
Linux spawns and then dies in the dynamic linker, so the probe checks the exit
status rather than just whether the process started.

The two builds stage into separate variant-keyed directories
(`runtime/llama-<build>-vulkan`, `runtime/llama-<build>-cpu`), because
`llama-server` links against sibling `ggml`/`llama` objects and extracting one
over the other leaves a tree with some libraries from each.

An operator-supplied `llama-server` on `PATH` still wins over both, and is never
probed, replaced or removed.

## Verify

```bash
cargo test -p legion-ares --lib offload
cargo test -p legion-ares --lib runtime_fallback
ps -o cmd= -C llama-server | grep -o -- '--device [^ ]*'
```

Tests cover: no GPU, integrated-only, a card too small to fit the model, a large
card, context trimming, that every supported platform gets a GPU-capable
primary, that a GPU primary always has a CPU fallback pinned as strongly as the
primary, that the two stage into different directories, and both failure shapes
of the runnability probe.

## Limits

- Device selection matches the GPU name from `nvidia-smi` against the Vulkan
  device list; an AMD or Intel discrete card falls back to "first
  non-integrated".
- **The fallback is only reachable through a failed probe.** A host whose Vulkan
  loader is present but broken enough to satisfy `--list-devices` and then fail
  under load keeps the Vulkan build.
- The probe costs one extra `llama-server` launch on the install path.
- Neither Windows Vulkan asset nor the fallback path has been exercised on real
  Windows GPU hardware yet; the pins are verified against the upstream release
  digests and the selection logic is unit-tested, but the end-to-end run is not.
- No CUDA, ROCm or SYCL build is staged on either platform, though llama.cpp
  publishes them. An operator who wants one installs it on `PATH`.

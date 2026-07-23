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

Linux uses the **Vulkan** build: llama.cpp publishes no Linux CUDA release, but
Vulkan reaches the same NVIDIA/AMD hardware through the driver ICD. A CPU build
is the fallback for hosts without a Vulkan loader.

## Verify

```bash
cargo test -p legion-ares --lib offload
ps -o cmd= -C llama-server | grep -o -- '--device [^ ]*'
```

Tests cover: no GPU, integrated-only, a card too small to fit the model, a large
card, and context trimming.

## Limits

- Device selection matches the GPU name from `nvidia-smi` against the Vulkan
  device list; an AMD or Intel discrete card falls back to "first
  non-integrated".
- Windows still pins the CPU build.

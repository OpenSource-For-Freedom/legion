# Legion Dev â€” a local, self-hosted coding model

Two halves that ship one model:

1. **`legion_dev/` â€” the training harness.** **Execution-verified** offline
   self-distillation that builds the `legion_dev` coding model and publishes it to
   HuggingFace ([`tburns-actual/legion_dev`](https://huggingface.co/tburns-actual/legion_dev)).
   The local coder teacher proposes solutions to real coding tasks; a sandboxed
   runner keeps **only the solutions that actually pass the tasks' `pytest`
   specs**, then QLoRA-SFTs on those, builds the Ollama model, and gates on
   **pass@1 by execution**. Same machinery shape as the `ares-training` harness
   next door, but the reward is *working code*, not a text heuristic.
2. **The dashboard is a separate repo** â€” `F:\dev\legiondev-studio` (Legion Dev
   Studio): a local coding-agent web app that pulls this model from HuggingFace
   into Ollama and lets it write code into / build / debug your real IDE projects.

```
 you â”€â”€â–¶ dashboard (localhost) â”€â”€â–¶ FastAPI â”€â”€â–¶ agent loop â”€â”€â–¶ legion_dev model (Ollama, loopback)
                                                     â”‚
                                                     â””â”€â–¶ tools: read / write / list / shell / search
```

## Why execution verification (and an honest ceiling)

A locally fine-tuned 1.5Bâ€“7B coder **will not match a frontier model** â€” that's a
ceiling of the base model. On an 8 GB GPU, 7B is the practical training ceiling,
and a realistic great outcome is *a fast, private, offline junior/autocomplete-
grade helper*.

What makes it as good as it *can* be â€” and avoids the degeneration that plagues
naive distillation â€” is the **execution gate**:

- The teacher (a local coder model, $0, offline) samples many solutions per task.
- The sandboxed runner ([executor.py](legion/training/legion-dev/legion_dev/executor.py))
  runs the task's real `pytest` tests and **keeps only the passing ones**. Quality
  comes from the test gate, not from a fancy teacher.
- The verified **reference** solution is the fallback, so every task still yields a
  *correct, working* gold example â€” never a trivial stub (stubs are what degenerate
  a model).
- Eval is **pass@1 by execution** on a held-out task set â€” a real capability
  metric that can't be gamed by well-formatted nonsense.

**Free "bigger teacher" trick:** the teacher only runs at dataset-build time
(inference). Point `--teacher-model` at a larger local model
(`qwen2.5-coder:14b` / `:32b`, spilling to CPU/RAM on 8 GB) to raise the *data*
ceiling above your 7B student â€” still $0, still offline.

## Layout

```
legion_dev/          the training pipeline (importable package)
  contracts.py       output contract, tiers, gate threshold, synthesis prompt
  tasks.py           the executable task catalog (starter + pytest spec + verified reference)
  executor.py        THE gate â€” sandboxed pytest runner (pass/fail by execution)
  extract.py         pull the solution file out of a model answer
  synth.py           teacher + execution-verified rejection sampling (reference fallback)
  score.py           grade a candidate by running the tests (critic == eval)
  critic.py          accept/critique wrapper
  dataset.py         SFT formatting from verified pairs, dedup, frozen test split
  train.py           QLoRA SFT, NF4 rank 32, time-boxed
  build.py           merge adapter -> ollama create (or GGUF via LLAMA_CPP_DIR)
  evaluate.py        Ollama pass@1;  evaluate_hf.py = transformers pass@1 (no Ollama)
  promote.py         no-regression promote gate
  report.py          per-run markdown report
  run.py             single end-to-end run
  iterate.py         time-boxed sweep loop ("train N hours, keep best by pass@1")
  publish.py         push adapter + summary + model-card metrics to HuggingFace
  runlog.py          persistent success/failure log -> logs/runs.log
assets/Modelfile.legiondev   the served persona (self-contained)
agents/   teacher.json + critic.json   config.env  tunable budget caps
tests/    pytest suite (runs the real executor)     (serving app: ../../legiondev-studio)
```

## Train it

```powershell
cd F:\dev\legion\training\legion-dev
$env:PYTHONPATH = $PWD

# fast wiring check (no GPU, no Ollama needed â€” reference solutions + the real executor):
python -m legion_dev.iterate --smoke --base-override Qwen/Qwen2.5-Coder-0.5B-Instruct --time-budget-min 10

# 6-hour iterate on the 1.5b tier, verified against real tests, keep the best adapter, publish:
python -m legion_dev.iterate --tier legion-dev:qwen2.5-coder-1.5b --time-budget-min 360 --teacher-model qwen2.5-coder:7b --publish
```

Or use `run_iterate.ps1` (detached, logs to `reports/iterate-live.log`).

## Serve it (the dashboard)

The serving app is a **separate repo**: `F:\dev\legiondev-studio` (Legion Dev
Studio) â€” a local coding-agent dashboard that pulls this model from HuggingFace
into Ollama and lets it touch your Visual Studio / VS Code projects.

```powershell
cd F:\dev\legiondev-studio
.\run.ps1              # http://127.0.0.1:8770
```

### Build the Ollama model from a trained adapter (the GGUF path)

`build.py` turns the best adapter into an Ollama model. **Use the llama.cpp GGUF
path** â€” Ollama's on-the-fly *safetensors* importer crashes the runner in the
sampler on some tied-embedding models (Qwen2.5-Coder-1.5B included: `ollama
create` exits 0 but the model dies at inference with `Assertion failed: found,
llama-sampling.cpp:660`). Converting to a real GGUF first avoids that entirely,
and `build_model` **smoke-tests** the result so a dead model fails the build.

```powershell
# one-time: llama.cpp convert script + an isolated venv for its deps
git clone --depth 1 https://github.com/ggml-org/llama.cpp F:\dev\llama.cpp
py -3.12 -m venv F:\dev\llama.cpp\.venv-convert
F:\dev\llama.cpp\.venv-convert\Scripts\python -m pip install `
    --index-url https://pypi.org/simple/ --extra-index-url https://download.pytorch.org/whl/cpu `
    -r F:\dev\llama.cpp\requirements\requirements-convert_hf_to_gguf.txt

# then point build.py at it (convert runs in the isolated venv, not the training env):
$env:LLAMA_CPP_DIR = 'F:\dev\llama.cpp'
$env:LLAMA_CONVERT_PYTHON = 'F:\dev\llama.cpp\.venv-convert\Scripts\python.exe'
```

With those set, `build_model(adapter_dir, out_dir, tier=..., tag='legion-dev')`
does merge â†’ f16 GGUF â†’ `ollama create --quantize q4_K_M` â†’ smoke test, and the
Studio's `effective_model()` serves `legion-dev` automatically once it exists.

## Vision track â€” one agent that reads screenshots

Same execution-verified method, but the model reads a **screenshot** of the code /
terminal and still produces code graded by real tests. The screenshots are
*rendered* from each task's own text ([render.py](legion/training/legion-dev/legion_dev/render.py)),
so the imageâ†’code data is grounded and execution-verified â€” no real screenshots
needed. Base = **Qwen2.5-VL** (`train_vl.py` LoRA-tunes the language side, freezes
the vision encoder); eval renders held-out screenshots â†’ generates â†’ runs the tests.

```powershell
# wiring check (renders screenshots + reference solutions; no GPU/Ollama):
python -m legion_dev.iterate_vl --smoke --base-override Qwen/Qwen2.5-VL-3B-Instruct --time-budget-min 10
# real run (needs GPU; 3B fits QLoRA on ~8 GB at small image res):
python -m legion_dev.iterate_vl --tier legion-dev-vl:qwen2.5-vl-3b --time-budget-min 360 --teacher-model qwen2.5-coder:7b --publish
```

Deps: `pillow`, a recent `transformers` (with Qwen2.5-VL), `qwen-vl-utils`,
torchvision. **Caveats (honest):** VL QLoRA is tight on 8 GB â€” use the 3B tier and
modest image resolution; and serving a fine-tuned VL model through Ollama needs the
GGUF *plus its vision projector (mmproj)*, so until that's published the Studio app
serves stock `qwen2.5-vl:7b` (which already reads screenshots) as the one agent.

## Test

```powershell
$env:PYTHONPATH = $PWD; python -m pytest tests -q
```

The suite runs the real executor: `test_tasks.py` asserts every reference
solution passes its own `pytest` spec (validates the catalog end to end).

## Prerequisites

- Ollama running with a coder teacher (`qwen2.5-coder:7b`, or a bigger one) + the tier base you serve.
- `pytest` on the training Python (the executor shells out to it).
- QLoRA stack: torch+CUDA, transformers, trl, peft, bitsandbytes, datasets, accelerate.
- Publish: HF token in `..\.env` (`HUGGINGFACE_API_KEY`) or a local `huggingface-cli login`.
- Python 3.14 here: `train.py` ships a `datasets`/`dill` compatibility shim.

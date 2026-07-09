# Ares training harness (standalone)

Offline QLoRA self-distillation that builds the `legion-ares` security-analyst
model and publishes it to HuggingFace (`tburns-actual/legion-ares`), where Legion
pulls it as a standalone unit. Kept **outside** the legion repo on purpose, since
a `git_warden`/`git clean` in legion wipes a gitignored copy, and in its own dir
(separate from the Minerva persona trainer in `../training/`).

## Layout

```
ares_train/        the pipeline (importable package)
  contracts.py     output contract, posture thresholds, synthesis prompt
  scenarios.py     deterministic scenario catalog
  evidence.py      CONFIRMED FINDINGS bundles + indicator ground truth
  synth.py         teacher (Ollama model + template fallback, rejection sampling)
  score.py         the code-only eval scorer (THE quality gate)
  critic.py        grade/accept wrapper (critic == eval)
  dataset.py       SFT formatting, dedup, train/val + frozen test split
  train.py         QLoRA SFT, NF4 rank 32, time-boxed
  build.py         merge adapter -> ollama create (or GGUF via LLAMA_CPP_DIR)
  evaluate.py      Ollama eval;  evaluate_hf.py = transformers eval (no Ollama)
  promote.py       no-regression promote gate
  report.py        per-run markdown report
  run.py           single end-to-end run
  iterate.py       time-boxed sweep loop ("train N hours, keep best")
  runlog.py        persistent success/failure log -> logs/runs.log
assets/Modelfile.ares   bundled copy of legion's SYSTEM persona (self-contained)
logs/   runs.log + runs.jsonl     reports/  per-run reports + summaries
tests/  pytest suite              config.env  tunable budget caps
```

## Run it

```powershell
cd F:\dev\legion\training\legion-ares
$env:PYTHONPATH = $PWD

# 6-hour iterate on the 1.7b tier, qwen3:14b teacher, keep the best adapter:
python -m ares_train.iterate --tier legion-ares:qwen3-1.7b --time-budget-min 360 --teacher-model qwen3:14b

# fast wiring check:
python -m ares_train.iterate --smoke --base-override Qwen/Qwen3-0.6B --time-budget-min 10
```

## See success / failures

```powershell
python -m ares_train.runlog 80           # last 80 log lines
Get-Content logs\runs.log -Tail 40 -Wait  # live
```

Every stage of every run appends one line to `logs/runs.log` (and `runs.jsonl`):
`start / dataset / baseline / cycleN / build / eval / promote / run DONE` tagged
`OK`/`WARN`/`FAIL`/`DONE`; a crash logs `run FAIL CRASH: ...`.

## Test

```powershell
$env:PYTHONPATH = $PWD; python -m pytest tests -q
```

## Prerequisites

- Ollama running with `qwen3:14b` (teacher) + tier base models.
- QLoRA stack: torch+CUDA, transformers, trl, peft, bitsandbytes, datasets, accelerate.
- Publish: HF token in `..\.env` (`HUGGINGFACE_API_KEY`). GGUF weight upload needs
  llama.cpp (`LLAMA_CPP_DIR`); Ollama 0.23 can't import Qwen3 safetensors.
- Python 3.14 here: train.py ships a `datasets`/`dill` compatibility shim.

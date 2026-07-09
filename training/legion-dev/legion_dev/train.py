"""
QLoRA SFT trainer — 4-bit NF4 base, LoRA rank 32, time-boxed. Heavy ML imports
inside train() so the rest of the harness imports with no torch dependency.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .contracts import TIERS

LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def _central_config():
    """The central Legion training config (legion/training/legion_training). Adds it to
    the path if the launcher didn't. Pure-python, no deps."""
    try:
        import legion_training
    except ImportError:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # legion/training
        import legion_training
    return legion_training


@dataclass
class TrainResult:
    status: str
    adapter_dir: str
    base_model: str
    steps_done: int
    seconds_used: float
    time_budget_min: float
    detail: str = ""


def _patch_datasets_for_py314() -> None:
    """Python 3.14 changed pickle's _batch_setitems signature; installed
    dill/datasets crash on Dataset fingerprinting. Swap in a stdlib hasher
    (only affects map() cache keys, irrelevant for a one-shot run)."""
    try:
        import hashlib
        from datasets.fingerprint import Hasher

        def _safe_hash(value):
            try:
                b = repr(value).encode("utf-8", "replace")
            except Exception:
                b = str(type(value)).encode()
            return hashlib.md5(b).hexdigest()

        Hasher.hash = staticmethod(_safe_hash)
    except Exception:
        pass


def _load_messages(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def train(data_dir, out_dir, *, tier="legion-dev:qwen2.5-coder-3b", base_override=None,
          rank=32, alpha=32, dropout=0.05, steps=200, epochs=3.0, lr=2e-4,
          batch_size=1, grad_accum=8, max_length=4096, time_budget_min=30.0,
          assistant_only_loss=False, smoke=False) -> TrainResult:
    import torch
    from datasets import Dataset
    from peft import LoraConfig
    from transformers import (AutoModelForCausalLM, AutoTokenizer,
                              BitsAndBytesConfig, TrainerCallback)
    from trl import SFTConfig, SFTTrainer

    _patch_datasets_for_py314()
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    adapter_dir = out_dir / "adapter"
    adapter_dir.mkdir(parents=True, exist_ok=True)

    base_model = base_override or TIERS.get(tier, {}).get("hf_base")
    if not base_model:
        return TrainResult("skipped", str(adapter_dir), str(base_model), 0, 0.0,
                           time_budget_min, f"unknown tier {tier}")

    train_rows = _load_messages(data_dir / "train.jsonl")
    if not train_rows:
        return TrainResult("skipped", str(adapter_dir), base_model, 0, 0.0,
                           time_budget_min, "no training rows (insufficient_data)")

    if smoke:
        steps, epochs, max_length = 2, 1.0, 512
        train_rows = train_rows[: min(8, len(train_rows))]

    ds = Dataset.from_list([{"messages": r["messages"]} for r in train_rows])

    tok = AutoTokenizer.from_pretrained(base_model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.bfloat16 if bf16 else torch.float16)
    model = AutoModelForCausalLM.from_pretrained(
        base_model, quantization_config=bnb, device_map="auto",
        torch_dtype=torch.bfloat16 if bf16 else torch.float16)
    model.config.use_cache = False

    peft_cfg = LoraConfig(r=rank, lora_alpha=alpha, lora_dropout=dropout, bias="none",
                          task_type="CAUSAL_LM", target_modules=LORA_TARGETS)

    class TimeBudget(TrainerCallback):
        def __init__(self, budget_s):
            self.deadline = time.monotonic() + budget_s
            self.stopped = False

        def on_step_end(self, args, state, control, **kw):
            if time.monotonic() >= self.deadline:
                control.should_training_stop = True
                self.stopped = True
            return control

    budget = TimeBudget(time_budget_min * 60.0)

    # Anti-overfit epoch cap from the CENTRAL training config (one rule, all models).
    _train_steps = _central_config().resolve_steps(
        {"batch_size": batch_size, "grad_accum": grad_accum, "epochs": epochs, "steps": steps},
        len(ds))

    sft_args = SFTConfig(
        output_dir=str(out_dir / "checkpoints"),
        per_device_train_batch_size=batch_size, gradient_accumulation_steps=grad_accum,
        learning_rate=lr, max_steps=_train_steps, num_train_epochs=epochs,
        max_length=max_length, logging_steps=1, save_strategy="no",
        bf16=bf16, fp16=not bf16, optim="paged_adamw_8bit",
        gradient_checkpointing=True, report_to=[], warmup_ratio=0.03,
        lr_scheduler_type="cosine", assistant_only_loss=assistant_only_loss)

    t0 = time.monotonic()
    trainer = SFTTrainer(model=model, args=sft_args, train_dataset=ds,
                         processing_class=tok, peft_config=peft_cfg, callbacks=[budget])
    trainer.train()
    elapsed = time.monotonic() - t0
    steps_done = int(trainer.state.global_step)

    trainer.save_model(str(adapter_dir))
    tok.save_pretrained(str(adapter_dir))

    status = "partial" if budget.stopped else "ok"
    detail = "stopped at time budget" if budget.stopped else "completed"
    return TrainResult(status, str(adapter_dir), base_model, steps_done, elapsed,
                       time_budget_min, detail)

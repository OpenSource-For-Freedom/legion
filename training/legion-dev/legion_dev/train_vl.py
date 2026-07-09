"""
QLoRA SFT for the vision model (Qwen2.5-VL). The vision encoder is frozen; LoRA
trains the language projections. Inputs are (screenshot + tests) -> the
execution-verified solution. Heavy ML imports are inside train_vl().

Needs: torch+CUDA, a recent transformers with Qwen2.5-VL, peft, bitsandbytes,
accelerate, pillow, and `qwen-vl-utils`. 3B fits QLoRA on ~8 GB at small image
resolution; 7B needs more.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .contracts import VISION_SYSTEM, VL_TIERS
from .train import TrainResult, _patch_datasets_for_py314

LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def _load_rows(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def train_vl(data_dir, out_dir, *, tier="legion-dev-vl:qwen2.5-vl-3b", base_override=None,
             rank=16, alpha=16, dropout=0.05, steps=200, epochs=3.0, lr=1e-4,
             grad_accum=8, max_length=2048, time_budget_min=30.0, min_pixels=None,
             max_pixels=None, smoke=False) -> TrainResult:
    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (AutoProcessor, BitsAndBytesConfig, Trainer,
                              TrainerCallback, TrainingArguments)
    try:
        from transformers import Qwen2_5_VLForConditionalGeneration as VLModel
    except Exception:  # older transformers
        from transformers import Qwen2VLForConditionalGeneration as VLModel
    try:
        from qwen_vl_utils import process_vision_info
    except Exception:
        process_vision_info = None

    _patch_datasets_for_py314()
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    adapter_dir = out_dir / "adapter"
    adapter_dir.mkdir(parents=True, exist_ok=True)

    base_model = base_override or VL_TIERS.get(tier, {}).get("hf_base")
    if not base_model:
        return TrainResult("skipped", str(adapter_dir), str(base_model), 0, 0.0,
                           time_budget_min, f"unknown VL tier {tier}")

    rows = _load_rows(data_dir / "train_vl.jsonl")
    if not rows:
        return TrainResult("skipped", str(adapter_dir), base_model, 0, 0.0,
                           time_budget_min, "no VL training rows")
    if smoke:
        steps, epochs = 2, 1.0
        rows = rows[: min(4, len(rows))]

    proc_kw = {}
    if min_pixels:
        proc_kw["min_pixels"] = min_pixels
    if max_pixels:
        proc_kw["max_pixels"] = max_pixels
    processor = AutoProcessor.from_pretrained(base_model, **proc_kw)
    tok = processor.tokenizer
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token

    bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.bfloat16 if bf16 else torch.float16)
    model = VLModel.from_pretrained(base_model, quantization_config=bnb, device_map="auto",
                                    torch_dtype=torch.bfloat16 if bf16 else torch.float16)
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    model = get_peft_model(model, LoraConfig(r=rank, lora_alpha=alpha, lora_dropout=dropout,
                                             bias="none", task_type="CAUSAL_LM",
                                             target_modules=LORA_TARGETS))
    image_token_id = getattr(model.config, "image_token_id", None)

    def messages_for(row):
        img = str((data_dir / row["image"]).resolve())
        return [
            {"role": "system", "content": [{"type": "text", "text": VISION_SYSTEM}]},
            {"role": "user", "content": [{"type": "image", "image": img},
                                         {"type": "text", "text": row["user_text"]}]},
            {"role": "assistant", "content": [{"type": "text", "text": row["answer"]}]},
        ]

    def collate(batch):
        msgs = [messages_for(r) for r in batch]
        texts = [processor.apply_chat_template(m, tokenize=False, add_generation_prompt=False) for m in msgs]
        if process_vision_info is not None:
            images = [process_vision_info(m)[0] for m in msgs]
        else:
            from PIL import Image
            images = [[Image.open(c["image"]) for c in m[1]["content"] if c.get("type") == "image"] for m in msgs]
        inputs = processor(text=texts, images=images, padding=True, truncation=True,
                           max_length=max_length, return_tensors="pt")
        labels = inputs["input_ids"].clone()
        labels[labels == tok.pad_token_id] = -100
        if image_token_id is not None:
            labels[labels == image_token_id] = -100
        inputs["labels"] = labels
        return inputs

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
    # Cap training to `epochs` passes so a tiny dataset can't balloon into 100+ epochs
    # (memorization). `steps` is an upper bound. Same fix as the text track (train.py).
    import math
    _cap = max(1, math.ceil(epochs * math.ceil(len(rows) / max(1, grad_accum))))
    _train_steps = min(steps, _cap) if steps and steps > 0 else _cap
    args = TrainingArguments(
        output_dir=str(out_dir / "checkpoints"),
        per_device_train_batch_size=1, gradient_accumulation_steps=grad_accum,
        learning_rate=lr, max_steps=_train_steps, num_train_epochs=epochs,
        logging_steps=1, save_strategy="no", bf16=bf16, fp16=not bf16,
        optim="paged_adamw_8bit", gradient_checkpointing=True, report_to=[],
        warmup_ratio=0.03, lr_scheduler_type="cosine", remove_unused_columns=False,
        dataloader_num_workers=0)

    t0 = time.monotonic()
    trainer = Trainer(model=model, args=args, train_dataset=rows, data_collator=collate,
                      callbacks=[budget])
    trainer.train()
    elapsed = time.monotonic() - t0
    steps_done = int(trainer.state.global_step)

    trainer.save_model(str(adapter_dir))
    processor.save_pretrained(str(adapter_dir))

    status = "partial" if budget.stopped else "ok"
    return TrainResult(status, str(adapter_dir), base_model, steps_done, elapsed,
                       time_budget_min, "stopped at time budget" if budget.stopped else "completed")

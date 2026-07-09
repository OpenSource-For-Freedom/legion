"""
Eval via transformers (no Ollama) — loads the base (optionally + a trained LoRA
adapter), generates a solution for each frozen test task, and grades by EXECUTION
(pass@1). Lets the iterate loop measure an adapter's real lift without a running
Ollama.
"""

from __future__ import annotations

import time

from .contracts import SYNTHESIS_SYSTEM, TIERS
from .dataset import frozen_test_tasks
from .evaluate import EvalReport, _finish
from .score import grade


def evaluate_hf(base_model, adapter_dir=None, *, tier="legion-dev:qwen2.5-coder-1.5b",
                temperature=0.2, max_new_tokens=1024, exec_timeout=30.0, load_4bit=True) -> EvalReport:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    label = f"{base_model}+adapter" if adapter_dir else f"{base_model} (base)"
    rep = EvalReport(model=label)

    tok = AutoTokenizer.from_pretrained(base_model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    kw = {"device_map": "auto"}
    if load_4bit and torch.cuda.is_available():
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
    else:
        kw["torch_dtype"] = torch.float16
    model = AutoModelForCausalLM.from_pretrained(base_model, **kw)
    if adapter_dir:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter_dir)
    model.eval()

    tasks = frozen_test_tasks()
    rep.n = len(tasks)
    lat: list[float] = []
    for task in tasks:
        msgs = [{"role": "system", "content": SYNTHESIS_SYSTEM}, {"role": "user", "content": task.render()}]
        try:
            text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        except Exception:
            text = SYNTHESIS_SYSTEM + "\n\n" + task.render()
        inputs = tok(text, return_tensors="pt").to(model.device)
        t0 = time.monotonic()
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=max_new_tokens,
                                 do_sample=temperature > 0, temperature=max(temperature, 1e-5),
                                 top_p=0.9, pad_token_id=tok.pad_token_id)
        lat.append(time.monotonic() - t0)
        answer = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        v = grade(answer, task, timeout=exec_timeout)
        if v.has_code:
            rep.had_code += 1
        if v.passed:
            rep.passed += 1
        rep.per_item.append({"task": task.name, "passed": v.passed, "reasons": v.reasons})

    rep = _finish(rep, lat)
    del model
    try:
        torch.cuda.empty_cache()
    except Exception:
        pass
    return rep

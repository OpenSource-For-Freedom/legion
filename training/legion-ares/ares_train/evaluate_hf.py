"""
Eval via transformers (no Ollama / no llama.cpp). Loads the base (optionally with
a trained LoRA adapter) via peft and generates answers for the frozen test set,
then scores them. Lets the iterate loop measure an adapter's lift even where
Ollama can't import Qwen3 safetensors.
"""

from __future__ import annotations

import time

from .contracts import GATES, SYNTHESIS_SYSTEM, TIERS
from .dataset import frozen_test_pairs
from .evaluate import EvalReport
from .score import score_answer


def _strip_think(text: str) -> str:
    return text.rsplit("</think>", 1)[-1].strip() if "</think>" in text else text.strip()


def evaluate_hf(base_model, adapter_dir=None, *, n_per=8, tier="legion-ares:qwen3-1.7b",
                temperature=0.3, max_new_tokens=400, load_4bit=True) -> EvalReport:
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

    pairs = frozen_test_pairs(n_per)
    rep.n = len(pairs)
    g, f, c, a, lat = [], [], [], [], []
    for bundle, instruction in pairs:
        user = f"{instruction}\n\n{bundle.render()}"
        msgs = [{"role": "system", "content": SYNTHESIS_SYSTEM}, {"role": "user", "content": user}]
        try:
            text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True,
                                           enable_thinking=False)
        except TypeError:
            text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        inputs = tok(text, return_tensors="pt").to(model.device)
        t0 = time.monotonic()
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=max_new_tokens,
                                 do_sample=temperature > 0, temperature=max(temperature, 1e-5),
                                 top_p=0.9, pad_token_id=tok.pad_token_id)
        dt = time.monotonic() - t0
        answer = _strip_think(tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True))
        res = score_answer(answer, bundle)
        g.append(res.grounding); f.append(res.format)
        c.append(res.citation_coverage); a.append(res.anti_parrot); lat.append(dt)
        rep.invented_total += len(res.invented)
        if res.passed:
            rep.passed += 1
        rep.per_item.append({"scenario": bundle.scenario, "passed": res.passed,
                             "reasons": res.reasons, "metrics": res.as_metrics(), "answer": answer})

    def _mean(xs):
        return sum(xs) / len(xs) if xs else 0.0

    rep.pass_rate = rep.passed / rep.n if rep.n else 0.0
    rep.grounding, rep.format = _mean(g), _mean(f)
    rep.citation_coverage, rep.anti_parrot = _mean(c), _mean(a)
    rep.mean_latency_s = _mean(lat)
    rep.gates_cleared = (rep.invented_total <= GATES["invented_indicators_max"]
                         and rep.grounding >= GATES["grounding_min"]
                         and rep.format >= GATES["format_min"]
                         and rep.citation_coverage >= GATES["citation_coverage_min"]
                         and rep.anti_parrot >= GATES["anti_parrot_min"])
    del model
    try:
        torch.cuda.empty_cache()
    except Exception:
        pass
    return rep

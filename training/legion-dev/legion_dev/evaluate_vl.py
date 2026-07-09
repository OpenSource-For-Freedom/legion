"""
Vision eval — render each frozen test task to a screenshot, have the VL model
(base + optional LoRA adapter) read it and produce a solution, then grade by
EXECUTION (pass@1). Same gate as everything else.
"""

from __future__ import annotations

import time

from .contracts import VISION_SYSTEM, VL_TIERS
from .dataset_vl import frozen_test_pairs_vl
from .evaluate import EvalReport, _finish
from .score import grade


def evaluate_vl(base_model, adapter_dir=None, *, tier="legion-dev-vl:qwen2.5-vl-3b",
                work_dir=".", kind="code", temperature=0.2, max_new_tokens=1024,
                exec_timeout=30.0, load_4bit=True) -> EvalReport:
    import torch
    from transformers import AutoProcessor, BitsAndBytesConfig
    try:
        from transformers import Qwen2_5_VLForConditionalGeneration as VLModel
    except Exception:
        from transformers import Qwen2VLForConditionalGeneration as VLModel
    try:
        from qwen_vl_utils import process_vision_info
    except Exception:
        process_vision_info = None

    label = f"{base_model}+adapter" if adapter_dir else f"{base_model} (base)"
    rep = EvalReport(model=label)

    processor = AutoProcessor.from_pretrained(base_model)
    kw = {"device_map": "auto"}
    if load_4bit and torch.cuda.is_available():
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
    else:
        kw["torch_dtype"] = torch.float16
    model = VLModel.from_pretrained(base_model, **kw)
    if adapter_dir:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter_dir)
    model.eval()

    pairs = frozen_test_pairs_vl(work_dir, kind=kind)
    rep.n = len(pairs)
    lat: list[float] = []
    for task, img, user_text in pairs:
        messages = [
            {"role": "system", "content": [{"type": "text", "text": VISION_SYSTEM}]},
            {"role": "user", "content": [{"type": "image", "image": img},
                                         {"type": "text", "text": user_text}]},
        ]
        text = processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        if process_vision_info is not None:
            images = process_vision_info(messages)[0]
        else:
            from PIL import Image
            images = [Image.open(img)]
        inputs = processor(text=[text], images=images, return_tensors="pt").to(model.device)
        t0 = time.monotonic()
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=max_new_tokens,
                                 do_sample=temperature > 0, temperature=max(temperature, 1e-5),
                                 top_p=0.9)
        lat.append(time.monotonic() - t0)
        gen = out[0][inputs["input_ids"].shape[1]:]
        answer = processor.decode(gen, skip_special_tokens=True)
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

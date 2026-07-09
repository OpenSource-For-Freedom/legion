"""
Build stage: trained LoRA adapter -> Ollama-registered Ares model.
  1. merge adapter into fp16 base (peft)
  2. render Modelfile from the bundled assets/Modelfile.ares (FROM <merged>)
  3. ollama create --quantize q4_K_M  (or llama.cpp GGUF path if LLAMA_CPP_DIR set)

Note: Ollama 0.23.1 can't import Qwen3 safetensors; that case returns a clear
error pointing at the llama.cpp path.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .contracts import TIERS

# bundled copy of legion's Modelfile.ares — keeps the trainer standalone.
MODELFILE_ARES = Path(__file__).resolve().parents[1] / "assets" / "Modelfile.ares"


@dataclass
class BuildResult:
    status: str
    tag: str
    method: str
    merged_dir: str = ""
    gguf_path: str = ""
    gguf_sha256: str = ""
    detail: str = ""
    verified: bool | None = None       # did the shipped GGUF pass the Ollama coherence gate
    verify_pass: str = ""              # e.g. "7/12" for the dashboard/report


def merge_adapter(adapter_dir, base_model, out_dir) -> str:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    merged = Path(out_dir) / "merged"
    merged.mkdir(parents=True, exist_ok=True)
    base = AutoModelForCausalLM.from_pretrained(base_model, torch_dtype=torch.float16, device_map="cpu")
    model = PeftModel.from_pretrained(base, str(adapter_dir)).merge_and_unload()
    model.save_pretrained(str(merged), safe_serialization=True)
    AutoTokenizer.from_pretrained(base_model).save_pretrained(str(merged))
    return str(merged)


def render_modelfile(from_ref, out_path) -> str:
    text = MODELFILE_ARES.read_text(encoding="utf-8")
    lines, replaced = [], False
    for ln in text.splitlines():
        if ln.strip().lower().startswith("from ") and not replaced:
            lines.append(f"FROM {from_ref}")
            replaced = True
        else:
            lines.append(ln)
    if not replaced:
        lines.insert(0, f"FROM {from_ref}")
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(out_path)


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _ollama_create(tag, modelfile, quantize, timeout) -> tuple[bool, str]:
    cmd = ["ollama", "create", tag, "-f", modelfile]
    if quantize:
        cmd += ["--quantize", quantize]
    try:
        p = subprocess.run(cmd, capture_output=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode == 0, out[-4000:]
    except FileNotFoundError:
        return False, "ollama not found on PATH"
    except subprocess.TimeoutExpired:
        return False, f"ollama create timed out after {timeout}s"


def _llama_cpp_dir():
    d = os.environ.get("LLAMA_CPP_DIR")
    if d and (Path(d) / "convert_hf_to_gguf.py").exists():
        return Path(d)
    return None


def verify_build(tag, *, tier, n_per=8, min_pass_rate=0.30, max_incoherent=1, host=None):
    """Score the freshly-registered Ollama model on the frozen test set with the
    coherence-aware scorer. Rejects a build whose answers are degenerate (broken
    chat template / over-quant) or whose pass rate collapses. This is the gate that
    would have caught the `{{ .Prompt }}` template bug before it ever shipped.
    Returns (ok, EvalReport, n_incoherent)."""
    from . import evaluate as ev
    rep = ev.evaluate_model(tag, n_per=n_per, tier=tier, host=host)
    incoherent = sum(1 for it in rep.per_item
                     if any("incoherent" in r for r in it.get("reasons", [])))
    ok = incoherent <= max_incoherent and rep.pass_rate >= min_pass_rate
    return ok, rep, incoherent


def _finalize(ok, tag, method, tier, *, merged="", gguf="", sha="", detail="", verify=True) -> BuildResult:
    status = "ok" if ok else "error"
    verified: bool | None = None
    vpass = ""
    if ok and verify:
        try:
            vok, rep, incoh = verify_build(tag, tier=tier)
            verified, vpass = vok, f"{rep.passed}/{rep.n}"
            if not vok:
                status = "degenerate"
                detail = (f"GGUF failed the coherence gate: pass {rep.passed}/{rep.n}, "
                          f"{incoh} incoherent — likely a broken chat template or over-quant; "
                          "not shippable. " + (detail or ""))
        except Exception as e:
            detail = f"(build verify skipped: {e}) " + (detail or "")
    return BuildResult(status, tag, method, merged, gguf, sha, detail, verified, vpass)


def build_model(adapter_dir, out_dir, *, tier="legion-ares:qwen3-4b", tag=None,
                base_model=None, quantize=None, timeout=3600.0, do_merge=True,
                verify=True) -> BuildResult:
    out_dir = Path(out_dir)
    tag = tag or tier
    base_model = base_model or TIERS.get(tier, {}).get("hf_base", "")
    quantize = quantize or TIERS.get(tier, {}).get("quant", "q4_K_M")

    if do_merge:
        try:
            merged = merge_adapter(adapter_dir, base_model, out_dir)
        except Exception as e:
            return BuildResult("error", tag, "none", detail=f"merge failed: {e}")
    else:
        merged = str(Path(adapter_dir))

    llama = _llama_cpp_dir()
    if llama:
        try:
            gguf = _gguf_via_llamacpp(merged, out_dir, llama, quantize)
            mf = render_modelfile(f"./{Path(gguf).name}", out_dir / "Modelfile")
            ok, log = _ollama_create(tag, str(mf), None, timeout)
            return _finalize(ok, tag, "gguf", tier, merged=merged, gguf=gguf,
                             sha=_sha256(gguf) if ok else "", detail=log, verify=verify)
        except Exception as e:
            return BuildResult("error", tag, "gguf", merged, detail=f"gguf path failed: {e}")

    mf = render_modelfile(merged, out_dir / "Modelfile")
    ok, log = _ollama_create(tag, str(mf), quantize, timeout)
    detail = log
    if not ok and "unsupported architecture" in log.lower():
        detail = ("Ollama on this host cannot import Qwen3 safetensors "
                  "(\"unsupported architecture Qwen3ForCausalLM\"). Use the llama.cpp "
                  "GGUF path: set LLAMA_CPP_DIR to a checkout with convert_hf_to_gguf.py "
                  "(+ llama-quantize on PATH), or upgrade Ollama. Merged model ready at: "
                  + merged + "\n---\n" + log)
    return _finalize(ok, tag, "ollama-import", tier, merged=merged, detail=detail, verify=verify)


def _gguf_via_llamacpp(merged, out_dir, llama, quantize) -> str:
    import sys
    f16 = out_dir / "model-f16.gguf"
    subprocess.run([sys.executable, str(llama / "convert_hf_to_gguf.py"), merged,
                    "--outfile", str(f16), "--outtype", "f16"],
                   check=True, capture_output=True, encoding="utf-8", errors="replace", timeout=3600)
    q = out_dir / f"legion-ares.{quantize}.gguf"
    qbin = shutil.which("llama-quantize") or str(llama / "llama-quantize")
    subprocess.run([qbin, str(f16), str(q), quantize],
                   check=True, capture_output=True, encoding="utf-8", errors="replace", timeout=3600)
    return str(q)

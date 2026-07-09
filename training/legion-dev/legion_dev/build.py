"""
Build stage: trained LoRA adapter -> Ollama-registered Legion Dev model.
  1. merge adapter into fp16 base (peft)
  2. render Modelfile from the bundled assets/Modelfile.legiondev (FROM <merged>)
  3. ollama create --quantize q4_K_M  (or llama.cpp GGUF path if LLAMA_CPP_DIR set)

If the installed Ollama can't import the safetensors architecture, the error
points at the llama.cpp GGUF path.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .contracts import TIERS

# bundled copy of the served persona — keeps the trainer standalone.
MODELFILE_DEV = Path(__file__).resolve().parents[1] / "assets" / "Modelfile.legiondev"

# tokenizer files copied verbatim from the base model into the merged dir.
_TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "vocab.json",
                    "merges.txt", "special_tokens_map.json", "added_tokens.json")


@dataclass
class BuildResult:
    status: str
    tag: str
    method: str
    merged_dir: str = ""
    gguf_path: str = ""
    gguf_sha256: str = ""
    detail: str = ""


def _copy_base_tokenizer(base_model, merged) -> None:
    """Copy the base model's ORIGINAL tokenizer files into the merged dir.

    Do NOT re-save via `AutoTokenizer(...).save_pretrained()`: the training env's
    (newer) transformers writes a tokenizer_config the llama.cpp convert venv's
    (older, pinned) transformers can't load — `convert_hf_to_gguf` then dies in
    AutoTokenizer.from_pretrained. The base's source files are canonical and load
    under any transformers version."""
    from huggingface_hub import snapshot_download

    src = Path(base_model)
    if not src.is_dir():  # a HF repo id -> fetch just the tokenizer files (cache hit if trained)
        src = Path(snapshot_download(base_model, allow_patterns=list(_TOKENIZER_FILES)))
    copied = 0
    for name in _TOKENIZER_FILES:
        f = src / name
        if f.exists():
            shutil.copy2(f, Path(merged) / name)
            copied += 1
    if not copied:
        raise RuntimeError(f"no tokenizer files found for base {base_model}")


def merge_adapter(adapter_dir, base_model, out_dir) -> str:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM

    merged = Path(out_dir) / "merged"
    merged.mkdir(parents=True, exist_ok=True)
    base = AutoModelForCausalLM.from_pretrained(base_model, torch_dtype=torch.float16, device_map="cpu")
    model = PeftModel.from_pretrained(base, str(adapter_dir)).merge_and_unload()
    model.save_pretrained(str(merged), safe_serialization=True)
    _copy_base_tokenizer(base_model, merged)
    return str(merged)


def render_modelfile(from_ref, out_path) -> str:
    text = MODELFILE_DEV.read_text(encoding="utf-8")
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


def _convert_python() -> str:
    """Python for llama.cpp's convert_hf_to_gguf.py. Its deps (gguf, numpy<2, a
    pinned transformers) differ from the training env, so point
    LLAMA_CONVERT_PYTHON at an isolated convert venv; default to the current one."""
    import sys
    return os.environ.get("LLAMA_CONVERT_PYTHON") or sys.executable


def _ollama_host() -> str:
    return os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")


def _smoke(tag, timeout=120) -> tuple[bool, str]:
    """Actually run the model once. `ollama create` exiting 0 does NOT mean the
    model runs — an imported model can still crash the runner in the sampler at
    inference. A build that can't produce a token is a failed build, not 'ok'."""
    import json as _json
    import urllib.request
    body = _json.dumps({"model": tag, "prompt": "ok", "stream": False,
                        "options": {"num_predict": 4}}).encode()
    req = urllib.request.Request(_ollama_host() + "/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = _json.loads(r.read().decode())
        if data.get("error"):
            return False, str(data["error"])
        return ("response" in data), (data.get("response") or "")[:200]
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _gguf_f16(merged, out_dir, llama) -> str:
    """Merged HF weights -> f16 GGUF via llama.cpp's mature converter, then let
    Ollama quantize the GGUF. Ollama imports GGUFs reliably; its on-the-fly
    safetensors importer does not (it crashes the sampler on some tied-embedding
    models, e.g. Qwen2.5-Coder-1.5B) — so no llama-quantize binary is needed."""
    f16 = Path(out_dir) / "model-f16.gguf"
    subprocess.run([_convert_python(), str(llama / "convert_hf_to_gguf.py"), str(merged),
                    "--outfile", str(f16), "--outtype", "f16"],
                   check=True, capture_output=True, encoding="utf-8", errors="replace", timeout=3600)
    return str(f16)


def build_model(adapter_dir, out_dir, *, tier="legion-dev:qwen2.5-coder-3b", tag=None,
                base_model=None, quantize="q4_K_M", timeout=3600.0, do_merge=True) -> BuildResult:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = tag or tier
    base_model = base_model or TIERS.get(tier, {}).get("hf_base", "")

    if do_merge:
        try:
            merged = merge_adapter(adapter_dir, base_model, out_dir)
        except Exception as e:
            return BuildResult("error", tag, "none", detail=f"merge failed: {e}")
    else:
        merged = str(Path(adapter_dir))

    llama = _llama_cpp_dir()
    if llama:
        # Preferred: convert to a real GGUF, then Ollama quantizes the GGUF.
        try:
            f16 = _gguf_f16(merged, out_dir, llama)
        except subprocess.CalledProcessError as e:
            return BuildResult("error", tag, "gguf", merged,
                               detail=f"convert_hf_to_gguf failed: {(e.stderr or e.stdout or '')[-2000:]}")
        mf = render_modelfile(f"./{Path(f16).name}", out_dir / "Modelfile")
        ok, log = _ollama_create(tag, str(mf), quantize, timeout)
        method, gguf_path, gguf_sha = "gguf", f16, (_sha256(f16) if ok else "")
    else:
        mf = render_modelfile(merged, out_dir / "Modelfile")
        ok, log = _ollama_create(tag, str(mf), quantize, timeout)
        method, gguf_path, gguf_sha = "ollama-import", "", ""
        if not ok and "unsupported architecture" in log.lower():
            log = ("Ollama can't import these safetensors. Set LLAMA_CPP_DIR to a llama.cpp "
                   "checkout (convert_hf_to_gguf.py) + LLAMA_CONVERT_PYTHON to a venv with its "
                   "deps to use the GGUF path. Merged model at: " + merged + "\n---\n" + log)

    if not ok:
        return BuildResult("error", tag, method, merged, gguf_path, gguf_sha, log)

    # create exited 0 — but sampler/runner crashes only surface at inference, so a
    # green create can still be a dead model. Smoke-test before calling it "ok".
    ran, smsg = _smoke(tag)
    if not ran:
        return BuildResult("error", tag, method, merged, gguf_path, gguf_sha,
                           f"created but the model FAILED to run (smoke test): {smsg}\n---\n{log}")
    return BuildResult("ok", tag, method, merged, gguf_path, gguf_sha, f"smoke ok: {smsg!r}")

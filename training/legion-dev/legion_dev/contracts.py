"""
Single source of truth for the Legion Dev output contract and the build/eval
gates. Legion Dev is a *coding* model trained by execution-verified
self-distillation: given a task, the current file, and a pytest spec, it must
produce the complete corrected file so the tests pass. The gate is `pytest`
(see executor.py / score.py), never a text heuristic — a candidate is accepted
only if it actually runs and passes.

Mirrored by the served model's Modelfile (assets/Modelfile.legiondev): train-time
and serve-time system prompts must match.
"""

from __future__ import annotations

REPO = "tburns-actual/legion_dev"
BASE_FAMILY = "qwen2.5-coder"
QUANT = "Q4_K_M"

# Code-specialized tiers. Instruct variants ship a chat template and follow
# instructions out of the box. NOTE: the *teacher* (dataset generation) can be a
# larger local model than the student — it only runs inference at build time, so
# qwen2.5-coder:14b/32b (CPU-spill on 8 GB) raises the data ceiling for free.
TIERS = {
    "legion-dev:qwen2.5-coder-1.5b": {"hf_base": "Qwen/Qwen2.5-Coder-1.5B-Instruct",
                                      "ollama_base": "qwen2.5-coder:1.5b", "num_ctx": 8192},
    "legion-dev:qwen2.5-coder-3b":   {"hf_base": "Qwen/Qwen2.5-Coder-3B-Instruct",
                                      "ollama_base": "qwen2.5-coder:3b",   "num_ctx": 8192},
    "legion-dev:qwen2.5-coder-7b":   {"hf_base": "Qwen/Qwen2.5-Coder-7B-Instruct",
                                      "ollama_base": "qwen2.5-coder:7b",   "num_ctx": 8192},
}

DEFAULT_TIER = "legion-dev:qwen2.5-coder-3b"

# Vision-language tiers — ONE agent that reads screenshots (of code, a terminal, an
# error) AND writes code. 3B is the practical QLoRA ceiling on an 8 GB GPU; 7B needs
# more VRAM. Fine-tuned via legion_dev.train_vl on execution-verified image+code data.
VL_TIERS = {
    "legion-dev-vl:qwen2.5-vl-3b": {"hf_base": "Qwen/Qwen2.5-VL-3B-Instruct", "num_ctx": 8192},
    "legion-dev-vl:qwen2.5-vl-7b": {"hf_base": "Qwen/Qwen2.5-VL-7B-Instruct", "num_ctx": 8192},
}
DEFAULT_VL_TIER = "legion-dev-vl:qwen2.5-vl-3b"

# Policy parity with legion-ares: never distil from / train these families.
BLOCKED_TAGS = ("deepseek",)


def is_blocked(tag: str) -> bool:
    norm = "".join(c for c in tag.lower() if c.isalnum())
    return any(b in norm for b in BLOCKED_TAGS)


# The Legion Dev persona. Train-time and serve-time system prompts MUST match.
SYNTHESIS_SYSTEM = (
    "You are Legion Dev, a local coding assistant. You are given a task, the "
    "current contents of a Python file, and a pytest test file that specifies the "
    "required behavior. Produce the COMPLETE corrected contents of the file so "
    "that every test passes. You may write one short sentence of explanation "
    "first, but you MUST include the full file in a single fenced ```python code "
    "block. The tests are the specification — make them pass. Fix the actual cause "
    "of the failure, not the symptom (no bare try/except, sleep, or hardcoded value "
    "to force a pass). Change only what is needed and keep the rest of the file as "
    "it was: keep the public function names and signatures the tests import, match "
    "the file's existing style and naming, and do not reformat, refactor, or add "
    "features, options, or abstractions the tests do not require. Follow the "
    "language's standard conventions. Do not modify or restate the tests, do not "
    "invent libraries or APIs that are not available, and never include a real "
    "secret value (read secrets from the environment instead)."
)

# Vision persona — same execution contract, but the current file/error is shown as
# a SCREENSHOT the model must read. Train-time and serve-time must match.
VISION_SYSTEM = (
    "You are Legion Dev, a local coding assistant that can see. You are given a "
    "SCREENSHOT (of a code file, a terminal, or an error) and a pytest test file "
    "that specifies the required behavior. Read the screenshot carefully, then "
    "produce the COMPLETE corrected contents of the file so that every test passes. "
    "You may write one short sentence first, but you MUST include the full file in a "
    "single fenced ```python code block. The tests are the specification — make them "
    "pass. Fix the actual cause of the failure, not the symptom. Change only what is "
    "needed, keep the public function names and signatures the tests import, match "
    "the file's existing style, and do not reformat or add what the tests do not "
    "require. Do not restate the tests, do not invent unavailable APIs, and never "
    "include a real secret value."
)

# The build/eval gate. Execution pass@1 on the frozen test set is the metric.
# A trained tier "clears the gate" only if it passes at least this fraction; the
# promote step additionally requires no regression vs the baseline.
GATES = {
    "pass_rate_min": 0.60,
}

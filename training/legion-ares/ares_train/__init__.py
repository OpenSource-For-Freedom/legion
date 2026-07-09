"""
Ares offline training harness (standalone — lives outside the legion repo so
git_warden / git clean can't wipe it).

Reconstructs the QLoRA self-distillation pipeline that builds the `legion-ares`
model: teacher synthesis -> critic rejection sampling -> time-boxed QLoRA SFT ->
Ollama build -> eval gate -> promote -> report. The trained model is published
to HuggingFace and pulled into Legion as a standalone unit. Deterministic core
(contracts, scenarios, evidence, score, critic, dataset) imports with no
torch/ollama dependency; train/build/evaluate pull heavy deps lazily.
"""

__all__ = [
    "contracts", "evidence", "scenarios", "score", "critic", "synth",
    "dataset", "train", "build", "evaluate", "evaluate_hf", "promote",
    "report", "ollama_client", "runlog",
]

__version__ = "2026.06.20-v4-sft"

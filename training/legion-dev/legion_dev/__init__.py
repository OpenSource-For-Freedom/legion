"""
Legion Dev offline training harness (standalone — lives next to the ares-training
harness under legion-agent).

Execution-verified self-distillation that builds the `legion_dev` coding model:
the local coder teacher proposes solutions to real coding tasks, the sandboxed
runner keeps only the ones that PASS the tasks' pytest specs (execution-verified
rejection sampling), then QLoRA SFT -> Ollama build -> pass@1 eval gate -> promote
-> report. The trained model is published to HuggingFace (tburns-actual/legion_dev)
and served by the local dashboard (../server). Deterministic core (contracts,
tasks, executor, extract, score, critic, synth, dataset) imports with no
torch/ollama dependency; train/build/evaluate pull heavy deps lazily.
"""

__all__ = [
    "contracts", "tasks", "executor", "extract", "score", "critic", "synth",
    "dataset", "train", "build", "evaluate", "evaluate_hf", "promote",
    "report", "ollama_client", "runlog",
    # vision track (one agent that reads screenshots): render task -> screenshot,
    # execution-verified image+code data, Qwen2.5-VL QLoRA, pass@1 eval.
    "render", "dataset_vl", "train_vl", "evaluate_vl", "iterate_vl",
]

__version__ = "2026.07.06-v3-exec+vision"

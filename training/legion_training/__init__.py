"""Central training config for every Legion model.

One source of truth: shared CORE (DEFAULTS + SYNTHETIC + SECURITY) plus a per-model
registry (MODELS) that splits into process / context / skills / data. Every harness
imports this and reads its resolved settings, so training stays consistent and adding
a model is one registry entry that inherits the core.

Usage from a harness (its launcher puts F:\\dev\\legion\\training on PYTHONPATH):
    import legion_training as lt
    cfg = lt.get("legion-dev-coder")            # core + this model's split + env
    steps = lt.resolve_steps(cfg, n_examples)   # the shared anti-overfit epoch cap
    sys_prompt = lt.security_prefix() + "\\n\\n" + persona   # security-first context
"""
from .registry import (DEFAULTS, MODELS, PROCESSES, SECURITY, SYNTHETIC,
                       TRAINING_ROOT, get, models, resolve_steps, security_prefix)

__all__ = ["DEFAULTS", "SYNTHETIC", "SECURITY", "MODELS", "PROCESSES", "TRAINING_ROOT",
           "get", "models", "resolve_steps", "security_prefix"]

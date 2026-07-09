"""AGENTIC eval — the capability metric for the tool-use track.

Unlike evaluate_hf (one generation graded as a single file), this runs the model
in a REAL tool loop against each held-out task: generate -> parse a tool call ->
execute it in a scratch workspace (write_file / run_shell / read_file) -> feed the
result back -> repeat, until the model stops calling tools or hits the step cap.
Then it grades by EXECUTION: do the task's tests pass against the file the model
left in the workspace? This measures whether the model can DRIVE the loop to
green — exactly what the single-file fine-tunes can't do.

Reported: pass@1 (drove to green), plus `ran_tests` (did it ever call run_shell)
and mean steps — so we can see the chaining behavior improve, not just the score.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .agent_contracts import AGENT_SYSTEM, AGENT_TOOL_NAMES, AGENT_TOOLS
from .dataset import frozen_test_tasks
from .executor import run_task
from .trajectory import _user

_TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)
_FENCE_RE = re.compile(r"```(?:json|tool_call)?\s*(\{.*?\})\s*```", re.DOTALL)


@dataclass
class AgentEvalReport:
    model: str
    n: int = 0
    passed: int = 0          # drove the loop to green
    ran_tests: int = 0       # called run_shell at least once
    wrote_file: int = 0
    steps_total: int = 0
    per_item: list = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return self.passed / self.n if self.n else 0.0

    @property
    def gates_cleared(self) -> bool:
        from .contracts import GATES
        return self.pass_rate >= GATES["pass_rate_min"]

    @property
    def mean_steps(self) -> float:
        return self.steps_total / self.n if self.n else 0.0

    def summary(self) -> dict:
        return {"model": self.model, "n": self.n, "passed": self.passed,
                "pass_rate": round(self.pass_rate, 3), "ran_tests": self.ran_tests,
                "wrote_file": self.wrote_file, "gates_cleared": self.gates_cleared,
                "mean_steps": round(self.mean_steps, 2)}


def _parse_tool_call(text: str):
    """First tool call the model emitted: <tool_call>{...}</tool_call> (Qwen), else
    a fenced/bare json object naming a known tool. Returns (name, args) or None."""
    cands = _TOOL_CALL_RE.findall(text) or _FENCE_RE.findall(text)
    if not cands:
        # bare object anywhere in the text
        m = re.search(r"\{.*\}", text, re.DOTALL)
        cands = [m.group(0)] if m else []
    for snippet in cands:
        try:
            obj = json.loads(snippet)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "function" in obj and isinstance(obj["function"], dict):
            obj = obj["function"]
        name = obj.get("name")
        args = obj.get("arguments", obj.get("parameters", {}))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if name in AGENT_TOOL_NAMES and isinstance(args, dict):
            return name, args
    return None


def _exec_tool(name, args, workdir: Path, *, timeout=30.0) -> str:
    """Execute a tool against the scratch workspace, returning the observation the
    model sees — matches the Studio's tool outputs closely enough to transfer."""
    try:
        if name == "write_file":
            p = workdir / args["path"]
            p.parent.mkdir(parents=True, exist_ok=True)
            content = args.get("content", "")
            p.write_text(content, encoding="utf-8")
            return f"wrote {len(content)} bytes to {args['path']}"
        if name == "read_file":
            p = workdir / args["path"]
            return p.read_text(encoding="utf-8") if p.exists() else f"error: {args['path']} does not exist"
        if name == "run_shell":
            cmd = args.get("command", "")
            argv = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"] if "pytest" in cmd \
                else cmd
            proc = subprocess.run(argv, cwd=str(workdir), capture_output=True, encoding="utf-8",
                                  errors="replace", timeout=timeout,
                                  shell=not isinstance(argv, list))
            out = ((proc.stdout or "") + (proc.stderr or "")).strip()[-3000:]
            return (out or "(no output)") + f"\n[exit {proc.returncode}]"
    except subprocess.TimeoutExpired:
        return f"error: command timed out after {timeout}s"
    except Exception as e:
        return f"error in {name}: {e}"
    return f"error: unknown tool {name}"


def evaluate_agent(base_model, adapter_dir=None, *, tier="legion-dev:qwen2.5-coder-1.5b",
                   temperature=0.2, max_new_tokens=1024, max_steps=6, exec_timeout=30.0,
                   load_4bit=True) -> AgentEvalReport:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    label = f"{base_model}+adapter" if adapter_dir else f"{base_model} (base)"
    rep = AgentEvalReport(model=label)

    tok = AutoTokenizer.from_pretrained(base_model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    kw = {"device_map": "auto"}
    if load_4bit and torch.cuda.is_available():
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16)
    else:
        kw["torch_dtype"] = torch.float16
    model = AutoModelForCausalLM.from_pretrained(base_model, **kw)
    if adapter_dir:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter_dir)
    model.eval()

    tasks = frozen_test_tasks()
    rep.n = len(tasks)
    for task in tasks:
        workdir = Path(tempfile.mkdtemp(prefix="legiondev-agent-"))
        (workdir / task.test_file).write_text(task.tests, encoding="utf-8")
        (workdir / task.solution_file).write_text(task.starter, encoding="utf-8")
        messages = [{"role": "system", "content": AGENT_SYSTEM},
                    {"role": "user", "content": _user(task)}]
        used_run, used_write, steps = False, False, 0
        try:
            for _ in range(max_steps):
                text = tok.apply_chat_template(messages, tools=AGENT_TOOLS, tokenize=False,
                                               add_generation_prompt=True)
                inputs = tok(text, return_tensors="pt").to(model.device)
                with torch.no_grad():
                    out = model.generate(**inputs, max_new_tokens=max_new_tokens,
                                         do_sample=temperature > 0, temperature=max(temperature, 1e-5),
                                         top_p=0.9, pad_token_id=tok.pad_token_id)
                gen = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
                steps += 1
                call = _parse_tool_call(gen)
                if not call:
                    break  # model returned prose -> it thinks it's done
                name, args = call
                used_run = used_run or name == "run_shell"
                used_write = used_write or name == "write_file"
                obs = _exec_tool(name, args, workdir, timeout=exec_timeout)
                messages.append({"role": "assistant", "content": "",
                                 "tool_calls": [{"type": "function", "function": {"name": name, "arguments": args}}]})
                messages.append({"role": "tool", "name": name, "content": obs})
        except Exception as e:
            rep.per_item.append({"task": task.name, "passed": False, "error": str(e)[:200]})
            _rmtree(workdir)
            continue

        final = (workdir / task.solution_file).read_text(encoding="utf-8") if (workdir / task.solution_file).exists() else ""
        graded = run_task(task, final, timeout=exec_timeout)
        rep.steps_total += steps
        rep.ran_tests += int(used_run)
        rep.wrote_file += int(used_write)
        if graded.passed:
            rep.passed += 1
        rep.per_item.append({"task": task.name, "passed": graded.passed,
                             "ran_tests": used_run, "wrote_file": used_write, "steps": steps})
        _rmtree(workdir)

    del model
    try:
        torch.cuda.empty_cache()
    except Exception:
        pass
    return rep


def _rmtree(p: Path) -> None:
    import shutil
    shutil.rmtree(p, ignore_errors=True)

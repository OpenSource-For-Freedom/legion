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
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .agent_contracts import AGENT_SYSTEM, AGENT_TOOL_NAMES, AGENT_TOOLS, PYTEST_CMD
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
        if name == "list_dir":
            rel = args.get("path", ".")
            d = (workdir / rel)
            if not d.exists():
                return f"error: {rel} does not exist"
            if d.is_file():
                return f"error: {rel} is a file, not a directory"
            entries = sorted(c.name + ("/" if c.is_dir() else "") for c in d.iterdir())
            return "\n".join(entries) if entries else "(empty)"
        if name == "edit_file":
            p = workdir / args["path"]
            if not p.exists():
                return f"error: {args['path']} does not exist"
            src = p.read_text(encoding="utf-8")
            find = args.get("find", "")
            n = src.count(find) if find else 0
            if n == 0:
                return f"error: `find` text not found in {args['path']}"
            if n > 1:
                return f"error: `find` matches {n} places in {args['path']}; make it unique"
            p.write_text(src.replace(find, args.get("replace", ""), 1), encoding="utf-8")
            return f"edited {args['path']} (1 replacement)"
        if name == "search":
            import re as _re
            root = workdir / args.get("path", ".")
            pat = args.get("pattern", "")
            flags = _re.IGNORECASE if args.get("ignore_case") else 0
            try:
                rx = _re.compile(pat if args.get("regex", True) else _re.escape(pat), flags)
            except _re.error as e:
                return f"error: bad regex: {e}"
            files = [root] if root.is_file() else [f for f in root.rglob("*") if f.is_file()]
            hits = []
            for f in files:
                try:
                    for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        if rx.search(line):
                            hits.append(f"{f.relative_to(workdir).as_posix()}:{i}: {line.strip()[:200]}")
                            if len(hits) >= 50:
                                break
                except Exception:
                    continue
                if len(hits) >= 50:
                    break
            return "\n".join(hits) if hits else "(no matches)"
        if name == "find_definition":
            import re as _re
            root = workdir / args.get("path", ".")
            sym = _re.escape(args.get("symbol", ""))
            if not sym:
                return "error: symbol is required"
            rx = _re.compile(rf"(?:^|\s)(?:def|class)\s+{sym}\b|^\s*{sym}\s*[:=]")
            files = [root] if root.is_file() else [f for f in root.rglob("*.py") if f.is_file()]
            for f in files:
                try:
                    for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        if rx.search(line):
                            return f"{f.relative_to(workdir).as_posix()}:{i}: {line.strip()[:200]}"
                except Exception:
                    continue
            return f"error: definition of {args.get('symbol', '')} not found"
        if name == "run_shell":
            cmd = args.get("command", "")
            argv = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"] if "pytest" in cmd \
                else cmd
            # Run with the PROJECT workspace on PYTHONPATH so `from mypkg import ...` resolves
            # to the files the agent wrote, exactly as the grader (executor.run_project) does —
            # not to whatever the parent training process had on its path. Without this, a
            # multi-file project's imports behave differently under the agent than at grading.
            _env = dict(os.environ)
            _env["PYTHONPATH"] = str(workdir)
            _env["PYTHONDONTWRITEBYTECODE"] = "1"
            proc = subprocess.run(argv, cwd=str(workdir), capture_output=True, encoding="utf-8",
                                  errors="replace", timeout=timeout, env=_env,
                                  shell=not isinstance(argv, list))
            out = ((proc.stdout or "") + (proc.stderr or "")).strip()[-3000:]
            return (out or "(no output)") + f"\n[exit {proc.returncode}]"
    except subprocess.TimeoutExpired:
        return f"error: command timed out after {timeout}s"
    except Exception as e:
        return f"error in {name}: {e}"
    return f"error: unknown tool {name}"


def verify_contract() -> list[str]:
    """Preflight guard: prove the agentic pieces speak ONE protocol, so a run cannot
    silently score 0 on a contract/executor/trajectory mismatch. Checks, behaviorally:
      1. every tool declared in AGENT_TOOLS is actually EXECUTABLE by this eval loop, and
      2. every tool the TRAJECTORIES teach exists in AGENT_TOOLS *and* is executable.
    Both are derived live (real _exec_tool calls + the real trajectory source), so they
    cannot drift from a hand-maintained list. Returns a list of problems ([] == in sync)."""
    import re as _re
    import shutil
    import tempfile
    from .agent_contracts import AGENT_TOOLS, AGENT_TOOL_NAMES

    # representative valid args for each declared tool (required fields satisfied)
    probe = {
        "read_file": {"path": "sample.py"},
        "list_dir": {"path": "."},
        "search": {"pattern": "foo"},
        "find_definition": {"symbol": "foo"},
        "edit_file": {"path": "sample.py", "find": "1", "replace": "2"},
        "write_file": {"path": "new.py", "content": "x = 1\n"},
        "run_shell": {"command": "echo ok"},
    }
    issues: list[str] = []
    executable: set[str] = set()
    wd = Path(tempfile.mkdtemp(prefix="legiondev-contract-"))
    try:
        (wd / "sample.py").write_text("foo = 1\n", encoding="utf-8")
        for t in AGENT_TOOLS:
            nm = t["function"]["name"]
            if nm not in probe:
                issues.append(f"tool '{nm}' is declared in AGENT_TOOLS but verify_contract has no probe args for it")
                continue
            obs = _exec_tool(nm, probe[nm], wd, timeout=15.0)
            if obs.startswith("error: unknown tool"):
                issues.append(f"tool '{nm}' is declared in AGENT_TOOLS but the eval loop cannot execute it")
            else:
                executable.add(nm)
    finally:
        shutil.rmtree(wd, ignore_errors=True)

    # trajectories may only teach tools that exist in the contract AND are executable
    traj_src = (Path(__file__).resolve().parent / "trajectory.py").read_text(encoding="utf-8")
    taught = set(_re.findall(r'_tc\(\s*["\']([a-z_]+)["\']', traj_src))
    for nm in sorted(taught - AGENT_TOOL_NAMES):
        issues.append(f"trajectory teaches '{nm}' which is not declared in AGENT_TOOLS")
    for nm in sorted((taught & AGENT_TOOL_NAMES) - executable):
        issues.append(f"trajectory teaches '{nm}' which the eval loop cannot execute")
    return issues


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
        used_run, used_write, steps, nudges = False, False, 0, 0
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
                    # VERIFY BEFORE FINISH. The doctrine is explicit: you are not done until
                    # the tests have actually RUN and passed. Models frequently NARRATE the
                    # call ("now I'll run pytest") or print the code in a fence, then stop —
                    # so they never see their own failure and never self-correct. A real
                    # harness (and a real user) would push back once, so we do too, instead
                    # of scoring an answer the agent never verified. One nudge only.
                    if not used_run and nudges < 1:
                        nudges += 1
                        messages.append({"role": "assistant", "content": gen[:600]})
                        messages.append({"role": "user", "content":
                                         "You have not run the tests yet, so you are not done. "
                                         "Do not describe the call or paste code — emit an actual "
                                         f"run_shell tool call with `{PYTEST_CMD}`, read the real "
                                         "output, and if anything fails, fix the code and run again."})
                        continue
                    break  # genuinely done (or already verified)
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


def evaluate_combined(base_model, adapter_dir=None, *, tier="legion-dev:qwen2.5-coder-3b",
                      **kw) -> "AgentEvalReport":
    """One gate over BOTH tiers: single-file agent tasks + multi-file PROJECT tasks. Merged into
    a single report so a fine-tune has to earn the project capability WITHOUT regressing the
    single-file skill (both are in the denominator — a model that gains projects but breaks
    single-file does not clear). Loads the model once per sub-eval, sequentially (frees between),
    which is fine on an 8 GB card."""
    a = evaluate_agent(base_model, adapter_dir, tier=tier)
    p = evaluate_project(base_model, adapter_dir, tier=tier)
    rep = AgentEvalReport(model=(a.model + " +projects"))
    rep.n = a.n + p.n
    rep.passed = a.passed + p.passed
    rep.ran_tests = a.ran_tests + p.ran_tests
    rep.wrote_file = a.wrote_file + p.wrote_file
    rep.steps_total = a.steps_total + p.steps_total
    rep.per_item = ([{"tier": "single", **d} for d in a.per_item]
                    + [{"tier": "project", **d} for d in p.per_item])
    return rep


def _project_user(task) -> str:
    files = "\n".join(f"  {p}" for p in sorted(task.starter)) or "  (none)"
    spec = "\n\n".join(f"# {p}\n{c}" for p, c in sorted(task.tests.items()))
    return (
        f"Build this project in the current directory, end to end.\n\n"
        f"TASK: {task.prompt}\n\n"
        f"Files already present (a partial scaffold you finish):\n{files}\n\n"
        f"The tests below are the SPEC — they are already in the project; do NOT modify them:\n"
        f"```python\n{spec}\n```\n\n"
        f"Survey with list_dir/read_file if useful, then create and wire the necessary files "
        f"with write_file/edit_file, run `{PYTEST_CMD}` with run_shell, read the output, and fix "
        f"until every test passes. When green, reply with a short summary and NO tool call."
    )


def evaluate_project(base_model, adapter_dir=None, *, tier="legion-dev:qwen2.5-coder-3b",
                     temperature=0.2, max_new_tokens=1024, max_steps=16, exec_timeout=60.0,
                     load_4bit=True, tasks=None) -> AgentEvalReport:
    """Agent eval on MULTI-FILE PROJECT tasks (project_tasks). The model must scaffold and wire
    several files and drive the suite to green — the end-to-end tier single-file eval can't
    measure. Graded by EXECUTION: the pristine tests are re-run over the agent's final files
    (executor.run_project), so a model can neither pass by editing the tests nor be judged on
    string similarity."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    from .executor import run_project
    from .project_tasks import project_test_tasks

    tasks = tasks if tasks is not None else project_test_tasks()
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

    rep.n = len(tasks)
    for task in tasks:
        workdir = Path(tempfile.mkdtemp(prefix="legiondev-proj-"))
        for rel, content in task.seed().items():          # starter scaffold + pristine tests
            fp = workdir / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
        messages = [{"role": "system", "content": AGENT_SYSTEM},
                    {"role": "user", "content": _project_user(task)}]
        used_run, used_write, steps, nudges = False, False, 0, 0
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
                    if not used_run and nudges < 1:       # verify-before-finish
                        nudges += 1
                        messages.append({"role": "assistant", "content": gen[:600]})
                        messages.append({"role": "user", "content":
                                         "You have not run the tests yet, so you are not done. Emit a real "
                                         f"run_shell tool call with `{PYTEST_CMD}`, read the output, and fix any "
                                         "failure — do not describe the command or paste code."})
                        continue
                    break
                name, args = call
                used_run = used_run or name == "run_shell"
                used_write = used_write or name in ("write_file", "edit_file")
                obs = _exec_tool(name, args, workdir, timeout=exec_timeout)
                messages.append({"role": "assistant", "content": "",
                                 "tool_calls": [{"type": "function",
                                                 "function": {"name": name, "arguments": args}}]})
                messages.append({"role": "tool", "name": name, "content": obs})
        except Exception as e:
            rep.per_item.append({"task": task.name, "passed": False, "error": str(e)[:200]})
            _rmtree(workdir)
            continue

        # Grade by execution over the FINAL workspace, with pristine tests (tamper-proof):
        # collect every non-test file the agent produced and re-run the real suite on it.
        final_files = {}
        for fp in workdir.rglob("*"):
            if fp.is_file():
                rel = fp.relative_to(workdir).as_posix()
                if rel in task.test_files or "__pycache__" in rel:
                    continue
                try:
                    final_files[rel] = fp.read_text(encoding="utf-8")
                except Exception:
                    pass
        graded = run_project(task, final_files, timeout=exec_timeout)
        rep.steps_total += steps
        rep.ran_tests += int(used_run)
        rep.wrote_file += int(used_write)
        if graded.passed:
            rep.passed += 1
        rep.per_item.append({"task": task.name, "passed": graded.passed, "ran_tests": used_run,
                             "wrote_file": used_write, "steps": steps, "files": len(final_files)})
        _rmtree(workdir)

    del model
    try:
        torch.cuda.empty_cache()
    except Exception:
        pass
    return rep

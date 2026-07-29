"""Execution-verified AGENTIC trajectories.

Each trajectory is a multi-turn tool-use conversation whose tool results are REAL
(produced by the sandbox executor) and which is kept only if it ends in passing
tests — the same execution gate as the single-file track, now applied to tool-use
behavior. Two shapes:

  gold : write(reference) -> run_shell(pytest) -> PASS -> summary
  fix  : write(wrong) -> run(FAIL) -> read the failure -> write(reference) -> run -> PASS

`fix` teaches the behavior the served fine-tunes are missing: read a failing test
result and iterate instead of stopping. The "wrong" first attempt is grounded —
the task's own starter (buggy/stub, fails by construction) offline, or a rejected
teacher sample (a real model error) when available.
"""

from __future__ import annotations

from .agent_contracts import AGENT_SYSTEM, PYTEST_CMD
from .executor import run_project, run_task


def _tc(name, args):
    return {"type": "function", "function": {"name": name, "arguments": args}}


def _user(task) -> str:
    return (
        f"{task.prompt}\n\n"
        f"FILE `{task.solution_file}` (fix it):\n```python\n{task.starter.strip()}\n```\n\n"
        f"TESTS `{task.test_file}` (do not modify):\n```python\n{task.tests.strip()}\n```\n\n"
        f"Write the corrected `{task.solution_file}` with write_file, then run the "
        f"tests with run_shell(\"{PYTEST_CMD}\"). If they fail, read the output, fix the "
        f"file, and run again until every test passes."
    )


def _pytest_term(task, code: str) -> tuple[bool, str]:
    """Run the task's tests against `code`; return (passed, terminal-style output)
    exactly as run_shell would surface it to the model."""
    res = run_task(task, code)
    body = res.output.strip()
    if not body:
        body = "" if res.passed else "(no output)"
    return res.passed, (body + f"\n[exit {0 if res.passed else 1}]").strip()


def _wrote(task, code: str) -> dict:
    return {"role": "tool", "name": "write_file",
            "content": f"wrote {len(code)} bytes to {task.solution_file}"}


def gold_trajectory(task) -> dict | None:
    """write(reference) -> run -> PASS -> summary. Kept only if the reference
    actually passes (it always should; a failure means a broken task)."""
    passed, term = _pytest_term(task, task.reference)
    if not passed:
        return None
    msgs = [
        {"role": "system", "content": AGENT_SYSTEM},
        {"role": "user", "content": _user(task)},
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("write_file", {"path": task.solution_file, "content": task.reference})]},
        _wrote(task, task.reference),
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("run_shell", {"command": PYTEST_CMD})]},
        {"role": "tool", "name": "run_shell", "content": term},
        {"role": "assistant", "content":
            f"All tests pass. `{task.solution_file}` is implemented and pytest is green."},
    ]
    return {"messages": msgs, "meta": {"task": task.name, "kind": "gold"}}


def fix_trajectory(task, wrong_code: str) -> dict | None:
    """write(wrong) -> run(FAIL) -> fix with reference -> run(PASS) -> summary.
    Kept only if `wrong_code` really fails and the reference really passes."""
    if wrong_code.strip() == task.reference.strip():
        return None
    wrong_passed, wrong_term = _pytest_term(task, wrong_code)
    if wrong_passed:
        return None  # a "wrong" attempt that passes is not a fix trajectory
    ref_passed, ref_term = _pytest_term(task, task.reference)
    if not ref_passed:
        return None
    msgs = [
        {"role": "system", "content": AGENT_SYSTEM},
        {"role": "user", "content": _user(task)},
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("write_file", {"path": task.solution_file, "content": wrong_code})]},
        _wrote(task, wrong_code),
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("run_shell", {"command": PYTEST_CMD})]},
        {"role": "tool", "name": "run_shell", "content": wrong_term},
        {"role": "assistant",
         "content": "The tests fail. I will read the failure and correct the implementation.",
         "tool_calls": [_tc("write_file", {"path": task.solution_file, "content": task.reference})]},
        _wrote(task, task.reference),
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("run_shell", {"command": PYTEST_CMD})]},
        {"role": "tool", "name": "run_shell", "content": ref_term},
        {"role": "assistant", "content":
            f"Fixed. `{task.solution_file}` now passes every test."},
    ]
    return {"messages": msgs, "meta": {"task": task.name, "kind": "fix"}}


def _user_lean(task) -> str:
    """A task-only prompt (no inline file dump) so the trajectory must DISCOVER the
    code with tools — the full-agent, understand-first behavior."""
    return (
        f"{task.prompt}\n\n"
        f"Fix `{task.solution_file}` so its tests in `{task.test_file}` pass. Explore "
        f"the project with your tools to see the current code, make the change, then "
        f"run `{PYTEST_CMD}` to verify."
    )


def _listed(task) -> dict:
    files = sorted({task.solution_file, task.test_file})
    return {"role": "tool", "name": "list_dir", "content": "\n".join("file " + f for f in files)}


def explore_fix_trajectory(task) -> dict | None:
    """understand-first: list_dir -> read_file(current) -> write(reference) ->
    run(PASS) -> summary. Teaches the doctrine's explore-before-edit + verify loop
    using the full agent's read/nav tools. Kept only if the reference passes."""
    ref_passed, ref_term = _pytest_term(task, task.reference)
    if not ref_passed:
        return None
    msgs = [
        {"role": "system", "content": AGENT_SYSTEM},
        {"role": "user", "content": _user_lean(task)},
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("list_dir", {"path": "."})]},
        _listed(task),
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("read_file", {"path": task.solution_file})]},
        {"role": "tool", "name": "read_file", "content": task.starter},
        {"role": "assistant",
         "content": f"I've read `{task.solution_file}` and see what needs to change. Implementing the fix.",
         "tool_calls": [_tc("write_file", {"path": task.solution_file, "content": task.reference})]},
        _wrote(task, task.reference),
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("run_shell", {"command": PYTEST_CMD})]},
        {"role": "tool", "name": "run_shell", "content": ref_term},
        {"role": "assistant", "content":
            f"All tests pass. `{task.solution_file}` is implemented and verified with pytest."},
    ]
    return {"messages": msgs, "meta": {"task": task.name, "kind": "explore_fix"}}


def trajectories_for_task(task, *, wrong_samples: list[str] | None = None) -> list[dict]:
    """All execution-verified trajectories for a task: the gold path, an
    understand-first explore-then-fix path, a fix path from the task's own starter
    (offline, a real failure), and a fix path per supplied `wrong_sample`."""
    out: list[dict] = []
    g = gold_trajectory(task)
    if g:
        out.append(g)
    e = explore_fix_trajectory(task)
    if e:
        out.append(e)
    seen_wrong = set()
    for wrong in [task.starter, *(wrong_samples or [])]:
        key = " ".join((wrong or "").split())
        if not key or key in seen_wrong:
            continue
        seen_wrong.add(key)
        f = fix_trajectory(task, wrong)
        if f:
            out.append(f)
    return out


# =============================================================================================
# PROJECT trajectories — multi-file, end-to-end. Same execution gate (kept only if the tests
# actually pass), same tool surface, but the model learns to scaffold + wire SEVERAL files and
# drive the suite green, which is the behavior single-file trajectories can't teach.
# =============================================================================================

def _project_user_traj(task) -> str:
    files = "\n".join(f"  {p}" for p in sorted(task.starter)) or "  (none)"
    spec = "\n\n".join(f"# {p}\n{c}" for p, c in sorted(task.tests.items()))
    return (
        f"Build this project in the current directory, end to end.\n\n"
        f"TASK: {task.prompt}\n\n"
        f"Files already present (a partial scaffold you finish):\n{files}\n\n"
        f"The tests below are the SPEC — already in the project; do NOT modify them:\n"
        f"```python\n{spec}\n```\n\n"
        f"Create and wire the necessary files with write_file, run `{PYTEST_CMD}` with run_shell, "
        f"read the output, and fix until every test passes."
    )


def _files_in_build_order(files: dict) -> list[str]:
    """Implementation modules first, package __init__ last — the natural order to build a
    package so its re-exports resolve once the modules exist."""
    return sorted(files, key=lambda p: (p.endswith("__init__.py"), p))


def _wrote_path(path: str, content: str) -> dict:
    return {"role": "tool", "name": "write_file",
            "content": f"wrote {len(content)} bytes to {path}"}


def _project_term(task, files: dict) -> tuple[bool, str]:
    res = run_project(task, files)
    body = (res.output or "").strip() or ("" if res.passed else "(no output)")
    return res.passed, (body + f"\n[exit {0 if res.passed else 1}]").strip()


def project_gold_trajectory(task) -> dict | None:
    """write each file(reference) -> run_shell(pytest) -> PASS -> summary. Kept only if the
    reference actually passes as a whole project."""
    passed, term = _project_term(task, task.reference)
    if not passed:
        return None
    msgs = [{"role": "system", "content": AGENT_SYSTEM},
            {"role": "user", "content": _project_user_traj(task)}]
    for path in _files_in_build_order(task.reference):
        content = task.reference[path]
        msgs.append({"role": "assistant", "content": "",
                     "tool_calls": [_tc("write_file", {"path": path, "content": content})]})
        msgs.append(_wrote_path(path, content))
    msgs.append({"role": "assistant", "content": "",
                 "tool_calls": [_tc("run_shell", {"command": PYTEST_CMD})]})
    msgs.append({"role": "tool", "name": "run_shell", "content": term})
    msgs.append({"role": "assistant", "content":
                 f"All tests pass. The `{task.name}` project is implemented across "
                 f"{len(task.reference)} files and pytest is green."})
    return {"messages": msgs, "meta": {"task": task.name, "kind": "project_gold"}}


def project_fix_trajectory(task) -> dict | None:
    """run(the stub scaffold, FAIL) -> read the failure -> implement every file -> run -> PASS.
    Teaches the real loop: run first to see what's missing, build it, verify. Kept only if the
    starter genuinely fails and the reference genuinely passes."""
    starter_passed, fail_term = _project_term(task, task.starter)
    ref_passed, pass_term = _project_term(task, task.reference)
    if starter_passed or not ref_passed:
        return None
    msgs = [{"role": "system", "content": AGENT_SYSTEM},
            {"role": "user", "content": _project_user_traj(task)},
            {"role": "assistant", "content": "",
             "tool_calls": [_tc("run_shell", {"command": PYTEST_CMD})]},
            {"role": "tool", "name": "run_shell", "content": fail_term},
            {"role": "assistant", "content":
             "The scaffold does not pass yet. I'll implement the modules the tests require."}]
    for path in _files_in_build_order(task.reference):
        content = task.reference[path]
        msgs.append({"role": "assistant", "content": "",
                     "tool_calls": [_tc("write_file", {"path": path, "content": content})]})
        msgs.append(_wrote_path(path, content))
    msgs.append({"role": "assistant", "content": "",
                 "tool_calls": [_tc("run_shell", {"command": PYTEST_CMD})]})
    msgs.append({"role": "tool", "name": "run_shell", "content": pass_term})
    msgs.append({"role": "assistant", "content":
                 f"All tests pass now. The `{task.name}` project is complete and verified."})
    return {"messages": msgs, "meta": {"task": task.name, "kind": "project_fix"}}


def project_trajectories_for_task(task) -> list[dict]:
    """Both execution-verified project shapes for a multi-file task."""
    out: list[dict] = []
    for fn in (project_gold_trajectory, project_fix_trajectory):
        t = fn(task)
        if t:
            out.append(t)
    return out

"""Contract for the AGENTIC (tool-use) track.

The single-file track (contracts.py) trains Legion Dev to emit one corrected
file. That produces a good code-*writer* but not a tool-loop *driver*: served in
the Studio, the fine-tunes do the first write_file and then narrate the run step
instead of calling run_shell. This track trains the missing behavior — DRIVE the
loop: write_file -> run_shell(pytest) -> read the result -> fix -> run again ->
stop with a summary once the tests pass.

Train/serve format parity: trajectories use assistant `tool_calls` + role:"tool"
results, which the Qwen chat template renders as <tool_call>/<tool_response> —
exactly what the Studio + Ollama exchange at serve time.
"""

from __future__ import annotations


def _sec_prefix() -> str:
    """Security-first context from the CENTRAL training config, prepended to the
    agent persona so it trains security-first. Degrades to '' if unavailable."""
    try:
        try:
            import legion_training
        except ImportError:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # legion/training
            import legion_training
        return legion_training.security_prefix() + "\n\n"
    except Exception:
        return ""


PYTEST_CMD = "pytest -q"

# Static system prompt for training. Mirrors the Studio's serve-time system prompt
# intent (backend/config.py system_prompt): confined tool agent, one call per turn,
# iterate until green. Train-time and serve-time must stay aligned.
AGENT_SYSTEM = _sec_prefix() + (
    "You are Legion Dev, an all-capable local coding agent on the user's machine. "
    "You fix and implement code inside the user's project using tools. Work step by "
    "step: call ONE tool per turn and wait for its result before the next. "
    "Understand before you change: use list_dir, read_file, search, or find_definition "
    "to see the current code, then edit it (edit_file for a small surgical change, "
    "write_file for a new file or full rewrite), then run_shell to run the tests "
    f"(`{PYTEST_CMD}`), read the output, and if any test fails, fix and run again. "
    "Keep going until every test passes, then reply with a short summary and NO tool "
    "call. Work like a senior developer: fix the actual cause of "
    "the failure, not the symptom (no bare try/except, sleep, or hardcoded value to "
    "force a pass); change only what is needed and match the file's existing style; "
    "do not invent libraries or APIs that are not available. Keep the public names "
    "the tests import; do not modify or restate the tests; never hardcode a secret "
    "(read it from the environment)."
)

# Tool schema — mirrors the Studio's core code tools (legiondev-studio/backend/
# tools.py) so training transfers to serving verbatim. This is the full-agent
# surface the coder drives: understand (list_dir/read_file/search/find_definition),
# edit (edit_file/write_file), verify (run_shell). The Studio adds more (web, git,
# skills, editor) that this pytest-loop track doesn't exercise.
AGENT_TOOLS = [
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read and return the contents of a text file.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "list_dir",
        "description": "List the entries of a directory (one level).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "search",
        "description": "Search code with a regex across files under a path (pass regex=false for a literal string).",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "path": {"type": "string"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "find_definition",
        "description": "Find where a function/class/variable is defined (go-to-definition).",
        "parameters": {"type": "object", "properties": {
            "symbol": {"type": "string"}, "path": {"type": "string"}}, "required": ["symbol"]}}},
    {"type": "function", "function": {
        "name": "edit_file",
        "description": "Replace exactly one unique occurrence of `find` with `replace` in a file (surgical edit).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "find": {"type": "string"}, "replace": {"type": "string"}},
            "required": ["path", "find", "replace"]}}},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "Write (create or overwrite) a text file with the given content.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "file path, relative to the project"},
            "content": {"type": "string", "description": "full file contents"}},
            "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "run_shell",
        "description": "Run a shell command in the project and return its stdout, stderr and exit code. Use it to run the tests.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "the command to run, e.g. pytest -q"}},
            "required": ["command"]}}},
]

AGENT_TOOL_NAMES = {t["function"]["name"] for t in AGENT_TOOLS}


def verify_serve_parity(studio_dir: str | None = None) -> list[str]:
    """Assert the tools trained here are a subset of what Legion Studio SERVES, with
    compatible schemas — so a model trained in this repo actually works when the Studio
    drives it (and when it is published for the Studio to pull). Reads the Studio's
    `backend/tools.py` TOOL_DEFS via `ast` (no import/exec of Studio code). Best-effort:
    returns [] if in sync OR if the Studio isn't present in this environment (skipped);
    otherwise a list of the drifts to fix. Set LEGION_STUDIO_DIR to override the path."""
    import ast
    import os
    from pathlib import Path
    root = studio_dir or os.environ.get("LEGION_STUDIO_DIR", r"F:\dev\legiondev-studio")
    tools_py = Path(root) / "backend" / "tools.py"
    if not tools_py.exists():
        return []  # Studio not on this box — nothing to compare, not a failure
    try:
        tree = ast.parse(tools_py.read_text(encoding="utf-8"))
        served = next((ast.literal_eval(n.value) for n in tree.body
                       if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "TOOL_DEFS" for t in n.targets)), None)
    except Exception as e:
        return [f"could not read Legion Studio TOOL_DEFS ({tools_py}): {e}"]
    if served is None:
        return [f"Legion Studio {tools_py} has no TOOL_DEFS list to compare against"]
    served_req = {t["name"]: set((t.get("parameters") or {}).get("required", [])) for t in served}
    issues: list[str] = []
    for t in AGENT_TOOLS:
        fn = t["function"]
        nm = fn["name"]
        if nm not in served_req:
            issues.append(f"trained tool '{nm}' is NOT served by Legion Studio "
                          f"(add it to backend/tools.py TOOL_DEFS, or drop it from AGENT_TOOLS)")
            continue
        train_req = set((fn.get("parameters") or {}).get("required", []))
        missing = served_req[nm] - train_req
        if missing:
            issues.append(f"tool '{nm}': Studio requires {sorted(served_req[nm])} but training only teaches "
                          f"required {sorted(train_req)} — the model may omit {sorted(missing)} at serve time")
    return issues


# ============================================================================
# FULL-SDLC agentic track (research -> design -> plan -> build -> test ->
# review -> ship). Trains the model to DRIVE the studio's Ship pipeline. The
# discipline is the SDLC skill FROM THE STUDIO (single source of truth), and the
# tool surface mirrors legiondev-studio Ship mode — so train == serve. Kept
# separate from the pytest-loop contract above so neither track disturbs the other.
# ============================================================================

from . import skills as _studio_skills  # noqa: E402

_SDLC_SKILL = _studio_skills.load_skill("sdlc")
_SKILL_CATALOG = _studio_skills.catalog()

AGENT_SYSTEM_SDLC = _sec_prefix() + (
    "You are Legion Dev, an all-capable local coding agent. Deliver the task END TO "
    "END through the full software lifecycle, calling ONE tool per turn and acting "
    "(never just describing). Follow this operating contract exactly:\n\n"
    + (_SDLC_SKILL or
       "research -> design -> plan -> build -> test -> review -> ship; complete each "
       "phase by calling its tool; never ship on red tests or without a review.")
    + ("\n\nKnowledge skills you can load with use_skill(name) before the work they "
       "cover (e.g. use_skill('code-review') in the REVIEW phase):\n" + _SKILL_CATALOG
       if _SKILL_CATALOG else "")
)

# SDLC tool surface = the studio Ship tools + core code tools + research/skill tools.
AGENT_TOOLS_SDLC = AGENT_TOOLS + [
    {"type": "function", "function": {
        "name": "research",
        "description": "RESEARCH phase — after surveying the codebase and researching the domain/libraries/best-practices, record findings.",
        "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}}},
    {"type": "function", "function": {
        "name": "design",
        "description": "DESIGN phase — record requirements, acceptance criteria, and the technical approach.",
        "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}}},
    {"type": "function", "function": {
        "name": "set_plan",
        "description": "PLAN phase — the agile sprint backlog: ordered, concrete build tasks.",
        "parameters": {"type": "object", "properties": {"steps": {"type": "array", "items": {"type": "string"}}}, "required": ["steps"]}}},
    {"type": "function", "function": {
        "name": "check_step",
        "description": "Tick off a finished build task by its 0-based index.",
        "parameters": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}}},
    {"type": "function", "function": {
        "name": "run_tests",
        "description": "TEST gate — run the project's tests/build. Records green/red; deploy is blocked until green.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "review",
        "description": "REVIEW gate — code-review the diff (load use_skill('code-review')), then record findings + how they were addressed.",
        "parameters": {"type": "object", "properties": {"findings": {"type": "string"}}, "required": ["findings"]}}},
    {"type": "function", "function": {
        "name": "deploy",
        "description": "SHIP gate — deploy to production. Only works after green tests AND a review AND the user confirms.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "use_skill",
        "description": "Load a knowledge skill's full guidance into context before the work it covers (e.g. use_skill('code-review')).",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "web_search",
        "description": "Search the web (RESEARCH phase) and return top results.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "web_fetch",
        "description": "Fetch a web page/API by URL and return its readable text (RESEARCH phase).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
]

AGENT_TOOL_NAMES_SDLC = {t["function"]["name"] for t in AGENT_TOOLS_SDLC}

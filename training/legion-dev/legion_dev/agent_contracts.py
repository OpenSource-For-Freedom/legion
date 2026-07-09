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

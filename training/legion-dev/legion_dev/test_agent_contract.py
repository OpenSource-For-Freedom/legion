"""Contract-parity tests — the 'work together each time' guardrails.

The agentic protocol must be coherent across all three surfaces:
  train (agent_contracts + trajectory)  ->  eval (evaluate_agent._exec_tool)  ->
  serve (legiondev-studio backend/tools.py TOOL_DEFS)  ->  deploy (publish.py).

These run in CI (pytest) and as a fail-fast preflight inside iterate_agent, so a
model can never silently score 0 (or be un-drivable when served) on a protocol drift.
"""
from legion_dev.agent_contracts import AGENT_TOOL_NAMES, verify_serve_parity
from legion_dev.evaluate_agent import verify_contract


def test_train_internal_contract_in_sync():
    # every declared tool is executable by the eval loop, and trajectories only teach
    # tools that exist in the contract and are executable.
    issues = verify_contract()
    assert issues == [], "train contract/executor/trajectory drift:\n  " + "\n  ".join(issues)


def test_trained_tools_served_by_studio():
    # every tool trained here is served by Legion Studio with a compatible schema.
    # Skips cleanly (returns []) if the Studio repo is not present in this environment.
    issues = verify_serve_parity()
    assert issues == [], "train<->serve drift:\n  " + "\n  ".join(issues)


def test_core_tools_present():
    # guard against a core tool being accidentally dropped from the contract.
    for t in ("read_file", "write_file", "edit_file", "list_dir", "search",
              "find_definition", "run_shell"):
        assert t in AGENT_TOOL_NAMES, f"core tool '{t}' missing from AGENT_TOOLS"

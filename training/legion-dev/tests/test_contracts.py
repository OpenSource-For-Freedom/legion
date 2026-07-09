from legion_dev.contracts import (BLOCKED_TAGS, DEFAULT_TIER, GATES, REPO, TIERS,
                                  SYNTHESIS_SYSTEM, is_blocked)


def test_repo_targets_legion_dev():
    assert REPO == "tburns-actual/legion_dev"


def test_tiers_are_coder_models():
    assert DEFAULT_TIER in TIERS
    for name, spec in TIERS.items():
        assert name.startswith("legion-dev:")
        assert "coder" in spec["hf_base"].lower()


def test_deepseek_blocked():
    assert "deepseek" in BLOCKED_TAGS
    assert is_blocked("legion-dev:deepseek-coder-6.7b")
    assert not is_blocked(DEFAULT_TIER)


def test_gate_is_execution_pass_rate():
    assert "pass_rate_min" in GATES
    assert 0.0 < GATES["pass_rate_min"] <= 1.0


def test_system_prompt_demands_a_fenced_file():
    assert "```python" in SYNTHESIS_SYSTEM
    assert "tests" in SYNTHESIS_SYSTEM.lower()

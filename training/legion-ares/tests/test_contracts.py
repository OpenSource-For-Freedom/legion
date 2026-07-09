from ares_train.contracts import (DEFAULT_TIER, GATES, TIERS, is_blocked, posture_for)


def test_posture_thresholds_match_rust():
    assert posture_for(0.80) == "CRITICAL"
    assert posture_for(0.75) == "CRITICAL"
    assert posture_for(0.74) == "ELEVATED"
    assert posture_for(0.45) == "ELEVATED"
    assert posture_for(0.44) == "WATCH"
    assert posture_for(0.20) == "WATCH"
    assert posture_for(0.19) == "BASELINE"


def test_blocked_policy_resists_rename():
    assert is_blocked("deepseek")
    assert is_blocked("DeepSeek-R1")
    assert is_blocked("d-e-e-p-s-e-e-k")
    assert not is_blocked("legion-ares:qwen3-4b")


def test_tier_table_and_defaults():
    assert DEFAULT_TIER in TIERS
    for spec in TIERS.values():
        assert spec["hf_base"].startswith("Qwen/Qwen3")
        assert spec["num_ctx"] >= 2048


def test_gates_match_model_card():
    assert GATES["invented_indicators_max"] == 0
    assert GATES["grounding_min"] == 0.95
    assert GATES["format_min"] == 0.98
    assert GATES["citation_coverage_min"] == 0.80
    assert GATES["anti_parrot_min"] == 0.90

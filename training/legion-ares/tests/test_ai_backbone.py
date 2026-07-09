"""CLLMSP backbone coverage: the AI/LLM-security domain is present and on the ai platform."""
from ares_train.scenarios import build_catalog
from ares_train.scenarios_ai import AI_BUILDERS


def test_cllmsp_domain_present():
    names = {b.scenario for b in build_catalog(1)}
    expected = {
        "ai_prompt_injection_indirect", "ai_jailbreak_attempt", "ai_insecure_output",
        "ai_data_poisoning", "ai_model_dos", "ai_model_integrity", "ai_malicious_sdk",
        "ai_sensitive_disclosure", "ai_excessive_agency", "ai_mcp_tool_poisoning",
        "ai_mcp_rug_pull", "ai_vector_db_poisoning", "ai_shadow_ai", "ai_model_theft",
    }
    assert expected <= names
    assert len(AI_BUILDERS) == 14


def test_ai_scenarios_tagged_ai_platform():
    ai = [b for b in build_catalog(1) if b.scenario.startswith("ai_")]
    assert ai and all(b.platform == "ai" for b in ai)
    assert all(b.platform_disp == "AI/LLM stack" for b in ai)


def test_other_domains_intact():
    names = {b.scenario for b in build_catalog(1)}
    # dual-OS + package + specialty must remain alongside the AI backbone
    for s in ("linux_kernel_rootkit", "windows_lsass_dump", "npm_supply_chain",
              "pip_supply_chain", "c2_beacon", "data_exfil_dns", "cred_harvest_files"):
        assert s in names

from ares_train.evidence import EvidenceBundle, Finding
from ares_train.scenarios import build_catalog


def test_render_has_platform_and_posture():
    b = EvidenceBundle(scenario="npm_supply_chain", score=0.50, platform="linux", findings=[
        Finding("ACTIVE ALERTS (critical/high)", "High",
                "npm postinstall script executed - node_modules/evil-pkg/install.js",
                ["node_modules/evil-pkg/install.js", "evil-pkg"]),
        Finding("RULE HITS", "High", "dev DEV-04 - postinstall touches process.env", ["DEV-04"]),
    ])
    text = b.render()
    assert text.startswith("Platform: Linux.")
    assert "Local posture: ELEVATED (score 0.50)." in text
    assert "CONFIRMED FINDINGS:" in text
    assert text.index("ACTIVE ALERTS") < text.index("RULE HITS")


def test_clean_bundle_render():
    b = EvidenceBundle(scenario="clean_windows", score=0.05, platform="windows", clean=True,
                       note="checked: alerts")
    text = b.render()
    assert "Platform: Windows." in text
    assert "BASELINE" in text and "Baseline is clean" in text


def test_lead_and_top_findings():
    b = EvidenceBundle(scenario="x", score=0.6, findings=[
        Finding("RULE HITS", "Critical", "a", ["SYS-10"]),
        Finding("LOCAL EVENTS", "Medium", "b", ["x.log"]),
    ])
    assert b.all_indicators() == {"SYS-10", "x.log"}
    assert [f.severity for f in b.top_findings()] == ["Critical"]
    assert len(b.lead_findings(2)) == 2


def test_catalog_deterministic_and_covers_os_and_specialty():
    a = build_catalog(3)
    assert [x.scenario for x in a] == [x.scenario for x in build_catalog(3)]
    names = {x.scenario for x in a}
    # OS coverage
    for s in ("linux_kernel_rootkit", "linux_systemd_persistence", "windows_lsass_dump",
              "windows_registry_runkey", "clean_linux", "clean_windows"):
        assert s in names
    # specialty skill set: C2 / exfil / obfuscation / credential harvesting
    for s in ("c2_beacon", "malware_outreach", "data_exfil_dns", "data_exfil_cloud",
              "cred_harvest_files", "cred_harvest_browser", "obfuscated_loader"):
        assert s in names
    # guardrails (4 classes)
    for s in ("prompt_injection_linux", "prompt_injection_windows", "code_request",
              "identity_spoof", "destructive_action"):
        assert s in names
    # both platforms represented
    plats = {x.platform for x in a}
    assert "linux" in plats and "windows" in plats


def test_platform_disp():
    assert EvidenceBundle("x", 0.5, "linux").platform_disp == "Linux"
    assert EvidenceBundle("x", 0.5, "windows").platform_disp == "Windows"
    assert EvidenceBundle("x", 0.5, "cross").platform_disp == "Windows/Linux"

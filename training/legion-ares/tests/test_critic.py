from ares_train.critic import accept, grade
from ares_train.evidence import EvidenceBundle, Finding


def _bundle():
    return EvidenceBundle(scenario="malicious_peer", score=0.58, findings=[
        Finding("ACTIVE ALERTS (critical/high)", "High",
                "outbound connection to AbuseIPDB-listed host 185.220.101.47:443", ["185.220.101.47"]),
        Finding("RULE HITS", "High",
                "system SYS-05 - connection to blacklisted IP 185.220.101.47", ["185.220.101.47", "SYS-05"]),
    ], mitre=["T1071"])


def test_critic_accepts_grounded_plaintext():
    b = _bundle()
    ans = ("The host is elevated because it is beaconing to AbuseIPDB-listed 185.220.101.47, "
           "which SYS-05 flags as a blacklisted destination. Pull the host off the network and "
           "capture the owning process for evidence.")
    v = grade(ans, b)
    assert v.accepted and v.metrics["invented"] == 0.0 and accept(ans, b)


def test_critic_rejects_invented_and_markdown():
    v = grade("- Beacon to 9.9.9.9 detected\n- **Action:** block it", _bundle())
    assert not v.accepted
    assert any("invented" in r or "format" in r for r in v.reasons)

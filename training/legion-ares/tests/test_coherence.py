"""Lock the coherence/degeneracy gate: the exact failure modes that shipped once
(broken chat template -> evidence-echo + repetition loops) must be REJECTED, and
clean prose syntheses must still pass."""
from ares_train.score import coherence_flags, score_answer
from ares_train.scenarios import c2_beacon, clean_linux, windows_service_persistence


def test_repetition_loop_rejected():
    b = c2_beacon(0)
    loop = ("The answer is 7036. This is the event id for a new service. " * 8)
    assert coherence_flags(loop), "repetition loop should flag"
    assert not score_answer(loop, b).passed


def test_evidence_echo_rejected():
    b = windows_service_persistence(0)
    echo = ("CONFIRMED FINDINGS: ACTIVE ALERTS (critical/high): [High] new service "
            "UpdaterSvc installed RULE HITS: [High] system SYS-07 service installed. "
            "Local posture: ELEVATED (score 0.62).")
    flags = coherence_flags(echo)
    assert "echoes evidence format" in flags
    assert not score_answer(echo, b).passed


def test_thinking_leak_rejected():
    b = c2_beacon(0)
    leaked = ("<think> the user wants a summary, let me think about the beacon </think> "
              "The host beacons to 185.220.101.47 flagged by SYS-02; isolate it.")
    assert "thinking leaked" in coherence_flags(leaked)
    assert not score_answer(leaked, b).passed


def test_good_synthesis_has_no_coherence_flags():
    b = c2_beacon(0)
    good = ("The host is critical because it beacons to 185.220.101.47 on a fixed cadence, "
            "which SYS-02 flags as a new outbound connection to a malicious peer. That "
            "periodic C2 channel is the finding that matters most. Pull the host off the "
            "network and capture the owning process before remediating.")
    assert coherence_flags(good) == []
    assert score_answer(good, b).passed, score_answer(good, b).reasons


def test_clean_baseline_prose_not_flagged():
    # "no confirmed findings" is prose, not the evidence header -> must not trip echo
    b = clean_linux(0)
    ans = ("The Linux host reads baseline and nothing alarming surfaced. I reviewed alerts, "
           "rule hits, YARA, OSV, and baseline drift and found no confirmed findings. There "
           "is no single finding to prioritize; keep the baseline current so drift stands out.")
    assert coherence_flags(ans) == []
    assert score_answer(ans, b).passed, score_answer(ans, b).reasons

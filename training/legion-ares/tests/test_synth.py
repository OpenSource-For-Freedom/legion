import pytest

from ares_train.dataset import instruction_for
from ares_train.scenarios import BUILDERS, build_catalog
from ares_train.score import score_answer
from ares_train.synth import synthesize, template_gold

CATALOG = build_catalog(8)


@pytest.mark.parametrize("idx", range(len(CATALOG)))
def test_template_gold_clears_gate(idx):
    bundle = CATALOG[idx]
    instr = instruction_for(bundle, idx)
    ans = template_gold(bundle, instr)
    res = score_answer(ans, bundle)
    assert res.passed, f"{bundle.scenario}#{idx}: {res.reasons}\n{ans}"


def test_synthesize_template_backend_passes_all_scenarios():
    seen = set()
    for idx, bundle in enumerate(CATALOG):
        cand = synthesize(bundle, instruction_for(bundle, idx), backend="template")
        assert cand.passed, f"{bundle.scenario}: {cand.reasons}"
        seen.add(bundle.scenario)
    assert len(seen) == len(BUILDERS)


def test_template_gold_plaintext_and_concise():
    for idx, bundle in enumerate(CATALOG[: len(BUILDERS)]):
        ans = template_gold(bundle, instruction_for(bundle, idx))
        assert "```" not in ans and "\n- " not in ans
        assert ans.count(". ") <= 8

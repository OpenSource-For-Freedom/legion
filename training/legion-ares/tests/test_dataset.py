from ares_train.dataset import (bundle_from_dict, bundle_to_dict, frozen_test_pairs,
                                read_jsonl, build_dataset, _split_catalog)
from ares_train.scenarios import BUILDERS, build_catalog

N_SCEN = len(BUILDERS)


def test_frozen_test_held_out_from_train():
    train, test = _split_catalog(8)
    catalog = build_catalog(8)
    n_scen = len(catalog) // 8
    assert len(test) == n_scen == N_SCEN
    assert len(train) == len(catalog) - n_scen


def test_frozen_test_pairs_stable():
    a = [(b.scenario, i) for b, i in frozen_test_pairs(8)]
    assert a == [(b.scenario, i) for b, i in frozen_test_pairs(8)]
    assert len(a) == N_SCEN


def test_bundle_dict_roundtrip():
    for bundle in build_catalog(2):
        back = bundle_from_dict(bundle_to_dict(bundle))
        assert back.render() == bundle.render()
        assert back.all_indicators() == bundle.all_indicators()
        assert back.platform == bundle.platform


def test_build_dataset_template_backend(tmp_path):
    stats = build_dataset(tmp_path, n_per=4, teacher_backend="template")
    assert stats.accepted > 0 and stats.rejected == 0
    assert stats.train + stats.val == stats.accepted - stats.deduped
    assert stats.test == N_SCEN
    train = read_jsonl(tmp_path / "train.jsonl")
    assert train
    assert [m["role"] for m in train[0]["messages"]] == ["system", "user", "assistant"]
    assert "CONFIRMED FINDINGS:" in train[0]["messages"][1]["content"]


def test_build_dataset_instructions_per(tmp_path):
    s1 = build_dataset(tmp_path / "a", n_per=4, instructions_per=1, teacher_backend="template")
    s3 = build_dataset(tmp_path / "b", n_per=4, instructions_per=3, teacher_backend="template")
    assert s3.candidates > s1.candidates  # more phrasings = more candidates

"""W3-B: single-result evaluator — outcome matrix + abstention semantics."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import quality_eval as qe  # noqa: E402


@pytest.mark.parametrize("human,ai,outcome", [
    ("confirmed", "confirmed", "agreement"),
    ("false_positive", "false_positive", "agreement"),
    ("confirmed", "false_positive", "disagreement"),
    ("false_positive", "confirmed", "disagreement"),
    ("confirmed", "uncertain", "ai_abstained"),
    ("uncertain", "confirmed", "human_uncertain_ai_decided"),
    ("uncertain", "uncertain", "both_uncertain"),
])
def test_outcome_matrix(human, ai, outcome):
    assert qe.evaluate_single(human, ai)["outcome"] == outcome


def test_abstention_is_not_worded_as_failure():
    note = qe.evaluate_single("confirmed", "uncertain")["note"]
    assert "not a failure" in note


def test_illegal_values_rejected():
    with pytest.raises(qe.EvalError):
        qe.evaluate_single("maybe", "confirmed")
    with pytest.raises(qe.EvalError):
        qe.evaluate_single("confirmed", "definitely")


def test_evaluate_from_files(tmp_path):
    sid = "a" * 64
    labels = {"schema_version": 3, "corpus": {"repo-a": 5}, "labels": [
        {"sample_id": sid, "validity": "uncertain"}]}
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(labels), encoding="utf-8")
    rp = tmp_path / "result.json"
    rp.write_text(json.dumps({"assessment": "uncertain",
                              "confidence": "low", "model": "m",
                              "prompt_version": "w3b-v1"}), encoding="utf-8")
    out = qe.evaluate_from_files(lp, sid, rp)
    assert out["outcome"] == "both_uncertain" and out["sample_id"] == sid


def test_unknown_sample_id_rejected(tmp_path):
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps({"schema_version": 3, "labels": []}),
                  encoding="utf-8")
    rp = tmp_path / "r.json"
    rp.write_text("{}", encoding="utf-8")
    with pytest.raises(qe.EvalError):
        qe.evaluate_from_files(lp, "b" * 64, rp)

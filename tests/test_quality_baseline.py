"""W2-B2.8D Final: tests for the multi-axis quality-baseline tool.

Covers the schema_version 3 label file (five axes bound one-to-one to the
deterministic sample), aggregation math, reason-code accounting, the evidence
classifier, and — most importantly — the STRUCTURAL privacy gate that stands
between a detailed LOCAL labels file and any committed public summary."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import quality_baseline as qb  # noqa: E402
from quality_sample import sample_id  # noqa: E402


def _e(alias="repo-a", rule="P001", population=5, validity="confirmed",
       level="correct", gate="correct", act="actionable",
       reason="true_defect", project="proj-x", file="a.py", line=10,
       fingerprint="f" * 64, evidence="observed defect at the anchor"):
    return {"sample_id": sample_id(alias, project, file, line, rule,
                                   fingerprint),
            "alias": alias, "rule": rule, "population": population,
            "project": project, "file": file, "line": line,
            "fingerprint": fingerprint, "review_id": None,
            "validity": validity, "level_assessment": level,
            "gate_assessment": gate, "actionability": act,
            "reason_code": reason, "evidence": evidence}


def _labels(entries, corpus=None):
    return {"schema_version": 3,
            "corpus": corpus or {"repo-a": 100, "repo-b": 50},
            "labels": entries}


def _sample_of(entries):
    return [{k: e[k] for k in ("sample_id", "alias", "rule", "population",
                               "project", "file", "line", "fingerprint")}
            for e in entries]


# ---- schema validation ----------------------------------------------------------

def test_load_valid_labels(tmp_path):
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(_labels([_e(), _e(line=11, validity="uncertain",
                                            level="uncertain",
                                            gate="uncertain",
                                            act="needs_context",
                                            reason="metadata_gap")])),
                 encoding="utf-8")
    out = qb.load_labels(p)
    assert len(out["labels"]) == 2 and out["labels"][0]["rule"] == "P001"
    assert out["corpus"] == {"repo-a": 100, "repo-b": 50}


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version=2),                  # old version
    lambda d: d.pop("corpus"),                             # no corpus
    lambda d: d.update(corpus={"acme-main": 571}),         # raw repo name
    lambda d: d.update(corpus={"repo-a": 0}),              # non-positive
    lambda d: d["labels"][0].update(sample_id="nothex"),   # bad sample_id
    lambda d: d["labels"][0].update(alias="repoA"),        # bad alias
    lambda d: d["labels"][0].update(alias="repo-z"),       # alias not in corpus
    lambda d: d["labels"][0].update(rule="bad"),           # bad rule id
    lambda d: d["labels"][0].update(population=0),         # bad population
    lambda d: d["labels"][0].update(project=""),           # empty project
    lambda d: d["labels"][0].update(file=""),              # empty file
    lambda d: d["labels"][0].update(line="7"),             # non-int line
    lambda d: d["labels"][0].update(fingerprint=""),       # empty fingerprint
    lambda d: d["labels"][0].update(review_id=""),         # empty review_id
    lambda d: d["labels"][0].update(evidence="  "),        # blank evidence
    lambda d: d["labels"][0].pop("evidence"),              # missing evidence
])
def test_malformed_labels_rejected(tmp_path, mutate):
    data = _labels([_e()])
    mutate(data)
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.load_labels(p)


def test_duplicate_sample_id_rejected(tmp_path):
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(_labels([_e(), _e()])), encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.load_labels(p)


@pytest.mark.parametrize("field,value", [
    ("validity", "maybe"),
    ("level_assessment", "way_too_high"),
    ("gate_assessment", "kinda_strict"),
    ("actionability", "sometimes"),
    ("reason_code", "vibes"),
])
def test_each_axis_value_is_validated(tmp_path, field, value):
    entry = _e()
    entry[field] = value
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(_labels([entry])), encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.load_labels(p)


def test_corrupt_json_fails_closed(tmp_path):
    p = tmp_path / "labels.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.load_labels(p)


# ---- one-to-one binding ---------------------------------------------------------

def test_one_to_one_accepts_matching_sets_in_any_order():
    entries = [_e(line=n) for n in (1, 2, 3)]
    sample = _sample_of(entries)
    qb.verify_one_to_one(list(reversed(entries)), sample)
    qb.verify_one_to_one(entries, list(reversed(sample)))


def test_one_to_one_rejects_duplicate_label():
    entries = [_e(line=1), _e(line=2)]
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one(entries + [entries[0]], _sample_of(entries))


def test_one_to_one_rejects_label_outside_sample():
    entries = [_e(line=1), _e(line=2)]
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one(entries, _sample_of(entries[:1]))


def test_one_to_one_rejects_unlabelled_finding():
    entries = [_e(line=1), _e(line=2)]
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one(entries[:1], _sample_of(entries))


@pytest.mark.parametrize("field,value", [
    ("alias", "repo-b"), ("rule", "P002"), ("population", 9),
    ("project", "proj-y"), ("file", "b.py"), ("line", 99),
    ("fingerprint", "e" * 64),
])
def test_one_to_one_rejects_identity_mismatch(field, value):
    entry = _e()
    sample = _sample_of([entry])
    bad = dict(entry)
    bad[field] = value
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one([bad], sample)


# ---- sample_id recomputation (forgery resistance) -------------------------------

_FORGED = "ab" * 32


def test_forged_sample_id_in_label_rejected_at_load(tmp_path):
    entry = _e()
    entry["sample_id"] = _FORGED
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(_labels([entry])), encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.load_labels(p)


def test_forged_sample_id_in_label_rejected_at_verify():
    entry = _e()
    sample = _sample_of([entry])
    forged = {**entry, "sample_id": _FORGED}
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one([forged], sample)


def test_forged_sample_id_in_sample_rejected():
    entry = _e()
    sample = _sample_of([entry])
    sample[0]["sample_id"] = _FORGED
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one([entry], sample)


def test_same_forged_value_in_both_files_still_rejected():
    # matching forged values are NOT enough — the id must be derivable from
    # the identity itself
    entry = _e()
    sample = _sample_of([entry])
    forged_label = {**entry, "sample_id": _FORGED}
    sample[0]["sample_id"] = _FORGED
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one([forged_label], sample)


def test_forgery_error_never_echoes_ids_or_identity():
    entry = _e(project="very-secret-project")
    sample = _sample_of([entry])
    sample[0]["sample_id"] = _FORGED
    with pytest.raises(qb.QualityError) as exc:
        qb.verify_one_to_one([entry], sample)
    msg = str(exc.value)
    assert _FORGED not in msg and "very-secret-project" not in msg
    assert entry["sample_id"] not in msg


def test_legacy_sample_without_sample_id_is_a_quality_error():
    entry = _e()
    legacy = [{k: v for k, v in s.items() if k != "sample_id"}
              for s in _sample_of([entry])]
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one([entry], legacy)


def test_sample_entry_missing_identity_field_is_a_quality_error():
    entry = _e()
    sample = _sample_of([entry])
    del sample[0]["fingerprint"]
    with pytest.raises(qb.QualityError):
        qb.verify_one_to_one([entry], sample)


# ---- mandatory sample input ------------------------------------------------------

def test_build_public_summary_requires_a_sample_argument(tmp_path):
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(_labels([_e()], corpus={"repo-a": 5})),
                  encoding="utf-8")
    with pytest.raises(TypeError):
        qb.build_public_summary(lp)  # type: ignore[call-arg]


def test_build_public_summary_rejects_missing_sample_file(tmp_path):
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(_labels([_e()], corpus={"repo-a": 5})),
                  encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.build_public_summary(lp, tmp_path / "no-such-sample.json")


def test_cli_default_paths_run_one_to_one_on_sample_json(tmp_path,
                                                         monkeypatch):
    entries = [_e(line=1), _e(line=2)]
    local = tmp_path / ".quality-local"
    local.mkdir()
    (local / "labels.json").write_text(
        json.dumps(_labels(entries, corpus={"repo-a": 5})), encoding="utf-8")
    (local / "sample.json").write_text(json.dumps(_sample_of(entries)),
                                       encoding="utf-8")
    (tmp_path / "docs" / "quality").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    out = qb.main([])
    assert "2 reviewed" in out
    assert (tmp_path / "docs" / "quality" / "baseline-summary.json").exists()
    # incomplete binding through the SAME default path must fail
    (local / "sample.json").write_text(
        json.dumps(_sample_of(entries + [_e(line=3)])), encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.main([])


# ---- aggregation ----------------------------------------------------------------

def test_aggregate_counts_each_axis_independently():
    labels = [
        _e(line=1, validity="confirmed", level="correct", gate="correct",
           act="actionable"),
        _e(line=2, validity="confirmed", level="too_high", gate="too_strict",
           act="needs_context"),
        _e(line=3, validity="uncertain", level="uncertain", gate="uncertain",
           act="non_actionable", reason="metadata_gap"),
    ]
    agg = qb.aggregate({"corpus": {"repo-a": 100}, "labels": labels})
    row = agg.rules[0].as_row()
    assert row["validity"] == {"confirmed": 2, "false_positive": 0,
                               "uncertain": 1}
    assert row["level_assessment"]["too_high"] == 1
    assert row["gate_assessment"]["too_strict"] == 1
    assert row["actionability"] == {"actionable": 1, "needs_context": 1,
                                    "non_actionable": 1}
    # fifth axis: reason codes surface as counts and sum to reviewed
    assert row["reason_code_counts"] == {"metadata_gap": 1, "true_defect": 2}
    assert sum(row["reason_code_counts"].values()) == row["reviewed"]


def test_inconsistent_population_rejected():
    labels = [_e(line=1, population=5), _e(line=2, population=6)]
    with pytest.raises(qb.QualityError):
        qb.aggregate({"corpus": {}, "labels": labels})


def test_totals_rates_have_explicit_numerator_denominator():
    labels = [
        _e(line=1, validity="confirmed"),
        _e(line=2, validity="false_positive", reason="parameterized_or_safe"),
        _e(line=3, validity="uncertain", level="uncertain", gate="uncertain",
           act="needs_context", reason="metadata_gap"),
    ]
    tot = qb.aggregate({"corpus": {}, "labels": labels}).totals()
    assert tot["observed_confirmed_rate"] == {"numerator": 1, "denominator": 2,
                                              "value": 0.5}
    assert tot["uncertainty_rate"]["denominator"] == 3
    assert tot["level_agreement"]["denominator"] == 2
    assert tot["gate_agreement"]["denominator"] == 2
    assert sum(tot["reason_code_counts"].values()) == tot["reviewed"]


def test_aggregate_is_order_independent():
    labels = [_e(line=n, rule=r) for n, r in
              ((1, "P001"), (2, "P002"), (3, "P001"))]
    a = qb.public_summary(qb.aggregate({"corpus": {"repo-a": 9},
                                        "labels": labels}))
    b = qb.public_summary(qb.aggregate({"corpus": {"repo-a": 9},
                                        "labels": list(reversed(labels))}))
    assert a == b


# ---- evidence classifier --------------------------------------------------------

def _stat(confirmed=0, fp=0, uncertain=0):
    return qb.RuleStat(
        alias="repo-a", rule="X1", population=confirmed + fp + uncertain,
        reviewed=confirmed + fp + uncertain,
        validity={"confirmed": confirmed, "false_positive": fp,
                  "uncertain": uncertain},
        level_assessment={}, gate_assessment={}, actionability={})


def test_evidence_insufficient_when_nothing_decided():
    assert qb.evidence_class(_stat(uncertain=4)) == "insufficient_evidence"


def test_evidence_insufficient_when_uncertain_dominates():
    assert qb.evidence_class(_stat(confirmed=1, uncertain=3)) \
        == "insufficient_evidence"


def test_evidence_needs_hardening_on_false_positives():
    assert qb.evidence_class(_stat(confirmed=1, fp=1)) == "needs_hardening"


def test_evidence_provisionally_credible_when_clean():
    assert qb.evidence_class(_stat(confirmed=20)) == "provisionally_credible"


# ---- structural privacy gate ----------------------------------------------------

def _clean_summary():
    labels = [_e(line=n) for n in (1, 2, 3)]
    return qb.public_summary(qb.aggregate({"corpus": {"repo-a": 100},
                                           "labels": labels}))


def test_public_summary_passes_the_gate_and_has_structural_corpus():
    summary = _clean_summary()
    qb.assert_anonymized(summary)  # must not raise
    assert summary["corpus"] == {"repo-a": {"findings": 100}}


def test_evidence_text_is_never_serialized():
    marker = "UNIQUE-EVIDENCE-MARKER-XYZ"
    labels = [_e(evidence=f"detail {marker} detail")]
    summary = qb.public_summary(qb.aggregate({"corpus": {"repo-a": 5},
                                              "labels": labels}))
    assert marker not in json.dumps(summary)


def test_gate_rejects_any_extra_key():
    summary = _clean_summary()
    summary["extra"] = 1
    with pytest.raises(qb.QualityError):
        qb.assert_anonymized(summary)
    summary = _clean_summary()
    summary["rules"][0]["fingerprint"] = "a" * 64
    with pytest.raises(qb.QualityError):
        qb.assert_anonymized(summary)
    summary = _clean_summary()
    summary["totals"]["evidence"] = "text"
    with pytest.raises(qb.QualityError):
        qb.assert_anonymized(summary)


@pytest.mark.parametrize("leak", [
    "C:\\projects\\acme\\secret.cs",       # Windows drive C
    "D:/data/repo/file.tsx",                # another drive, forward slashes
    "\\\\fileserver\\share\\dump.json",     # UNC path
    "/home/dev/repo/main.py",               # POSIX path
    "/Users/dev/repo/main.swift",           # macOS path
    "Some-Internal-Repo-Name",              # repository-name-like string
    "SOME-INTERNAL-REPO-NAME",              # ...case variant
    "Password=hunter2;",                    # secret-looking text
    "AKIAIOSFODNN7EXAMPLE",                 # token-looking text
    "0272ffdf" + "0" * 56,                  # fingerprint-like hex
])
def test_gate_rejects_leaked_string_values_anywhere(leak):
    # as a corpus alias
    summary = _clean_summary()
    summary["corpus"] = {leak: {"findings": 1}}
    with pytest.raises(qb.QualityError):
        qb.assert_anonymized(summary)
    # as a rule row value
    summary = _clean_summary()
    summary["rules"][0]["repo"] = leak
    with pytest.raises(qb.QualityError):
        qb.assert_anonymized(summary)
    # replacing fixed text
    summary = _clean_summary()
    summary["note"] = leak
    with pytest.raises(qb.QualityError):
        qb.assert_anonymized(summary)


def test_gate_error_never_echoes_the_offending_value():
    poison = "C:\\very\\secret\\path.cs"
    summary = _clean_summary()
    summary["rules"][0]["repo"] = poison
    with pytest.raises(qb.QualityError) as exc:
        qb.assert_anonymized(summary)
    assert poison not in str(exc.value)


def test_gate_rejects_reason_counts_not_summing_to_reviewed():
    summary = _clean_summary()
    summary["rules"][0]["reason_code_counts"] = {"true_defect": 1}
    with pytest.raises(qb.QualityError):
        qb.assert_anonymized(summary)


# ---- end to end -----------------------------------------------------------------

def test_build_public_summary_end_to_end_with_sample(tmp_path):
    entries = [_e(line=1), _e(line=2, validity="uncertain",
                              level="uncertain", gate="uncertain",
                              act="needs_context", reason="metadata_gap")]
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(_labels(entries, corpus={"repo-a": 100})),
                  encoding="utf-8")
    sp = tmp_path / "sample.json"
    sp.write_text(json.dumps(_sample_of(entries)), encoding="utf-8")
    out = qb.build_public_summary(lp, sp)
    assert out["schema_version"] == 3
    assert out["totals"]["reviewed"] == 2
    assert out["totals"]["uncertainty_rate"]["numerator"] == 1


def test_build_public_summary_fails_on_incomplete_binding(tmp_path):
    entries = [_e(line=1), _e(line=2)]
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(_labels(entries[:1], corpus={"repo-a": 100})),
                  encoding="utf-8")
    sp = tmp_path / "sample.json"
    sp.write_text(json.dumps(_sample_of(entries)), encoding="utf-8")
    with pytest.raises(qb.QualityError):
        qb.build_public_summary(lp, sp)

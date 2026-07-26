"""W3-E7: the earned-evidence acceptance rule, pinned.

The first W3-E7 run was voided because the harness could not tell the agent
runtime's verdict guard from the model's own judgment. These regressions cover
the other half of that defect: a cross-project case must not satisfy its
acceptance criterion by coincidence — the evidence has to have been read, and
the verdict has to be the model's.

Pure classification of recorded rows; no model, no network, no stored run.
"""
from __future__ import annotations

from auditor.ai.quality_harness import earned_evidence


def _accept(rows):
    """The cross-project acceptance rule. Every case here IS cross-project;
    the not-applicable case has its own test below."""
    return earned_evidence(rows, cross_project=True)


def _row(kind, **kw):
    base = {"case_id": "c", "kind": kind, "outcome": "no_issue_observed",
            "model_outcome": "no_issue_observed", "guard_downgraded": "",
            "cross_project_reached": [], "target": None, "issues": []}
    return {**base, **kw}


def test_a_cross_project_negative_is_accepted_only_after_reading_the_protection():
    unread = _accept([_row("negative")])["rows"][0]
    assert unread["sibling_reached"] is False
    assert unread["meets_acceptance"] is False      # right for the wrong reason

    read = _accept([_row("negative",
                        cross_project_reached=["shared/Guard.cs"])])["rows"][0]
    assert read["sibling_reached"] is True
    assert read["meets_acceptance"] is True


def test_a_guard_downgraded_negative_never_meets_the_criterion():
    """The guard's `insufficient_context` is the runtime declining to conclude.
    Even with the protection read, nothing was concluded."""
    row = _accept([_row("negative", outcome="insufficient_context",
                       guard_downgraded="evidence_not_closed",
                       cross_project_reached=["shared/Guard.cs"])])["rows"][0]
    assert row["sibling_reached"] is True
    assert row["meets_acceptance"] is False


def test_a_model_abstained_negative_never_meets_the_criterion():
    row = _accept([_row("negative", outcome="insufficient_context",
                       model_outcome="insufficient_context",
                       cross_project_reached=["shared/Guard.cs"])])["rows"][0]
    assert row["meets_acceptance"] is False


def test_a_positive_needs_both_the_sibling_and_a_citation_on_the_target():
    target = ["shared/Guard.cs", 2, 4]
    issue = {"evidence": [{"file": "shared/Guard.cs", "line_start": 3,
                           "line_end": 3}]}
    reached_only = _accept([_row("positive", target=target,
                                cross_project_reached=["shared/Guard.cs"])])
    assert reached_only["rows"][0]["meets_acceptance"] is False   # nothing cited

    cited_only = _accept([_row("positive", target=target, issues=[issue])])
    assert cited_only["rows"][0]["meets_acceptance"] is False     # not traced

    both = _accept([_row("positive", target=target, issues=[issue],
                        cross_project_reached=["shared/Guard.cs"])])
    assert both["rows"][0]["cites_target"] is True
    assert both["rows"][0]["meets_acceptance"] is True


def test_an_abstain_is_the_models_word_not_the_guards():
    honest = _accept([_row("abstain", outcome="insufficient_context",
                          model_outcome="insufficient_context")])["rows"][0]
    assert honest["meets_acceptance"] is True

    guarded = _accept([_row("abstain", outcome="insufficient_context",
                           guard_downgraded="evidence_not_closed")])["rows"][0]
    assert guarded["meets_acceptance"] is False


def test_the_reading_requirement_does_not_apply_to_an_in_repo_case():
    """An in-repo case has no sibling to reach, so the criterion is undefined
    for it — None, never a False that would read as a failure. Its detection is
    the scoring classifier's job, not this table's."""
    rows = [_row(k) for k in ("positive", "negative", "abstain")]
    for r in earned_evidence(rows, cross_project=False)["rows"]:
        assert r["meets_acceptance"] is None
        assert r["sibling_reached"] is False       # still recorded, as a fact

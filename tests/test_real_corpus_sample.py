"""REAL-CORPUS-1A sampling and reviewer packets: deterministic, no network.

The properties here are the ones that decide whether the labels this corpus
eventually carries can be believed:

* the two context paths are measured by their own packers and their own caps;
* the blind sample is chosen without the scanner's output, so a different
  report cannot move a single unit;
* each track has its own review contract, and a claim that cannot exist is
  not offered as an answer;
* the packets match the sample one-to-one, and nothing committable carries
  code, a path, or a pack.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.review import (PACK_MAX_BYTES, SOURCE_MAX_BYTES,
                               ContextTooLargeError, build_context_pack,
                               finding_review_id)
from tools.real_corpus import RepoSpec
from tools.real_corpus_audit import (AuditProfilingError, audit_size_bucket,
                                     audit_summary, legal_pairs,
                                     profile_repository, project_roots,
                                     unsupported_languages)
from tools.real_corpus_sample import (
    ACTIONABILITY,
    BLIND_MIN_BODY_BYTES,
    LEVELS,
    MAX_REPO_SHARE,
    REVIEW_PACK_CAP,
    REVIEWERS,
    TRACK_A_LABEL_FIELDS,
    TRACK_A_LABELS,
    TRACK_B_ISSUE_FIELDS,
    TRACK_B_OUTCOMES,
    SamplingError,
    assign_blind_buckets,
    blind_leakage,
    build_blind_packet,
    build_blind_population,
    build_findings_packet,
    build_findings_units,
    catalog_rules_by_language,
    context_bound,
    finding_stratum,
    inclusion_probabilities,
    normalize_finding_path,
    public_output_problem,
    repo_shares,
    scanner_overlap,
    select_blind,
    select_stratified,
    single_finding_review_pack,
    size_bucket,
    validate_blind_labels,
    validate_findings_labels,
    verify_blind_packets,
    verify_findings_packets,
)


def _spec(repo_id="repo-one", language="python"):
    return RepoSpec(repo_id, "https://github.com/o/r", "a" * 40, "MIT",
                    language)


def _finding(n: int, **over):
    f = {"rule_id": "P001", "language": "python", "precision": "heuristic",
         "level": "warning", "file": f"pkg/m{n}.py", "line": n,
         "title": f"t{n}", "detail": f"d{n}", "snippet": f"secret_{n} = 1",
         "gate_action": "review", "fingerprint": f"{n:064x}"}
    f.update(over)
    return f


def _report(findings, root=".", language="python"):
    return {"tool": "ai-code-auditor",
            "projects": [{"root": root, "language": language,
                          "findings": findings}]}


# An empty tree: the packer still builds a pack from the report's own fields,
# it simply finds no source to attach. Tests about identity, stratification
# and determinism do not need source; the tests that are about SIZE build a
# real tree of their own.
_EMPTY_ROOT = Path(tempfile.mkdtemp(prefix="rc1a-empty-"))


def _units(spec, report, *, root=_EMPTY_ROOT, unpackable=None):
    return build_findings_units(spec, report, repo_root=root,
                                unpackable=unpackable)


def _py_tree(tmp_path: Path, *, functions: int = 6, files: int = 3) -> Path:
    """A small real Python repository. Every function is comfortably over the
    judgeable floor so nothing is silently filtered out of the population."""
    body = "\n".join(f"    value_{i} = compute({i}) + offset_{i}"
                     for i in range(6))
    for f in range(files):
        src = tmp_path / "pkg" / f"mod{f}.py"
        src.parent.mkdir(parents=True, exist_ok=True)
        text = ["import os", "import sys", "from typing import Any", ""]
        for n in range(functions):
            text += [f"def fn_{f}_{n}(offset_{'_'.join(str(i) for i in [0])}):",
                     body.replace("offset_", "offset_0_" ), "    return 0", ""]
        src.write_text("\n".join(text), encoding="utf-8")
    return tmp_path


# ---- size buckets --------------------------------------------------------------------

@pytest.mark.parametrize("frac, expected", [
    (0.0, "small"), (0.25, "small"), (0.49, "small"),
    (0.50, "medium"), (0.65, "medium"), (0.79, "medium"),
    (0.80, "large"), (0.95, "large"), (1.0, "large"), (1.5, "large"),
])
def test_size_buckets_follow_the_real_fraction_of_the_cap(frac, expected):
    # a cap of 100 so the boundary is exact
    assert size_bucket(round(100 * frac), 100) == expected


def test_a_zero_cap_is_refused_rather_than_divided_by():
    with pytest.raises(SamplingError):
        size_bucket(100, 0)


# ---- the two context paths are NOT the same path -------------------------------------

def test_the_review_track_uses_the_review_packers_own_cap():
    """The first closing round bucketed review packs against 12288 — the
    source budget of audit queries AI002-AI008. It is not this packer's cap
    and it changes the answer: the corpus's largest pack, 6302 bytes, reads
    as `medium` against 12288 and `small` against the real 24576."""
    assert REVIEW_PACK_CAP == PACK_MAX_BYTES == 24576
    assert size_bucket(6302, 12288) == "medium"
    assert size_bucket(6302, REVIEW_PACK_CAP) == "small"


def test_findings_sizing_does_not_reach_for_the_audit_packer(monkeypatch,
                                                             tmp_path):
    """Behavioural, not a grep: make the audit packer explode and the review
    track must be entirely unaffected."""
    def explode(*_a, **_k):
        raise AssertionError("the review track called the audit packer")

    monkeypatch.setattr("tools.real_corpus_audit.build_audit_pack", explode)
    src = tmp_path / "pkg" / "m1.py"
    src.parent.mkdir(parents=True)
    src.write_text("\n".join(f"x{i} = {i}" for i in range(200)),
                   encoding="utf-8")
    units = _units(_spec(), _report([_finding(1, file="pkg/m1.py", line=100)]),
                   root=tmp_path)
    assert len(units) == 1 and units[0].context_bytes > 0


def test_audit_profiling_does_not_reach_for_the_review_packer(monkeypatch,
                                                              tmp_path):
    """The mirror of the test above, and the reason the audit profiler lives
    in its own module: it must never be able to borrow a review limit."""
    def explode(*_a, **_k):
        raise AssertionError("audit profiling called the review packer")

    monkeypatch.setattr("auditor.ai.review.build_context_pack", explode)
    monkeypatch.setattr("tools.real_corpus_sample.build_context_pack", explode)
    tree = _py_tree(tmp_path)
    report = _report([], root=".", language="python")
    profiles = profile_repository(_spec(), tree, report, skips={})
    assert isinstance(profiles, list)     # it ran; the review packer was never
    #                                       reachable from this path at all
    import tools.real_corpus_audit as audit_mod
    assert not hasattr(audit_mod, "build_context_pack")
    assert not hasattr(audit_mod, "single_finding_review_pack")


def test_each_query_is_bucketed_against_its_own_cap():
    """AI001 gets 16384 and the rest get 12288. A single shared number would
    put the same pack in two different buckets depending on the query."""
    assert audit_size_bucket(13000, 16384) == "medium"
    assert audit_size_bucket(13000, 12288) == "large"
    with pytest.raises(AuditProfilingError):
        audit_size_bucket(100, 0)


def test_audit_pack_size_is_taken_from_build_audit_pack_verbatim(monkeypatch,
                                                                 tmp_path):
    """The recorded size is the canonical bytes the packer produced — not a
    re-serialisation, not an estimate, not a sum of pieces."""
    canonical = "CANONICAL-" + "x" * 5000
    fake = {"canonical": canonical,
            "pieces": [{"context_id": "src:1", "text": "y" * 900}],
            "privacy_manifest": {"files_sent": 1, "pieces_sent": 1}}
    monkeypatch.setattr("tools.real_corpus_audit.build_audit_pack",
                        lambda *_a, **_k: fake)
    tree = _py_tree(tmp_path)
    profiles = profile_repository(_spec(), tree,
                                  _report([], language="python"), skips={})
    assert profiles
    assert all(p.pack_bytes == len(canonical.encode("utf-8"))
               for p in profiles)
    assert all(p.source_bytes == 900 for p in profiles)


def test_a_language_no_query_supports_is_reported_not_silently_dropped():
    """The scanner names .NET projects `dotnet`; the audit catalog names its
    queries for `csharp`. Every .NET project therefore has zero legal pairs
    and never gets audited at all. Reporting only the packs that were built
    would show that as silence."""
    report = _report([], root=".", language="dotnet")
    assert legal_pairs(report) == []
    assert unsupported_languages(report) == {"dotnet": 1}
    summary = audit_summary([], {}, unsupported_languages(report))
    assert summary["project_languages_no_query_supports"] == {"dotnet": 1}


def test_project_roots_come_from_the_report_not_from_the_tree():
    report = {"projects": [{"root": "svc/a", "language": "python"},
                           {"root": "svc/b", "language": "java"},
                           {"root": "svc/a", "language": "python"},
                           {"nonsense": True}]}
    assert project_roots(report) == [("svc/a", "python"), ("svc/b", "java")]


# ---- track A: emitted findings --------------------------------------------------------

def test_every_emitted_finding_becomes_an_identified_candidate():
    units = _units(_spec(), _report([_finding(i) for i in range(20)]))
    assert len(units) == 20
    assert len({u.sample_id for u in units}) == 20
    assert all(u.track == "findings" for u in units)


def test_the_recorded_size_is_the_packers_size_not_the_snippets(tmp_path):
    """Sizing by the finding's snippet is what put the two previous corpora at
    a tenth of the budget: the snippet here is 13 bytes while the real file is
    thousands, and the unit must follow the file."""
    src = tmp_path / "pkg" / "m1.py"
    src.parent.mkdir(parents=True)
    src.write_text("\n".join(f"CONSTANT_{i} = 'value number {i}'"
                             for i in range(400)), encoding="utf-8")
    finding = _finding(1, file="pkg/m1.py", line=200)
    report = _report([finding])

    unit, = _units(_spec(), report, root=tmp_path)
    snippet_bytes = len((finding["snippet"] + finding["detail"]).encode())
    assert unit.context_bytes > snippet_bytes * 50

    pack = build_context_pack(report, tmp_path,
                              finding_review_id(".", finding))
    assert unit.context_bytes == len(pack["canonical"].encode("utf-8"))
    assert single_finding_review_pack(report, tmp_path,
                                      finding_review_id(".", finding)) \
        == unit.context_bytes


def test_the_bound_report_separates_the_line_window_from_the_byte_budget(
        tmp_path):
    """A small pack has three very different causes, and only one of them is
    about the corpus."""
    ordinary = tmp_path / "pkg" / "ordinary.py"
    ordinary.parent.mkdir(parents=True)
    ordinary.write_text("\n".join(f"x{i} = {i}" for i in range(2000)),
                        encoding="utf-8")
    wide = tmp_path / "pkg" / "wide.py"
    wide.write_text("\n".join(f"y{i} = '{'q' * 1900}'" for i in range(30)),
                    encoding="utf-8")
    huge = tmp_path / "pkg" / "huge.py"
    huge.write_text("\n".join(f"z{i} = {i}" for i in range(20000)),
                    encoding="utf-8")

    f_ord = _finding(1, file="pkg/ordinary.py", line=1000)
    f_wide = _finding(2, file="pkg/wide.py", line=15)
    f_huge = _finding(3, file="pkg/huge.py", line=10000)

    a = context_bound(_report([f_ord]), tmp_path, finding_review_id(".", f_ord))
    assert a["source_lines"] == 41           # the window, not the budget
    assert a["bound_by_line_window"] is True
    assert a["bound_by_byte_budget"] is False
    assert a["source_bytes"] < SOURCE_MAX_BYTES

    b = context_bound(_report([f_wide]), tmp_path,
                      finding_review_id(".", f_wide))
    assert b["bound_by_byte_budget"] is True
    assert b["bound_by_line_window"] is False
    assert b["window_span"] == 30 and b["source_lines"] < 30
    assert b["source_bytes"] <= SOURCE_MAX_BYTES

    # A file past SOURCE_MAX_BYTES * 8 is refused WHOLE: no truncated window.
    c = context_bound(_report([f_huge]), tmp_path,
                      finding_review_id(".", f_huge))
    assert c["files_sent"] == 0
    assert c["source_lines"] == 0 and c["source_bytes"] == 0
    assert c["bound_by_line_window"] is False
    assert c["bound_by_byte_budget"] is False
    assert c["pack_bytes"] < a["pack_bytes"]


def test_a_finding_the_packer_refuses_is_dropped_and_counted(monkeypatch):
    """A unit whose real size is unknown cannot be assigned a bucket. It
    leaves the population and shows up as a coverage gap."""
    def refuse(*_a, **_k):
        raise ContextTooLargeError()   # fixed safe message, takes no args

    monkeypatch.setattr("tools.real_corpus_sample.build_context_pack", refuse)
    gaps: list[str] = []
    units = _units(_spec(), _report([_finding(i) for i in range(5)]),
                   unpackable=gaps)
    assert units == []
    assert len(gaps) == 5


def test_a_report_without_fingerprints_cannot_be_sampled():
    bad = _report([{**_finding(1), "fingerprint": ""}])
    with pytest.raises(SamplingError, match="fingerprint"):
        _units(_spec(), bad)


def test_findings_that_share_a_fingerprint_stay_distinct_units():
    """A fingerprint is a MULTISET key — the baseline matcher lets duplicates
    match one-for-one — so one repository really can hold several findings
    with the same fingerprint."""
    same = "d" * 64
    report = _report([
        _finding(1, fingerprint=same, file="a.py", line=10),
        _finding(2, fingerprint=same, file="b.py", line=20),
        _finding(3, fingerprint=same, file="b.py", line=99),
    ])
    units = _units(_spec(), report)
    assert len(units) == 3
    assert len({u.sample_id for u in units}) == 3
    reversed_report = _report(list(reversed(report["projects"][0]["findings"])))
    again = _units(_spec(), reversed_report)
    assert {u.sample_id for u in units} == {u.sample_id for u in again}


def test_the_stratum_carries_the_plan_s_five_axes():
    stratum = finding_stratum(_finding(1, rule_id="R007", level="error"))
    assert stratum.split("/") == ["R", "python", "heuristic", "error"]


# ---- selection ------------------------------------------------------------------------

def test_the_same_corpus_always_yields_the_same_sample():
    report = _report([_finding(i, rule_id=f"P00{i % 7}") for i in range(60)])
    first = select_stratified(_units(_spec(), report), 40)
    second = select_stratified(_units(_spec(), report), 40)
    assert [u.sample_id for u in first] == [u.sample_id for u in second]
    shuffled = list(reversed(_units(_spec(), report)))
    assert [u.sample_id for u in select_stratified(shuffled, 40)] \
        == [u.sample_id for u in first]


def test_one_huge_repository_is_capped_at_its_quota():
    units = []
    for repo, n in (("big", 400), ("a", 20), ("b", 20), ("c", 20), ("d", 20),
                    ("e", 20)):
        units += _units(_spec(repo),
                        _report([_finding(i, rule_id=f"P00{i % 5}")
                                 for i in range(n)]))
    picked = select_stratified(units, 100)
    assert repo_shares(picked)["big"] <= MAX_REPO_SHARE + 0.001


def test_a_corpus_too_narrow_for_the_ceiling_falls_short_visibly():
    """With three repositories no draw can put every share under 20 %. The
    plan says cap the quota and REPORT the shortfall — not shrink the sample
    until the arithmetic works."""
    units = []
    for repo in ("a", "b", "c"):
        units += _units(_spec(repo), _report([_finding(i) for i in range(50)]))
    picked = select_stratified(units, 60)
    assert len(picked) >= 30                      # a real sample survives
    assert max(repo_shares(picked).values()) > MAX_REPO_SHARE   # and it shows


def test_a_wide_enough_corpus_honours_the_ceiling():
    units = []
    for repo in "abcdefghij":
        units += _units(_spec(repo), _report([_finding(i, rule_id=f"P00{i % 4}")
                                              for i in range(40)]))
    picked = select_stratified(units, 100)
    assert max(repo_shares(picked).values()) <= MAX_REPO_SHARE + 0.001


def test_selection_spreads_across_strata():
    # across enough repositories that the 20 % ceiling is not the binding
    # constraint — the single-repository case is covered by the narrow-corpus
    # test above, where a cap of one unit is the correct, reported outcome
    units = []
    for repo in "abcdef":
        units += _units(_spec(repo),
                        _report([_finding(i, rule_id=f"{fam}00{i % 3}")
                                 for i, fam in enumerate("PPRRHHDD")]))
    picked = select_stratified(units, 24)
    assert len({u.stratum for u in picked}) >= 3


# ---- track B: independent of the report ----------------------------------------------

def test_the_blind_population_is_built_without_any_report(tmp_path):
    """`build_blind_population` takes no report and must never be given one:
    a sample the scanner helped choose cannot measure what the scanner
    missed."""
    population = build_blind_population(_spec(), _py_tree(tmp_path))
    assert population
    assert all(u.track == "blind" for u in population)
    assert all(u.stratum == "repo-one/python" for u in population)
    assert all(len(u.local["code"].encode()) >= BLIND_MIN_BODY_BYTES
               for u in population)


def test_the_blind_sample_is_identical_under_two_contradictory_reports(
        tmp_path):
    """MANDATORY. Two reports that disagree about everything must select the
    same units. Before this round, deleting findings changed which units were
    drawn and only 13 of 25 survived a disagreement."""
    tree = _py_tree(tmp_path)
    population = build_blind_population(_spec(), tree)
    frozen = [u.sample_id for u in select_blind(population, per_repo=10)]

    # the reports differ, but neither can reach the draw at all
    empty = _report([])
    everything = _report([_finding(i, file=f"pkg/mod{i % 3}.py", line=5 + i)
                          for i in range(30)])
    for report in (empty, everything):
        again = build_blind_population(_spec(), tree)
        assert [u.sample_id for u in select_blind(again, per_repo=10)] == frozen
        # and the join runs afterwards without touching the selection
        chosen = select_blind(again, per_repo=10)
        scanner_overlap(chosen, report)
        assert [u.sample_id for u in chosen] == frozen


def test_deleting_every_finding_cannot_move_a_sampled_unit(tmp_path):
    tree = _py_tree(tmp_path)
    sample = select_blind(build_blind_population(_spec(), tree), per_repo=8)
    ids = [u.sample_id for u in sample]
    scanner_overlap(sample, _report([_finding(1, file="pkg/mod0.py", line=6)]))
    scanner_overlap(sample, _report([]))
    assert [u.sample_id for u in sample] == ids


def test_a_blind_unit_id_changes_when_the_code_changes(tmp_path):
    tree = _py_tree(tmp_path)
    before = {u.sample_id for u in build_blind_population(_spec(), tree)}
    target = tree / "pkg" / "mod0.py"
    target.write_text(target.read_text(encoding="utf-8")
                      .replace("value_0", "value_zero"), encoding="utf-8")
    after = {u.sample_id for u in build_blind_population(_spec(), tree)}
    assert before != after


def test_blind_sampling_is_deterministic(tmp_path):
    tree = _py_tree(tmp_path)
    a = select_blind(build_blind_population(_spec(), tree), per_repo=7)
    b = select_blind(build_blind_population(_spec(), tree), per_repo=7)
    assert [u.sample_id for u in a] == [u.sample_id for u in b]


def test_inclusion_probability_is_recorded_against_a_real_population(tmp_path):
    """A recall estimate needs a denominator that is a population and a known
    chance of inclusion. Both are recorded rather than assumed uniform."""
    population = build_blind_population(_spec(), _py_tree(tmp_path))
    sample = select_blind(population, per_repo=5)
    stats = inclusion_probabilities(population, sample)
    assert stats["repo-one"]["population"] == len(population)
    assert stats["repo-one"]["sampled"] == len(sample)
    assert 0 < stats["repo-one"]["inclusion_probability"] <= 1


# ---- overlap is per UNIT, and joined only after the freeze ----------------------------

@pytest.mark.parametrize("root, file, expected", [
    (".", "pkg/a.py", "pkg/a.py"),
    ("", "pkg/a.py", "pkg/a.py"),
    ("svc/api", "pkg/a.py", "svc/api/pkg/a.py"),
    ("svc/api/", "pkg/a.py", "svc/api/pkg/a.py"),
    ("svc/api", "svc/api/pkg/a.py", "svc/api/pkg/a.py"),   # already joined
    ("svc/api", "./pkg/a.py", "svc/api/pkg/a.py"),
    ("svc/api", "pkg\\a.py", "svc/api/pkg/a.py"),          # windows separator
])
def test_multi_project_path_normalization(root, file, expected):
    """MANDATORY. In a monorepo a finding's `file` is relative to ITS project
    root. Comparing it against a repository-relative unit path without joining
    the root matches the wrong project, or nothing."""
    assert normalize_finding_path(root, file) == expected


def test_a_finding_in_one_function_does_not_mark_the_others(tmp_path):
    """MANDATORY. On the real corpus the file-level rule marked 504 of 536
    units (94 %) as has_finding when no finding was inside them."""
    src = tmp_path / "pkg" / "two.py"
    src.parent.mkdir(parents=True)
    first = "\n".join(f"    a{i} = {i} * 31 + 7   # padding for the floor"
                      for i in range(8))
    second = "\n".join(f"    b{i} = {i} * 17 - 3   # padding for the floor"
                       for i in range(8))
    src.write_text(f"def first():\n{first}\n    return 1\n\n"
                   f"def second():\n{second}\n    return 2\n",
                   encoding="utf-8")
    units = [u for u in build_blind_population(_spec(), tmp_path)
             if u.local["file"] == "pkg/two.py"]
    assert len(units) == 2
    inner, outer = sorted(units, key=lambda u: u.local["start_line"])

    # the finding sits inside the FIRST function only
    line = inner.local["start_line"] + 1
    hits = scanner_overlap(units, _report([_finding(1, file="pkg/two.py",
                                                    line=line)]))
    assert hits[inner.sample_id], "the containing unit must match"
    assert hits[outer.sample_id] == [], "a sibling function must NOT match"


def test_overlap_respects_the_project_root_in_a_monorepo(tmp_path):
    src = tmp_path / "svc" / "api" / "pkg" / "m.py"
    src.parent.mkdir(parents=True)
    body = "\n".join(f"    v{i} = {i} * 13 + 5   # padding for the floor"
                     for i in range(8))
    src.write_text(f"def handler():\n{body}\n    return 0\n", encoding="utf-8")
    unit, = [u for u in build_blind_population(_spec(), tmp_path)
             if u.local["file"].endswith("m.py")]
    line = unit.local["start_line"] + 1

    # declared under the project root: the join must find it
    joined = _report([_finding(1, file="pkg/m.py", line=line)],
                     root="svc/api")
    assert scanner_overlap([unit], joined)[unit.sample_id]

    # the SAME relative path under a different project must not match
    other = _report([_finding(1, file="pkg/m.py", line=line)], root="svc/web")
    assert scanner_overlap([unit], other)[unit.sample_id] == []


def test_a_finding_without_a_usable_line_matches_nothing(tmp_path):
    units = select_blind(build_blind_population(_spec(), _py_tree(tmp_path)),
                         per_repo=4)
    hits = scanner_overlap(units, _report([_finding(1, line=0),
                                           _finding(2, line=None),
                                           _finding(3, line=True)]))
    assert all(v == [] for v in hits.values())


# ---- two review contracts -------------------------------------------------------------

def _sample(tmp_path):
    findings = _units(_spec(), _report([_finding(i) for i in range(6)]))
    blind = assign_blind_buckets(
        select_blind(build_blind_population(_spec(), _py_tree(tmp_path)),
                     per_repo=6))
    return findings, blind


def test_track_a_offers_the_adjudication_vocabulary(tmp_path):
    findings, _ = _sample(tmp_path)
    packet = build_findings_packet(findings, "R1", "salt")
    entry = packet[0]
    assert set(TRACK_A_LABEL_FIELDS) <= set(entry)
    assert entry["label"] == ""
    assert TRACK_A_LABELS == ("confirmed", "false_positive", "uncertain")
    assert "claim" in entry and "judged_on" in entry


def test_track_b_offers_outcomes_and_an_issue_list_not_a_verdict(tmp_path):
    _, blind = _sample(tmp_path)
    entry = build_blind_packet(blind, "R1", "salt")[0]
    assert entry["outcome"] == "" and entry["issues"] == []
    assert "label" not in entry, "there is no claim on this track to label"
    assert "false_positive" not in json.dumps(entry)
    assert TRACK_B_OUTCOMES == ("issues_found", "no_issue_observed",
                                "uncertain")


def test_the_two_packets_do_not_have_the_same_shape(tmp_path):
    """The previous round asserted the key sets were indistinguishable. They
    never were — `claim` and `code_unit` are right there — and pretending
    otherwise hid that the two tracks were being asked the same question."""
    findings, blind = _sample(tmp_path)
    a = build_findings_packet(findings, "R1", "salt")[0]
    b = build_blind_packet(blind, "R1", "salt")[0]
    assert set(a) != set(b)
    assert "claim" in a and "claim" not in b
    assert "code_unit" in b and "code_unit" not in a
    assert "issues" in b and "issues" not in a


def test_issues_found_with_an_empty_list_is_rejected():
    """MANDATORY. `issues_found` is a claim; a claim with nothing behind it
    cannot be reviewed, scored, or argued with."""
    problems = validate_blind_labels({"outcome": "issues_found", "issues": []})
    assert any("nothing to review" in p for p in problems)


def test_a_complete_issue_is_accepted():
    issue = {"rule_id": "P001", "line": 12, "span": "10-20",
             "statement": "a literal credential is assigned here",
             "evidence": "line 12 assigns a quoted secret",
             "level": "error", "actionability": "actionable"}
    assert validate_blind_labels({"outcome": "issues_found",
                                  "issues": [issue]}) == []
    assert set(TRACK_B_ISSUE_FIELDS) <= set(issue)


def test_an_issue_missing_evidence_or_a_statement_is_rejected():
    bare = {"rule_id": "P001", "line": 12, "span": "10-20", "statement": "",
            "evidence": "", "level": "error", "actionability": "actionable"}
    problems = validate_blind_labels({"outcome": "issues_found",
                                      "issues": [bare]})
    assert any("statement" in p for p in problems)
    assert any("evidence" in p for p in problems)


def test_no_issue_observed_may_not_carry_issues():
    problems = validate_blind_labels(
        {"outcome": "no_issue_observed",
         "issues": [{"statement": "x", "evidence": "y"}]})
    assert any("no_issue_observed carries" in p for p in problems)


def test_false_positive_is_refused_on_the_blind_track():
    """There is no claim on this track, so nothing can be false about it."""
    problems = validate_blind_labels(
        {"outcome": "issues_found",
         "issues": [{"rule_id": "P001", "line": 1, "span": "1-2",
                     "statement": "s", "evidence": "e", "level": "note",
                     "actionability": "actionable",
                     "label": "false_positive"}]})
    assert any("no meaning on the blind track" in p for p in problems)


def test_a_track_a_label_needs_a_reason_and_legal_values():
    assert validate_findings_labels(
        {"label": "confirmed", "reason": "the line assigns a literal secret",
         "level": "error", "gate": "block", "actionability": "actionable",
         "evidence_sufficiency": "sufficient"}) == []
    problems = validate_findings_labels(
        {"label": "definitely", "reason": "", "level": "critical",
         "gate": "nope", "actionability": "maybe",
         "evidence_sufficiency": "some"})
    assert len(problems) == 6
    assert LEVELS == ("error", "warning", "note")
    assert "unclear" in ACTIONABILITY


# ---- reviewer context -----------------------------------------------------------------

def test_track_a_receives_the_context_the_judgement_needs(tmp_path):
    """A reviewer cannot rule on a claim from a title and a one-line snippet.
    The entry carries the same source window and rule definition the model
    would see."""
    src = tmp_path / "pkg" / "m1.py"
    src.parent.mkdir(parents=True)
    src.write_text("\n".join(f"line_{i} = {i}" for i in range(200)),
                   encoding="utf-8")
    finding = _finding(1, file="pkg/m1.py", line=100)
    report = _report([finding])
    report["analysis_manifest"] = {"catalog": [
        {"rule_id": "P001", "title": "hardcoded credential",
         "description": "a literal secret in source", "category": "secrets"}]}
    from tools.real_corpus_sample import reviewer_evidence
    unit, = _units(_spec(), report, root=tmp_path)
    evidence = {unit.sample_id: reviewer_evidence(report, tmp_path, unit)}
    entry = build_findings_packet([unit], "R1", "salt", evidence=evidence)[0]
    judged = entry["judged_on"]
    assert "line_100" in judged["source_window"]
    assert judged["source_span"]
    assert judged["rule_definition"]["rule_id"] == "P001"


def test_track_b_receives_file_context_and_its_own_languages_rules(tmp_path):
    _, blind = _sample(tmp_path)
    catalog = catalog_rules_by_language({"r": {
        "projects": [{"root": ".", "language": "python", "findings": []}],
        "analysis_manifest": {"catalog": [
            {"rule_id": "P001", "title": "t", "description": "d",
             "category": "c"},
            {"rule_id": "R007", "title": "t2", "description": "d2",
             "category": "c2"}]}}})
    entry = build_blind_packet(blind, "R1", "salt", catalog_rules=catalog)[0]
    assert "import os" in entry["code_unit"]["file_context"]
    assert [r["rule_id"] for r in entry["applicable_rules"]] == ["P001",
                                                                 "R007"]
    # a menu of what the tool CAN say is not a hint about what it did say
    assert not blind_leakage([entry])


def test_the_blind_packet_never_carries_overlap_or_a_verdict(tmp_path):
    """MANDATORY. The join exists, but it lives beside the sample and must
    never reach a reviewer."""
    _, blind = _sample(tmp_path)
    packet = build_blind_packet(blind, "R1", "salt")
    assert blind_leakage(packet) == []
    blob = json.dumps(packet)
    for forbidden in ("overlap", "has_finding", "verdict", "gate_action",
                      "scanner_level", "scanner_gate", "scanner_precision",
                      "fingerprint", "claim"):
        assert f'"{forbidden}"' not in blob


def test_a_leaked_overlap_is_caught(tmp_path):
    _, blind = _sample(tmp_path)
    packet = build_blind_packet(blind, "R1", "salt")
    packet[0]["overlap"] = [{"rule_id": "P001"}]
    assert any("overlap" in leak for leak in blind_leakage(packet))


# ---- fail-closed verification, per contract ------------------------------------------

def _packets(units, builder, **kw):
    return {r: builder(units, r, "salt", **kw) for r in REVIEWERS}


def test_each_contract_is_verified_against_its_own_rules(tmp_path):
    findings, blind = _sample(tmp_path)
    verify_findings_packets(findings, _packets(findings,
                                               build_findings_packet))
    verify_blind_packets(blind, _packets(blind, build_blind_packet))


def test_a_findings_packet_holding_a_blind_unit_is_refused(tmp_path):
    findings, blind = _sample(tmp_path)
    packets = _packets(findings, build_findings_packet)
    packets["R1"][0]["track"] = "blind"
    with pytest.raises(SamplingError, match="another track"):
        verify_findings_packets(findings, packets)


def test_a_missing_unit_aborts_rather_than_trimming(tmp_path):
    findings, _ = _sample(tmp_path)
    packets = _packets(findings, build_findings_packet)
    packets["R2"].pop()
    with pytest.raises(SamplingError, match="does not match"):
        verify_findings_packets(findings, packets)


def test_a_forged_sample_id_is_refused(tmp_path):
    _, blind = _sample(tmp_path)
    packets = _packets(blind, build_blind_packet)
    packets["R1"][0]["sample_id"] = "0" * 16
    with pytest.raises(SamplingError, match="does not match"):
        verify_blind_packets(blind, packets)


def test_a_duplicated_unit_is_refused(tmp_path):
    _, blind = _sample(tmp_path)
    packets = _packets(blind, build_blind_packet)
    packets["R1"][1]["sample_id"] = packets["R1"][0]["sample_id"]
    with pytest.raises(SamplingError, match="duplicate"):
        verify_blind_packets(blind, packets)


def test_a_pre_filled_track_a_label_is_refused(tmp_path):
    findings, _ = _sample(tmp_path)
    packets = _packets(findings, build_findings_packet)
    packets["R1"][0]["label"] = "confirmed"
    with pytest.raises(SamplingError, match="pre-filled"):
        verify_findings_packets(findings, packets)


def test_a_pre_filled_track_b_outcome_or_issue_is_refused(tmp_path):
    _, blind = _sample(tmp_path)
    packets = _packets(blind, build_blind_packet)
    packets["R1"][0]["outcome"] = "no_issue_observed"
    with pytest.raises(SamplingError, match="pre-filled"):
        verify_blind_packets(blind, packets)

    packets = _packets(blind, build_blind_packet)
    packets["R2"][0]["issues"] = [{"statement": "x"}]
    with pytest.raises(SamplingError, match="pre-filled"):
        verify_blind_packets(blind, packets)


def test_identical_orders_for_both_reviewers_are_refused(tmp_path):
    findings, _ = _sample(tmp_path)
    packets = _packets(findings, build_findings_packet)
    packets["R2"] = [dict(e) for e in packets["R1"]]
    with pytest.raises(SamplingError, match="same findings order"):
        verify_findings_packets(findings, packets)


def test_the_two_packets_hold_the_same_units_in_different_orders(tmp_path):
    findings, _ = _sample(tmp_path)
    packets = _packets(findings, build_findings_packet)
    assert {e["sample_id"] for e in packets["R1"]} \
        == {e["sample_id"] for e in packets["R2"]}
    assert [e["sample_id"] for e in packets["R1"]] \
        != [e["sample_id"] for e in packets["R2"]]


# ---- the privacy boundary --------------------------------------------------------------

def test_the_public_view_of_a_unit_carries_no_content(tmp_path):
    findings, blind = _sample(tmp_path)
    for unit in findings + blind:
        public = json.dumps(unit.public())
        assert public_output_problem(public) is None, public


@pytest.mark.parametrize("blob, why", [
    ('{"file": "pkg/a.py"}', "file"),
    ('{"snippet": "secret = 1"}', "snippet"),
    ('{"code": "def f(): pass"}', "code"),
    ('{"claim": {}}', "claim"),
    ('{"code_unit": {}}', "code_unit"),
    ('{"x": "C:/project/auditor"}', "path"),
    ('{"x": ".quality-local/real-corpus"}', "path"),
])
def test_the_scrubber_refuses_anything_that_must_stay_local(blob, why):
    assert public_output_problem(blob) is not None, why


def test_a_counts_only_summary_passes_the_scrubber():
    assert public_output_problem(json.dumps(
        {"units": 120, "by_language": {"python": 31},
         "pack_bytes": {"median": 1921}})) is None


# ---- the AI Audit profile is its own report ------------------------------------------

def test_the_audit_summary_reports_its_own_distribution_and_its_skips(
        tmp_path, monkeypatch):
    """MANDATORY. repo / language / query / size bucket, and WHY a pair
    produced nothing. A profile that only showed successes would read as full
    coverage."""
    fake = {"canonical": "c" * 9000,
            "pieces": [{"context_id": "src:1", "text": "s" * 7000}],
            "privacy_manifest": {"files_sent": 2, "pieces_sent": 2}}
    monkeypatch.setattr("tools.real_corpus_audit.build_audit_pack",
                        lambda *_a, **_k: fake)
    tree = _py_tree(tmp_path)
    skips = {"no real candidate files for this query": 3}
    profiles = profile_repository(_spec(), tree,
                                  _report([], language="python"), skips=skips)
    summary = audit_summary(profiles, skips, {"dotnet": 2})

    for key in ("by_repo", "by_language", "by_query", "by_size_bucket",
                "skipped", "canonical_pack_bytes", "source_bytes",
                "caps_in_play", "project_languages_no_query_supports"):
        assert key in summary, key
    assert summary["by_repo"] == {"repo-one": len(profiles)}
    assert summary["by_language"] == {"python": len(profiles)}
    assert set(summary["by_query"]) == {f"AI00{i}" for i in range(1, 9)}
    assert summary["skipped"]["no real candidate files for this query"] == 3
    assert summary["project_languages_no_query_supports"] == {"dotnet": 2}
    assert summary["caps_in_play"] == [12288, 16384]
    # The point of per-query caps: this ONE pack (7000 source bytes) is
    # `small` under AI001's 16384 and `medium` under the 12288 the rest use.
    # A single shared cap would have to lie about one of them.
    buckets = {p.query_id: p.size_bucket for p in profiles}
    assert buckets["AI001"] == "small"
    assert {buckets[f"AI00{i}"] for i in range(2, 9)} == {"medium"}
    assert summary["by_size_bucket"] == {"medium": 7, "small": 1}


def test_the_audit_denominator_is_packs_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "tools.real_corpus_audit.build_audit_pack",
        lambda *_a, **_k: {"canonical": "c" * 100, "pieces": [],
                           "privacy_manifest": {"files_sent": 1,
                                                "pieces_sent": 1}})
    profiles = profile_repository(_spec(), _py_tree(tmp_path),
                                  _report([], language="python"), skips={})
    summary = audit_summary(profiles, {}, {})
    assert summary["packs"] == len(profiles)
    assert "PACKS" in summary["what"]
    assert "findings" in summary["what"] and "blind" in summary["what"]


# ---- the whole thing, end to end, twice ----------------------------------------------

def _fixture_corpus(tmp_path: Path) -> tuple[Path, Path]:
    """A miniature corpus on disk: two repositories, real trees, real
    reports. Enough to drive `build_corpus` without a network or a clone."""
    root = tmp_path / "corpus"
    specs = []
    for nth, repo_id in enumerate(("alpha", "beta")):
        tree = root / "repos" / repo_id
        tree.mkdir(parents=True)
        _py_tree(tree, functions=5, files=2)
        findings = [_finding(i, file=f"pkg/mod{i % 2}.py", line=5 + i * 3)
                    for i in range(6)]
        report = _report(findings, root=".", language="python")
        report["analysis_manifest"] = {"catalog": [
            {"rule_id": "P001", "title": "hardcoded credential",
             "description": "a literal secret in source",
             "category": "secrets"}]}
        out = root / "reports" / repo_id
        out.mkdir(parents=True)
        (out / "report.json").write_text(json.dumps(report), encoding="utf-8")
        specs.append({"repo_id": repo_id,
                      "url": f"https://github.com/o/{repo_id}",
                      "commit": f"{nth:040x}", "license_spdx": "MIT",
                      "language": "python"})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"corpus": "REAL-CORPUS-1A",
                                    "tool_commit": "b" * 40,
                                    "repositories": specs}), encoding="utf-8")
    return manifest, root


def test_running_the_whole_build_twice_is_byte_identical(tmp_path):
    """MANDATORY. Same corpus in, same everything out — summary and both
    tracks' packets. A sample that moves between runs cannot be reviewed."""
    from tools.real_corpus_sample import build_corpus
    manifest, root = _fixture_corpus(tmp_path)

    first = json.dumps(build_corpus(manifest, root), sort_keys=True)
    packets_first = {p.name: p.read_bytes()
                     for p in sorted((root / "packets").glob("*.json"))}
    second = json.dumps(build_corpus(manifest, root), sort_keys=True)
    packets_second = {p.name: p.read_bytes()
                      for p in sorted((root / "packets").glob("*.json"))}

    assert first == second
    assert packets_first == packets_second
    assert set(packets_first) == {"packet_findings_R1.json",
                                  "packet_findings_R2.json",
                                  "packet_blind_R1.json",
                                  "packet_blind_R2.json"}


def test_the_public_summary_carries_no_path_snippet_or_pack(tmp_path):
    """MANDATORY. The summary is the only thing that leaves `.quality-local`,
    so it is checked against the scrubber, not trusted."""
    from tools.real_corpus_sample import build_corpus
    manifest, root = _fixture_corpus(tmp_path)
    summary = build_corpus(manifest, root)
    assert public_output_problem(json.dumps(summary)) is None


def test_the_summary_keeps_the_three_denominators_apart(tmp_path):
    """Scanner findings, blind code units and AI Audit packs are three
    different populations. The summary must never add them or share a cap
    between them."""
    from tools.real_corpus_sample import build_corpus
    manifest, root = _fixture_corpus(tmp_path)
    summary = build_corpus(manifest, root)

    review = summary["single_finding_review"]
    blind = summary["blind_human_review"]
    audit = summary["ai_audit_packs"]

    assert review["cap"] == REVIEW_PACK_CAP
    assert "cap" not in blind, "a blind unit has no packer and no cap"
    assert blind["size_reference"]
    assert "FINDINGS" in review["what"]
    assert "CODE UNITS" in blind["what"]
    # no shared total anywhere
    assert "units" in review and "units" in blind and "packs" in audit
    assert summary["what_bounds_a_review_pack"]["applies_to"].startswith(
        "single_finding_review")


def test_the_summary_does_not_claim_a_large_bucket_it_did_not_reach(tmp_path):
    from tools.real_corpus_sample import build_corpus
    manifest, root = _fixture_corpus(tmp_path)
    review = build_corpus(manifest, root)["single_finding_review"]
    assert review["large_bucket_met"] == (
        review["large_bucket_units"] >= review["large_bucket_target"])


def test_the_blind_overlap_join_is_written_beside_the_sample_not_into_it(
        tmp_path):
    from tools.real_corpus_sample import build_corpus
    manifest, root = _fixture_corpus(tmp_path)
    build_corpus(manifest, root)
    overlap = json.loads((root / "blind_overlap.json").read_text(
        encoding="utf-8"))
    assert isinstance(overlap, dict)
    for name in ("packet_blind_R1.json", "packet_blind_R2.json"):
        packet = json.loads((root / "packets" / name).read_text(
            encoding="utf-8"))
        assert blind_leakage(packet["units"]) == []
        assert "overlap" not in json.dumps(packet)

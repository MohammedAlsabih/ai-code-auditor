"""REAL-CORPUS-1B: the human review workflow.

What is proved here is that a returned file can be TIED to the exact material
the reviewer was shown. A label formed on material that has since changed is
not evidence, and a tool that quietly accepts it produces numbers nobody
should believe.

No label is created anywhere in this file except as test input, and no test
computes a quality result.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tools.real_corpus_review import (
    EVIDENCE_MAX_CHARS,
    KAPPA_FLOOR,
    MAX_ISSUES_PER_UNIT,
    OTHER_RULE,
    PROTOCOL_VERSION,
    REASON_MAX_CHARS,
    RESULT_MAX_BYTES,
    STATEMENT_MAX_CHARS,
    ReviewError,
    _same_material,
    agreement,
    build_bundle,
    bundle_problem,
    cohens_kappa,
    digest,
    disagreement,
    handoff_dir,
    import_r3,
    import_result,
    main,
    public_output_problem,
    r3_packet,
    read_json,
    render_r3_ui,
    run_salt,
    render_ui,
    write_atomic,
    write_bundles,
)
from tools.real_corpus_sample import (
    REVIEWERS,
    TRACK_A_LABEL_FIELDS,
    TRACK_B_ISSUE_FIELDS,
)

# ---- fixtures: a miniature pair of packets ---------------------------------------------


def _finding_entry(n: int, position: int) -> dict:
    return {
        "position": position, "sample_id": f"{n:016x}", "track": "findings",
        "language": "python",
        "claim": {"rule_id": "P001", "title": f"t{n}", "detail": f"d{n}",
                  "file": f"pkg/m{n}.py", "line": 10 + n,
                  "snippet": f"secret_{n} = 1"},
        "judged_on": {"source_window": f"{10+n}: secret_{n} = 1",
                      "source_span": f"{n}-{n+40}",
                      "rule_definition": {"rule_id": "P001", "title": "cred"},
                      "manifest_evidence": [], "execution_evidence": {}},
        **{k: "" for k in TRACK_A_LABEL_FIELDS},
    }


def _blind_entry(n: int, position: int) -> dict:
    return {
        "position": position, "sample_id": f"{n + 500:016x}", "track": "blind",
        "language": "python",
        "code_unit": {"file": f"pkg/b{n}.py", "start_line": 100,
                      "end_line": 140, "file_context": "import os",
                      "code": "def f():\n    return 1"},
        "applicable_rules": [{"rule_id": "P001", "title": "cred",
                              "description": "d", "category": "secrets"},
                             {"rule_id": "R007", "title": "xss",
                              "description": "d", "category": "web"}],
        "outcome": "", "issues": [],
    }


def _packets(reviewer: str) -> dict:
    """R1 in order, R2 reversed — the two orders the sampler fixed."""
    findings = [_finding_entry(n, n + 1) for n in range(4)]
    blind = [_blind_entry(n, n + 1) for n in range(3)]
    if reviewer == "R2":
        findings = list(reversed(findings))
        blind = list(reversed(blind))
        for pos, e in enumerate(findings, 1):
            e["position"] = pos
        for pos, e in enumerate(blind, 1):
            e["position"] = pos
    return {"findings": findings, "blind": blind}


# r3_packet has no default salt on purpose: a seed written in the
# repository is a seed R3 can replay. Tests supply their own.
SALT = "test-run-salt-0123456789abcdef"


def _bundle(reviewer: str = "R1") -> dict:
    return build_bundle(_packets(reviewer), reviewer)


def _answer_findings(entry: dict, label: str = "confirmed") -> dict:
    e = json.loads(json.dumps(entry))
    e.update({"label": label, "level": "error", "gate": "block",
              "actionability": "actionable",
              "evidence_sufficiency": "sufficient",
              "reason": "the line assigns a literal secret"})
    return e


def _answer_blind(entry: dict, outcome: str = "issues_found") -> dict:
    e = json.loads(json.dumps(entry))
    e["outcome"] = outcome
    e["issues"] = ([{"rule_id": "P001", "line": 110, "span": "105-115",
                     "statement": "a literal credential is assigned",
                     "evidence": "line 110 assigns a quoted secret",
                     "level": "error", "actionability": "actionable"}]
                   if outcome == "issues_found" else [])
    return e


def _returned(reviewer: str = "R1", *, complete: bool = True,
              label: str = "confirmed", outcome: str = "issues_found") -> dict:
    b = _bundle(reviewer)
    f = [_answer_findings(e, label) for e in b["tracks"]["findings"]["entries"]]
    bl = [_answer_blind(e, outcome) for e in b["tracks"]["blind"]["entries"]]
    if not complete:
        for k in TRACK_A_LABEL_FIELDS:
            f[0][k] = ""
    return {"corpus": "REAL-CORPUS-1B",
            "protocol_version": PROTOCOL_VERSION,
            "bundle_id": b["bundle_id"],
            "reviewer": reviewer,
            "track_digests": {t: b["tracks"][t]["digest"]
                              for t in ("findings", "blind")},
            "tracks": {"findings": {"entries": f}, "blind": {"entries": bl}},
            "complete": complete}


# ---- bundles ----------------------------------------------------------------------------

def test_a_bundle_holds_each_reviewers_own_order():
    r1, r2 = _bundle("R1"), _bundle("R2")
    ids1 = [e["sample_id"] for e in r1["tracks"]["findings"]["entries"]]
    ids2 = [e["sample_id"] for e in r2["tracks"]["findings"]["entries"]]
    assert set(ids1) == set(ids2), "the same units"
    assert ids1 != ids2, "in different orders"


def test_a_bundle_carries_no_repo_name_path_overlap_or_label():
    for reviewer in REVIEWERS:
        b = _bundle(reviewer)
        assert bundle_problem(b) is None
        blob = json.dumps(b)
        for forbidden in ("repo_id", "overlap", "has_finding", "verdict",
                          "scanner_level", "fingerprint", "project_root",
                          ".quality-local"):
            assert forbidden not in blob


def test_a_prefilled_bundle_is_refused():
    b = _bundle("R1")
    b["tracks"]["findings"]["entries"][0]["label"] = "confirmed"
    assert "pre-filled" in (bundle_problem(b) or "")

    b = _bundle("R1")
    b["tracks"]["blind"]["entries"][0]["outcome"] = "no_issue_observed"
    assert "pre-filled" in (bundle_problem(b) or "")


def test_bundles_and_checksums_are_deterministic(tmp_path):
    """Regenerating from the same corpus must produce the same bytes, or two
    reviewers could be handed materially different work under one name."""
    packets = tmp_path / "packets"
    packets.mkdir()
    for reviewer in REVIEWERS:
        p = _packets(reviewer)
        for track in ("findings", "blind"):
            (packets / f"packet_{track}_{reviewer}.json").write_text(
                json.dumps({"units": p[track]}), encoding="utf-8")

    first_root = tmp_path / ".quality-local" / "one"
    second_root = tmp_path / ".quality-local" / "two"
    a = write_bundles(first_root, packets)
    b = write_bundles(second_root, packets)
    assert a == b
    for reviewer in REVIEWERS:
        for name in (f"bundle_{reviewer}.json", f"review_{reviewer}.html"):
            assert (handoff_dir(first_root, reviewer) / name).read_bytes() \
                == (handoff_dir(second_root, reviewer) / name).read_bytes()


def test_the_bundle_digest_changes_if_a_unit_changes():
    b = _bundle("R1")
    before = b["tracks"]["findings"]["digest"]
    entries = json.loads(json.dumps(b["tracks"]["findings"]["entries"]))
    entries[0]["claim"]["detail"] = "something else"
    assert digest(entries) != before


# ---- the offline UI ----------------------------------------------------------------------

@pytest.mark.parametrize("reviewer", REVIEWERS)
def test_the_ui_reaches_no_network_at_all(reviewer):
    """MANDATORY zero-network check. A reviewer's screen must not be able to
    fetch, report, or load anything."""
    html = render_ui(reviewer)
    for banned in ("http://", "https://", "//cdn", "fetch(", "XMLHttpRequest",
                   "WebSocket", "EventSource", "navigator.sendBeacon",
                   "import(", "src=", "href=", "@import", "integrity=",
                   "googleapis", "analytics", "gtag", "subprocess"):
        assert banned not in html, f"the UI references {banned}"


def test_the_ui_renders_the_two_tracks_through_separate_forms():
    html = render_ui("R1")
    assert "renderFindings" in html and "renderBlind" in html
    # Track B must not offer the adjudication vocabulary
    blind = html.split("function renderBlind")[1].split("function render(")[0]
    assert "false_positive" not in blind
    assert "OUTCOMES" in blind and "issues" in blind


def test_the_ui_refuses_a_bundle_belonging_to_the_other_reviewer():
    html = render_ui("R1")
    assert 'loaded.reviewer !== REVIEWER' in html
    # ...and refuses one made under a different protocol revision
    assert 'loaded.protocol_version !== PROTOCOL_VERSION' in html


def test_the_ui_marks_an_incomplete_export_as_a_draft():
    html = render_ui("R1")
    assert 'out.complete ? "" : "_DRAFT"' in html


# ---- fail-closed import -------------------------------------------------------------------

def test_a_faithful_result_is_accepted():
    out = import_result(_returned("R1"), _bundle("R1"))
    assert out["state"] == "accepted" and out["complete"] is True
    assert out["tracks"]["findings"]["units"] == 4
    assert out["tracks"]["blind"]["units"] == 3


@pytest.mark.parametrize("path", [
    ("findings", "claim", "detail"),
    ("findings", "judged_on", "source_window"),
    ("blind", "code_unit", "code"),
    ("blind", "code_unit", "file_context"),
])
def test_editing_the_material_that_was_judged_is_refused(path):
    """MANDATORY. If the code, the claim or the context came back changed,
    the label was formed on something else."""
    track, outer, inner = path
    r = _returned("R1")
    r["tracks"][track]["entries"][0][outer][inner] = "tampered"
    with pytest.raises(ReviewError, match="was modified"):
        import_result(r, _bundle("R1"))


def test_editing_applicable_rules_is_refused():
    r = _returned("R1")
    r["tracks"]["blind"]["entries"][0]["applicable_rules"].append(
        {"rule_id": "ZZZ", "title": "x", "description": "y", "category": "z"})
    with pytest.raises(ReviewError, match="was modified"):
        import_result(r, _bundle("R1"))


def test_a_forged_sample_id_is_refused():
    r = _returned("R1")
    r["tracks"]["findings"]["entries"][0]["sample_id"] = "f" * 16
    with pytest.raises(ReviewError, match="unknown sample_id"):
        import_result(r, _bundle("R1"))


def test_a_missing_unit_is_refused():
    r = _returned("R1")
    r["tracks"]["blind"]["entries"].pop()
    with pytest.raises(ReviewError, match="entries returned"):
        import_result(r, _bundle("R1"))


def test_a_duplicated_unit_is_refused():
    r = _returned("R1")
    entries = r["tracks"]["findings"]["entries"]
    entries[1]["sample_id"] = entries[0]["sample_id"]
    with pytest.raises(ReviewError, match="duplicate sample_id"):
        import_result(r, _bundle("R1"))


def test_a_swapped_sample_is_refused():
    """Two units keeping their own answers but exchanging ids: every id is
    still present exactly once, so only the byte-for-byte check catches it."""
    r = _returned("R1")
    e = r["tracks"]["findings"]["entries"]
    e[0]["sample_id"], e[1]["sample_id"] = e[1]["sample_id"], e[0]["sample_id"]
    with pytest.raises(ReviewError, match="was modified"):
        import_result(r, _bundle("R1"))


def test_a_cross_track_entry_is_refused():
    r = _returned("R1")
    r["tracks"]["findings"]["entries"][0]["track"] = "blind"
    with pytest.raises(ReviewError, match="another track"):
        import_result(r, _bundle("R1"))


def test_an_extra_key_is_refused_not_ignored():
    """An ignored key is a place to smuggle something past this tool into
    whatever reads the accepted result next."""
    r = _returned("R1")
    r["tracks"]["findings"]["entries"][0]["ai_suggestion"] = "confirmed"
    with pytest.raises(ReviewError, match="unexpected keys"):
        import_result(r, _bundle("R1"))


def test_r1s_file_is_refused_under_r2s_name():
    """MANDATORY. The bundles differ in order; accepting one for the other
    would silently mis-attribute every answer."""
    with pytest.raises(ReviewError, match="belongs to"):
        import_result(_returned("R1"), _bundle("R2"))


def test_a_partial_file_stays_a_draft_and_is_not_scored():
    out = import_result(_returned("R1", complete=False), _bundle("R1"))
    assert out["state"] == "draft"
    assert out["complete"] is False and len(out["incomplete"]) == 1
    with pytest.raises(ReviewError, match="draft"):
        agreement(out, import_result(_returned("R2"), _bundle("R2")))


def test_an_illegal_label_is_refused():
    r = _returned("R1", label="definitely")
    with pytest.raises(ReviewError, match="label must be one of"):
        import_result(r, _bundle("R1"))


def test_a_label_without_a_reason_is_refused():
    r = _returned("R1")
    r["tracks"]["findings"]["entries"][0]["reason"] = "   "
    with pytest.raises(ReviewError, match="reason"):
        import_result(r, _bundle("R1"))


def test_issues_found_with_no_issue_is_refused():
    r = _returned("R1")
    r["tracks"]["blind"]["entries"][0]["issues"] = []
    with pytest.raises(ReviewError, match="nothing to review"):
        import_result(r, _bundle("R1"))


def test_an_issue_outside_the_shown_unit_is_refused():
    """The reviewer saw lines 100-140. A finding at line 9000 cannot have
    come from the material in front of them."""
    r = _returned("R1")
    r["tracks"]["blind"]["entries"][0]["issues"][0]["line"] = 9000
    with pytest.raises(ReviewError, match="outside the unit shown"):
        import_result(r, _bundle("R1"))

    r = _returned("R1")
    r["tracks"]["blind"]["entries"][0]["issues"][0]["span"] = "1-9000"
    with pytest.raises(ReviewError, match="outside the unit shown"):
        import_result(r, _bundle("R1"))


def test_a_malformed_span_is_refused():
    r = _returned("R1")
    r["tracks"]["blind"]["entries"][0]["issues"][0]["span"] = "somewhere"
    with pytest.raises(ReviewError, match="not start-end"):
        import_result(r, _bundle("R1"))


def test_a_rule_outside_the_menu_is_refused_but_OTHER_is_allowed():
    r = _returned("R1")
    r["tracks"]["blind"]["entries"][0]["issues"][0]["rule_id"] = "N999"
    with pytest.raises(ReviewError, match="not in applicable_rules"):
        import_result(r, _bundle("R1"))

    r = _returned("R1")
    r["tracks"]["blind"]["entries"][0]["issues"][0]["rule_id"] = OTHER_RULE
    out = import_result(r, _bundle("R1"))
    sid = _bundle("R1")["tracks"]["blind"]["entries"][0]["sample_id"]
    assert out["tracks"]["blind"]["answers"][sid]["issues"][0]["rule_id"] \
        == OTHER_RULE


def test_control_characters_in_prose_are_refused():
    r = _returned("R1")
    r["tracks"]["findings"]["entries"][0]["reason"] = "looks bad\x00hidden"
    with pytest.raises(ReviewError, match="control character"):
        import_result(r, _bundle("R1"))


def test_oversized_prose_is_refused():
    r = _returned("R1")
    r["tracks"]["findings"]["entries"][0]["reason"] = "x" * 5000
    with pytest.raises(ReviewError, match="longer than"):
        import_result(r, _bundle("R1"))


# ---- agreement --------------------------------------------------------------------------

def test_kappa_reports_raw_agreement_beside_it():
    out = cohens_kappa(["a", "a", "b"], ["a", "a", "b"], ("a", "b"))
    assert out["kappa"] == 1.0 and out["raw_agreement"] == 1.0
    assert out["defined"] is True


def test_the_two_tracks_are_never_pooled():
    a = import_result(_returned("R1"), _bundle("R1"))
    b = import_result(_returned("R2"), _bundle("R2"))
    out = agreement(a, b)
    assert set(out["tracks"]) == {"findings", "blind"}
    assert out["tracks"]["findings"]["primary_field"] == "label"
    assert out["tracks"]["blind"]["primary_field"] == "outcome"
    assert "overall" not in out and "combined" not in out
    # secondary fields sit apart from the kappa that decides the gate
    assert set(out["tracks"]["findings"]["secondary"]) == {
        "level", "gate", "actionability", "evidence_sufficiency"}
    assert "issue_matching" in out["tracks"]["blind"]


def test_the_floor_is_point_four_on_both_tracks():
    a = import_result(_returned("R1"), _bundle("R1"))
    b = import_result(_returned("R2"), _bundle("R2"))
    out = agreement(a, b)
    assert out["kappa_floor"] == KAPPA_FLOOR == 0.4
    assert out["quality_result_permitted"] == all(
        out["tracks"][t]["meets_floor"] for t in ("findings", "blind"))


def test_a_disagreeing_pair_reports_no_quality_result():
    a = import_result(_returned("R1", label="confirmed",
                                outcome="issues_found"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive",
                                outcome="no_issue_observed"), _bundle("R2"))
    out = agreement(a, b)
    assert out["tracks"]["findings"]["primary"]["raw_agreement"] == 0.0
    assert out["quality_result_permitted"] is False


# ---- R3 ----------------------------------------------------------------------------------

def test_r3_is_refused_until_both_reviews_are_accepted():
    draft = import_result(_returned("R1", complete=False), _bundle("R1"))
    good = import_result(_returned("R2"), _bundle("R2"))
    with pytest.raises(ReviewError, match="accepted in full"):
        r3_packet(draft, good, salt=SALT)


def test_r3_contains_only_disagreements_and_hides_identity():
    a = import_result(_returned("R1", label="confirmed"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive"), _bundle("R2"))
    packet = r3_packet(a, b, _bundles(), salt=SALT)
    assert packet, "there are disagreements to arbitrate"
    for case in packet:
        assert set(case) == {"sample_id", "track", "disputed_fields",
                             "material", "judgement_A", "judgement_B",
                             "final", "reason"}
        assert case["final"] == {} and case["reason"] == ""
        blob = json.dumps(case)
        assert "R1" not in blob and "R2" not in blob
        assert case["judgement_A"] != case["judgement_B"]


def test_r3_is_empty_when_the_two_agree():
    a = import_result(_returned("R1"), _bundle("R1"))
    b = import_result(_returned("R2"), _bundle("R2"))
    assert r3_packet(a, b, _bundles(), salt=SALT) == []


def test_r3_neither_votes_nor_reconciles():
    import tools.real_corpus_review as mod
    src = Path(mod.__file__).read_text(encoding="utf-8")
    body = src.split("def r3_packet")[1].split("\ndef ")[0]
    for banned in ("majority", "Counter", "most_common", "resolve("):
        assert banned not in body, f"r3_packet references {banned}"


# ---- the public boundary ------------------------------------------------------------------

@pytest.mark.parametrize("blob, why", [
    ('{"code": "def f(): pass"}', "code"),
    ('{"code_unit": {}}', "code_unit"),
    ('{"claim": {}}', "claim"),
    ('{"label": "confirmed"}', "a label"),
    ('{"outcome": "issues_found"}', "an outcome"),
    ('{"issues": []}', "issues"),
    ('{"reason": "because"}', "reviewer prose"),
    ('{"entries": []}', "a raw packet"),
    ('{"answers": {}}', "raw answers"),
    ('{"x": "C:/synthetic/workspace"}', "a path"),
    ('{"x": ".quality-local/real-corpus"}', "a local path"),
])
def test_the_scrubber_refuses_anything_that_must_stay_local(blob, why):
    assert public_output_problem(blob) is not None, why


def test_a_counts_only_summary_passes_the_scrubber():
    assert public_output_problem(json.dumps(
        {"bundles": {"R1": {"units": 204}}, "kappa_floor": 0.4})) is None


def test_the_scrubber_reads_keys_as_keys_not_as_text():
    """REGRESSION. A counts-only agreement summary says which field kappa was
    computed on: `"primary_field": "label"`. A blunt scan of the encoded text
    refused it for "contains label" — the same class of bug as the bundle
    guard scanning a JSON dump, and it made the whole `agreement` command
    unprintable."""
    summary = {"tracks": {"findings": {"primary_field": "label",
                                       "units_both_completed": 120,
                                       "meets_floor": False},
                          "blind": {"primary_field": "outcome",
                                    "units_both_completed": 84,
                                    "meets_floor": False}},
               "kappa_floor": 0.4, "quality_result_permitted": False}
    assert public_output_problem(json.dumps(summary)) is None


def test_the_scrubber_still_refuses_the_real_thing():
    """The other half: naming a field is fine, carrying one is not."""
    assert public_output_problem(json.dumps(
        {"tracks": {"findings": {"answers": {"abc": {"label": "confirmed"}}}}})
    ) is not None
    assert public_output_problem(json.dumps(
        {"cases": [{"material": {"code": "x = 1"}}]})) is not None


def test_the_tool_creates_no_label_of_its_own():
    """Every label value in this module must be a CONTRACT constant or a
    refusal message — never a value assigned to a reviewer's answer."""
    import tools.real_corpus_review as mod
    src = Path(mod.__file__).read_text(encoding="utf-8")
    for assignment in re.findall(r'\["label"\]\s*=\s*(.+)', src):
        pytest.fail(f"the tool assigns a label: {assignment}")
    for assignment in re.findall(r'\["outcome"\]\s*=\s*(.+)', src):
        pytest.fail(f"the tool assigns an outcome: {assignment}")


def test_the_tool_starts_no_subprocess_and_opens_no_socket():
    """Checked against the CODE, not the prose. A docstring that says "no
    WebSocket" contains the word `WebSocket`, so a substring scan over the
    whole file fails on its own documentation — and would have to be relaxed
    until it stopped meaning anything."""
    import ast

    import tools.real_corpus_review as mod
    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("subprocess", "socket", "urllib", "requests", "http",
                   "asyncio", "ftplib", "smtplib", "telnetlib", "webbrowser"):
        assert banned not in imported, f"the tool imports {banned}"

    # Bare builtins are the dangerous ones. `re.compile` is a regex, not code
    # execution, so the two forms are checked separately rather than banning
    # the word `compile` and having to carve out an exception that would also
    # let `builtins.compile` through.
    bare: set[str] = set()
    attrs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                bare.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                attrs.add(fn.attr)
    for banned in ("exec", "eval", "compile", "__import__", "open"):
        assert banned not in bare, f"the tool calls the builtin {banned}()"
    for banned in ("system", "popen", "spawn", "urlopen", "connect",
                   "sendall", "request"):
        assert banned not in attrs, f"the tool calls .{banned}()"


def test_issue_fields_match_the_sampler_contract():
    assert set(TRACK_B_ISSUE_FIELDS) == {"rule_id", "line", "span",
                                         "statement", "evidence", "level",
                                         "actionability"}


# ---- the guard must inspect the DATA, not its encoding ----------------------------------

def test_a_url_in_reviewed_source_is_not_a_local_path():
    """REGRESSION. The first run against the real corpus was refused for 100
    "local paths", every one of which was a URL scheme inside the code being
    reviewed: `[A-Za-z]:[\\/]` matches the `s:/` of `https://`."""
    b = _bundle("R1")
    b["tracks"]["blind"]["entries"][0]["code_unit"]["code"] = (
        'r = get("https://example.test/x")\n'
        'db = connect("mongodb://host:1234")\n'
        '# see file:///tmp-like docs\n')
    assert bundle_problem(b) is None


def test_a_real_windows_path_is_still_refused():
    """The other half: loosening the rule must not disarm it."""
    for planted in ("E:/synthetic/workspace/x", "D:" + chr(92) + "work",
                    ' open("/home/someone/f")', ".quality-local/real-corpus"):
        b = _bundle("R1")
        b["tracks"]["blind"]["entries"][0]["code_unit"]["code"] = planted
        assert bundle_problem(b) == "carries a local path", planted


def test_source_containing_a_colon_then_newline_is_not_a_path():
    r"""REGRESSION. Scanning the JSON ENCODING makes `class A:` followed by a
    newline read as `A:\`, because the encoder wrote a literal backslash-n.
    Real Python source is full of that shape."""
    b = _bundle("R1")
    b["tracks"]["blind"]["entries"][0]["code_unit"]["code"] = (
        "class A:\n    pass\n\nclass B:\n    pass\n")
    assert bundle_problem(b) is None


def test_the_word_verdict_inside_reviewed_code_is_not_a_forbidden_key():
    """REGRESSION. The forbidden-key check must look at KEYS. A snippet that
    merely mentions `verdict` is code under review, not leaked scanner
    state."""
    b = _bundle("R1")
    b["tracks"]["blind"]["entries"][0]["code_unit"]["code"] = (
        'if summary["verdict"] == "block":  # overlap of concerns\n')
    assert bundle_problem(b) is None


def test_a_real_forbidden_key_is_still_refused():
    b = _bundle("R1")
    b["tracks"]["blind"]["entries"][0]["overlap"] = [{"rule_id": "P001"}]
    assert bundle_problem(b) == "carries overlap"

    b = _bundle("R1")
    b["tracks"]["findings"]["entries"][0]["claim"]["repo_id"] = "flask"
    assert bundle_problem(b) == "carries repo_id"


# ---- revision 2: the bundle's identity binds the answers to the material ------------------

def test_a_second_bundle_does_not_inherit_the_first_bundles_answers():
    """The defect this closes: saved progress was keyed by `R1`/`R2` alone.
    A second bundle for the same reviewer would then have shown that
    reviewer their own earlier judgement, already filled in, against
    material they had not looked at in this bundle."""
    first = _bundle("R1")
    packets = _packets("R1")
    packets["findings"][0]["claim"]["detail"] = "a different claim entirely"
    second = build_bundle(packets, "R1")

    # same reviewer, an overlapping sample_id, DIFFERENT storage key
    assert first["tracks"]["findings"]["entries"][0]["sample_id"] == \
        second["tracks"]["findings"]["entries"][0]["sample_id"]
    assert first["bundle_id"] != second["bundle_id"]

    html = render_ui("R1")
    assert 'const key = "rc1b-" + REVIEWER + "-" + loaded.bundle_id' in html
    # and the key is not computable before a bundle has been validated
    assert "let KEY = null, answers = {}" in html
    # ...and nothing is swapped in until every check has passed
    assert html.index("localStorage.getItem") < html.index("KEY = key")


def test_answers_are_read_only_after_the_bundle_is_accepted():
    html = render_ui("R1")
    load = html.split('addEventListener("change"')[1].split("readAsText")[0]
    for check in ("loaded.protocol_version !== PROTOCOL_VERSION",
                  "loaded.reviewer !== REVIEWER", "!loaded.bundle_id"):
        assert load.index(check) < load.index("localStorage.getItem"), check


def test_a_localStorage_failure_is_shown_not_swallowed():
    html = render_ui("R1")
    save = html.split("function store()")[1].split("function esc")[0]
    assert "catch" in save and "warn(" in save
    assert "NOT SAVED" in save


def test_the_ui_escapes_quotes_in_attributes():
    """Issue fields are interpolated into `value="..."`. Without escaping the
    quote, a reviewer's own text closes the attribute."""
    html = render_ui("R1")
    esc = html.split("function esc(")[1].split("function opts")[0]
    assert "&quot;" in esc and "&#39;" in esc
    assert '/[&<>"\']/g' in esc


def test_a_result_from_another_bundle_is_refused():
    """Forgery: the ids all line up, but the answers were formed on other
    material."""
    other = _returned("R1")
    other["bundle_id"] = "0000000000000000"
    with pytest.raises(ReviewError, match="answers a different bundle"):
        import_result(other, _bundle("R1"))


def test_a_tampered_track_digest_is_refused():
    bad = _returned("R1")
    bad["track_digests"]["blind"] = "f" * 64
    with pytest.raises(ReviewError, match="digest does not match"):
        import_result(bad, _bundle("R1"))


def test_an_old_protocol_revision_is_refused():
    old = _returned("R1")
    old["protocol_version"] = 1
    with pytest.raises(ReviewError, match="protocol version"):
        import_result(old, _bundle("R1"))


def test_an_extra_top_level_key_is_refused():
    """An extra key inside an entry was already refused. The top level is
    just as much a place to smuggle something past this tool."""
    smuggled = _returned("R1")
    smuggled["notes"] = {"anything": "at all"}
    with pytest.raises(ReviewError, match="unexpected top-level keys"):
        import_result(smuggled, _bundle("R1"))

    missing = _returned("R1")
    del missing["track_digests"]
    with pytest.raises(ReviewError, match="missing top-level keys"):
        import_result(missing, _bundle("R1"))


def test_an_extra_key_in_a_track_block_is_refused():
    bad = _returned("R1")
    bad["tracks"]["findings"]["summary"] = {"confirmed": 4}
    with pytest.raises(ReviewError, match="unexpected keys"):
        import_result(bad, _bundle("R1"))


def test_a_false_complete_flag_is_recomputed_not_believed():
    """`complete` is the reviewer's file claiming something about itself."""
    lying = _returned("R1", complete=False)
    lying["complete"] = True
    out = import_result(lying, _bundle("R1"))
    assert out["state"] == "draft"
    assert out["claimed_complete"] is True
    assert out["incomplete"], "the unanswered unit is named"


# ---- revision 2: kappa is undefined, not perfect ------------------------------------------

def test_one_category_on_both_sides_leaves_kappa_undefined():
    """THE DEFECT: two reviewers who answer `confirmed` to all 40 units have
    an expected agreement of 1.0, so kappa is 0/0. Revision 1 reported 1.0
    and passed the 0.4 floor on the strength of a division by zero."""
    out = cohens_kappa(["confirmed"] * 40, ["confirmed"] * 40,
                       ("confirmed", "false_positive", "uncertain"))
    assert out["kappa"] is None
    assert out["defined"] is False
    assert out["raw_agreement"] == 1.0, "the real observation is still shown"
    assert out["expected_agreement"] == 1.0
    assert "undefined_reason" in out


def test_an_undefined_kappa_does_not_meet_the_floor():
    one = _returned("R1", label="confirmed", outcome="no_issue_observed")
    two = _returned("R2", label="confirmed", outcome="no_issue_observed")
    out = agreement(import_result(one, _bundle("R1")),
                    import_result(two, _bundle("R2")))
    for track in ("findings", "blind"):
        primary = out["tracks"][track]["primary"]
        assert primary["kappa"] is None and primary["defined"] is False
        assert out["tracks"][track]["meets_floor"] is False
    assert out["quality_result_permitted"] is False


def test_a_label_outside_the_category_set_is_refused_by_kappa():
    with pytest.raises(ReviewError, match="outside the category set"):
        cohens_kappa(["a", "b"], ["a", "elsewhere"], ("a", "b"))


def test_two_results_covering_different_units_are_an_error_not_an_overlap():
    """Scoring the intersection would let one reviewer's omissions choose the
    denominator."""
    short = _returned("R2")
    short["tracks"]["findings"]["entries"].pop()
    bundle = _bundle("R2")
    bundle["tracks"]["findings"]["entries"].pop()
    bundle["tracks"]["findings"]["units"] = len(
        bundle["tracks"]["findings"]["entries"])
    bundle["tracks"]["findings"]["digest"] = digest(
        bundle["tracks"]["findings"]["entries"])
    short["track_digests"]["findings"] = bundle["tracks"]["findings"]["digest"]
    bundle["bundle_id"] = short["bundle_id"]

    with pytest.raises(ReviewError, match="different sample_id sets"):
        agreement(import_result(_returned("R1"), _bundle("R1")),
                  import_result(short, bundle))


# ---- revision 2: R3 can actually arbitrate -------------------------------------------------

def _bundles() -> dict:
    return {r: _bundle(r) for r in REVIEWERS}


def test_r3_receives_the_material_the_reviewers_judged():
    """THE DEFECT: revision 1 handed R3 two bare verdicts. Nobody can
    arbitrate a claim they cannot see."""
    a = import_result(_returned("R1", label="confirmed"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive"), _bundle("R2"))
    packet = r3_packet(a, b, _bundles(), salt=SALT)
    seen = set()
    for case in packet:
        seen.add(case["track"])
        if case["track"] == "findings":
            assert set(case["material"]) == {"claim", "judged_on"}
            assert case["material"]["claim"]["snippet"]
            assert case["material"]["judged_on"]["source_window"]
        else:
            assert set(case["material"]) == {"code_unit", "applicable_rules"}
            assert case["material"]["code_unit"]["code"]
            assert case["material"]["applicable_rules"]
    assert "findings" in seen


def test_r3_without_the_bundles_is_refused_rather_than_built_blind():
    a = import_result(_returned("R1", label="confirmed"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive"), _bundle("R2"))
    with pytest.raises(ReviewError, match="no original material"):
        r3_packet(a, b, salt=SALT)


def test_the_same_outcome_with_different_issues_is_a_disagreement():
    """THE DEFECT, and the more damaging half: both reviewers say this unit
    has problems, and they name entirely different problems. Revision 1
    compared `outcome` alone and sent nobody to arbitrate it."""
    one = _returned("R1", outcome="issues_found")
    two = _returned("R2", outcome="issues_found")
    for e in two["tracks"]["blind"]["entries"]:
        e["issues"][0].update({"rule_id": "R007", "line": 120,
                               "span": "118-125"})
    packet = r3_packet(import_result(one, _bundle("R1")),
                       import_result(two, _bundle("R2")), _bundles(), salt=SALT)
    blind = [c for c in packet if c["track"] == "blind"]
    assert blind, "different issues under the same outcome must reach R3"
    assert blind[0]["disputed_fields"] == ["issue_keys"]


def test_a_secondary_field_difference_is_a_disagreement():
    one = _returned("R1", label="confirmed")
    two = _returned("R2", label="confirmed")
    for e in two["tracks"]["findings"]["entries"]:
        e["gate"] = "review"
    packet = r3_packet(import_result(one, _bundle("R1")),
                       import_result(two, _bundle("R2")), _bundles(), salt=SALT)
    findings = [c for c in packet if c["track"] == "findings"]
    assert findings and findings[0]["disputed_fields"] == ["gate"]


def test_different_wording_alone_is_not_a_disagreement():
    """Two people who reach the same judgement and phrase it differently have
    given a third person nothing to decide."""
    one = _returned("R1", label="confirmed")
    two = _returned("R2", label="confirmed")
    for e in two["tracks"]["findings"]["entries"]:
        e["reason"] = "same conclusion, entirely different sentence"
    for e in two["tracks"]["blind"]["entries"]:
        for issue in e["issues"]:
            issue["evidence"] = "reworded evidence, same rule and line"
            issue["statement"] = "reworded statement"
    assert r3_packet(import_result(one, _bundle("R1")),
                     import_result(two, _bundle("R2")), _bundles(), salt=SALT) == []


def test_disagreement_is_computed_on_the_recorded_fields():
    a = {"label": "confirmed", "level": "error", "gate": "block",
         "actionability": "actionable", "evidence_sufficiency": "sufficient",
         "reason": "x"}
    assert disagreement("findings", a, dict(a)) == []
    assert disagreement("findings", a, {**a, "reason": "y"}) == []
    assert disagreement("findings", a, {**a, "label": "uncertain"}) == ["label"]


# ---- revision 2: R3's return goes through the same door -------------------------------------

def _r3_packet_pair() -> list:
    a = import_result(_returned("R1", label="confirmed"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive"), _bundle("R2"))
    return r3_packet(a, b, _bundles(), salt=SALT)


def _r3_decide(packet: list, *, blind_issues: bool = True) -> list:
    """A COMPLETE arbitration for every case.

    Track B answers with a real issue by default. The first version always
    wrote `{"outcome": "no_issue_observed", "issues": []}` — the one blind
    judgement that exercises none of the per-issue bounds. Nothing ever
    reached them, and `import_r3` was quietly accepting out-of-unit lines,
    rules that were never shown, and 50 000 characters of prose."""
    out = json.loads(json.dumps(packet))
    for case in out:
        case["reason"] = "arbitrated on the material shown"
        if case["track"] == "findings":
            case["final"] = {"label": "confirmed", "level": "error",
                             "gate": "block", "actionability": "actionable",
                             "evidence_sufficiency": "sufficient",
                             "reason": "the claim holds on the window shown"}
        elif blind_issues:
            unit = case["material"]["code_unit"]
            case["final"] = {"outcome": "issues_found", "issues": [{
                "rule_id": case["material"]["applicable_rules"][0]["rule_id"],
                "line": unit["start_line"] + 10,
                "span": f"{unit['start_line']}-{unit['end_line']}",
                "statement": "R3 confirms the issue A named",
                "evidence": "the assignment on that line is literal",
                "level": "error", "actionability": "actionable"}]}
        else:
            case["final"] = {"outcome": "no_issue_observed", "issues": []}
    return out


def test_a_faithful_r3_return_is_accepted():
    packet = _r3_packet_pair()
    out = import_r3(_r3_decide(packet), packet)
    assert out["state"] == "accepted"
    assert out["cases"] == len(packet) and not out["undecided"]
    assert len(out["resolved"]) == len(packet)


def test_r3_material_that_was_edited_is_refused():
    packet = _r3_packet_pair()
    tampered = _r3_decide(packet)
    if tampered[0]["track"] == "findings":
        tampered[0]["material"]["claim"]["snippet"] = "something else"
    else:
        tampered[0]["material"]["code_unit"]["code"] = "something else"
    with pytest.raises(ReviewError, match="`material` was modified"):
        import_r3(tampered, packet)


def test_r3_editing_a_reviewers_judgement_is_refused():
    packet = _r3_packet_pair()
    tampered = _r3_decide(packet)
    tampered[0]["judgement_A"]["label"] = "uncertain"
    with pytest.raises(ReviewError, match="`judgement_A` was modified"):
        import_r3(tampered, packet)


def test_r3_an_incomplete_final_judgement_is_refused():
    packet = _r3_packet_pair()
    partial = _r3_decide(packet)
    findings = next(i for i, c in enumerate(partial)
                    if c["track"] == "findings")
    del partial[findings]["final"]["gate"]
    with pytest.raises(ReviewError):
        import_r3(partial, packet)


def test_r3_a_decision_without_a_reason_is_refused():
    packet = _r3_packet_pair()
    silent = _r3_decide(packet)
    silent[0]["reason"] = "   "
    with pytest.raises(ReviewError, match="needs a reason"):
        import_r3(silent, packet)


def test_r3_an_undecided_case_leaves_the_return_a_draft():
    packet = _r3_packet_pair()
    partial = _r3_decide(packet)
    partial[0]["final"] = {}
    partial[0]["reason"] = ""
    out = import_r3(partial, packet)
    assert out["state"] == "draft"
    assert out["undecided"] == [partial[0]["sample_id"]]


def test_r3_a_case_that_was_never_handed_out_is_refused():
    packet = _r3_packet_pair()
    forged = _r3_decide(packet)
    forged[0]["sample_id"] = "ffffffffffffffff"
    with pytest.raises(ReviewError, match="unknown case"):
        import_r3(forged, packet)


def test_r3_a_dropped_case_is_refused():
    packet = _r3_packet_pair()
    short = _r3_decide(packet)[1:]
    with pytest.raises(ReviewError, match="cases returned for"):
        import_r3(short, packet)


def test_the_same_issue_judged_differently_is_a_disagreement():
    """The third clause of the Track B rule, and the easiest to leave out:
    both reviewers found THE SAME issue — same rule, same line — and graded it
    differently. Nothing about the outcome or the issue keys differs, so only
    a per-key comparison catches it."""
    for field, other in (("level", "warning"),
                         ("actionability", "not_actionable")):
        one = _returned("R1", outcome="issues_found")
        two = _returned("R2", outcome="issues_found")
        for e in two["tracks"]["blind"]["entries"]:
            e["issues"][0][field] = other
        packet = r3_packet(import_result(one, _bundle("R1")),
                           import_result(two, _bundle("R2")), _bundles(), salt=SALT)
        blind = [c for c in packet if c["track"] == "blind"]
        assert blind, f"a differing {field} on a shared issue must reach R3"
        assert blind[0]["disputed_fields"] == [f"issue:P001@110:{field}"], \
            blind[0]["disputed_fields"]


def test_a_shared_issue_graded_identically_creates_nothing():
    """The other half — otherwise every Track B unit would reach arbitration."""
    one = _returned("R1", outcome="issues_found")
    two = _returned("R2", outcome="issues_found")
    assert r3_packet(import_result(one, _bundle("R1")),
                     import_result(two, _bundle("R2")), _bundles(), salt=SALT) == []


def test_the_ab_order_is_deterministic_and_does_not_expose_a_reviewer():
    """Deterministic is not the same as constant. If the shuffle put R1 in
    position A every time, R3 would learn who was who from the first case."""
    a = import_result(_returned("R1", label="confirmed"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive"), _bundle("R2"))
    first = r3_packet(a, b, _bundles(), salt=SALT)
    second = r3_packet(a, b, _bundles(), salt=SALT)
    assert json.dumps(first, sort_keys=True) == json.dumps(second,
                                                           sort_keys=True)

    findings = [c for c in first if c["track"] == "findings"]
    from_r1 = sum(1 for c in findings
                  if c["judgement_A"]["label"] == "confirmed")
    assert 0 < from_r1 < len(findings), (
        f"judgement_A came from the same reviewer in {from_r1}/"
        f"{len(findings)} cases; the position leaks identity")


def test_a_track_a_judgement_cannot_answer_a_track_b_case():
    """R3 must not be able to file an answer in the wrong contract: a Track B
    case has no `label`, and accepting one would put an adjudication verdict
    on a unit where no claim was ever made."""
    one = _returned("R1", outcome="issues_found")
    two = _returned("R2", outcome="no_issue_observed")
    packet = r3_packet(import_result(one, _bundle("R1")),
                       import_result(two, _bundle("R2")), _bundles(), salt=SALT)
    blind = next(i for i, c in enumerate(packet) if c["track"] == "blind")

    swapped = _r3_decide(packet)
    swapped[blind]["final"] = {"label": "confirmed", "level": "error",
                               "gate": "block",
                               "actionability": "actionable",
                               "evidence_sufficiency": "sufficient",
                               "reason": "wrong contract"}
    with pytest.raises(ReviewError):
        import_r3(swapped, packet)


def test_the_r3_screen_reaches_nothing_either():
    html = render_r3_ui()
    for banned in ("<script src", "<link href", "fetch(", "XMLHttpRequest",
                   "WebSocket", "sendBeacon", "http://", "https://"):
        assert banned not in html, banned


# ---- bounded reads, atomic writes, confined paths --------------------------------------------

def test_a_file_over_the_cap_is_refused_without_being_parsed(tmp_path):
    big = tmp_path / "huge.json"
    big.write_bytes(b'{"pad":"' + b"x" * (RESULT_MAX_BYTES + 64) + b'"}')
    with pytest.raises(ReviewError, match="larger than"):
        read_json(big)


def test_a_file_exactly_at_the_cap_is_read(tmp_path):
    exact = tmp_path / "exact.json"
    body = b'{"pad":"' + b"x" * 40 + b'"}'
    exact.write_bytes(body)
    assert read_json(exact, cap=len(body))["pad"] == "x" * 40
    with pytest.raises(ReviewError, match="larger than"):
        read_json(exact, cap=len(body) - 1)


def test_unreadable_json_is_refused_as_such(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReviewError, match="not readable JSON"):
        read_json(bad)


def test_a_failed_write_leaves_the_previous_file_intact(tmp_path, monkeypatch):
    target = tmp_path / ".quality-local" / "out.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"kept": true}', encoding="utf-8")

    real_replace = Path.replace

    def boom(self, other):
        if self.name.endswith(".tmp"):
            raise OSError("disk full")
        return real_replace(self, other)

    monkeypatch.setattr(Path, "replace", boom)
    with pytest.raises(OSError):
        write_atomic(target, '{"kept": false}')
    assert json.loads(target.read_text(encoding="utf-8")) == {"kept": True}
    assert not list(tmp_path.glob("*.tmp")), "no temporary file is left behind"


def test_writing_outside_quality_local_is_refused(tmp_path):
    with pytest.raises(ReviewError, match="not under .quality-local"):
        handoff_dir(tmp_path / "somewhere", "R1")


# ---- the handoff is separate per reviewer -----------------------------------------------------

def _write_packets(tmp_path) -> Path:
    packets = tmp_path / "packets"
    packets.mkdir()
    for reviewer in REVIEWERS:
        p = _packets(reviewer)
        for track in ("findings", "blind"):
            (packets / f"packet_{track}_{reviewer}.json").write_text(
                json.dumps({"units": p[track]}), encoding="utf-8")
    return packets


def test_each_reviewer_gets_a_directory_holding_only_their_own_material(
        tmp_path):
    """Independence has to survive the delivery. One folder holding both
    bundles hands each reviewer the other's packet order, and once a result
    lands beside it, the other's answers."""
    root = tmp_path / ".quality-local" / "rc"
    write_bundles(root, _write_packets(tmp_path))

    for reviewer, other in (("R1", "R2"), ("R2", "R1")):
        here = sorted(p.name for p in handoff_dir(root, reviewer).iterdir())
        assert here == [f"bundle_{reviewer}.json", f"review_{reviewer}.html"]
        assert not any(other in name for name in here)


def test_the_whole_workflow_runs_from_the_command_line(tmp_path, capsys):
    root = tmp_path / ".quality-local" / "rc"
    packets = _write_packets(tmp_path)
    assert main(["--root", str(root), "bundle", "--packets",
                 str(packets)]) == 0
    built = json.loads(capsys.readouterr().out)
    assert built["bundles"]["R1"]["units"] == 7

    for reviewer, label in (("R1", "confirmed"), ("R2", "false_positive")):
        path = tmp_path / f"result_{reviewer}.json"
        path.write_text(json.dumps(_returned(reviewer, label=label)),
                        encoding="utf-8")
        assert main(["--root", str(root), "import", "--reviewer", reviewer,
                     "--result", str(path)]) == 0
        assert json.loads(capsys.readouterr().out)["state"] == "accepted"

    assert main(["--root", str(root), "agreement"]) == 0
    scored = json.loads(capsys.readouterr().out)
    assert set(scored["tracks"]) == {"findings", "blind"}
    assert (root / "agreement.json").exists()

    assert main(["--root", str(root), "r3-build"]) == 0
    cases = json.loads(capsys.readouterr().out)["cases"]
    assert cases > 0
    packet = json.loads((handoff_dir(root, "R3") / "r3_packet.json")
                        .read_text(encoding="utf-8"))
    decided = tmp_path / "r3.json"
    decided.write_text(json.dumps(_r3_decide(packet)), encoding="utf-8")
    assert main(["--root", str(root), "r3-import", "--result",
                 str(decided)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["state"] == "accepted" and out["cases_resolved"] == cases


def test_the_cli_refuses_a_root_outside_quality_local(tmp_path, capsys):
    assert main(["--root", str(tmp_path / "elsewhere"), "bundle",
                 "--packets", str(_write_packets(tmp_path))]) == 2
    assert "not under .quality-local" in capsys.readouterr().err


def test_importing_before_bundling_is_refused(tmp_path, capsys):
    root = tmp_path / ".quality-local" / "rc"
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_returned("R1")), encoding="utf-8")
    assert main(["--root", str(root), "import", "--reviewer", "R1",
                 "--result", str(path)]) == 2
    assert "no bundle yet" in capsys.readouterr().err


# ---- the guards must see EVERY node, not most of them --------------------------------------

@pytest.mark.parametrize("planted, where", [
    ({"files": ["E:/synthetic/workspace/x"]}, "a string inside a list"),
    ({"E:/synthetic/workspace/x": "value"}, "a string used as a key"),
    ({"a": {"b": [{"c": ["/home/someone/f"]}]}}, "a string nested deeper"),
    ({"a": [[".quality-local/real-corpus"]]}, "a string in a nested list"),
])
def test_the_path_guard_sees_strings_wherever_they_sit(planted, where):
    """REGRESSION. `_walk` yielded only dict VALUES, so a path sitting in a
    list, or used as a key, walked straight through both privacy guards."""
    assert public_output_problem(json.dumps(planted)) is not None, where

    b = _bundle("R1")
    b["tracks"]["blind"]["entries"][0]["code_unit"]["extra"] = planted
    assert bundle_problem(b) == "carries a local path", where


def test_the_forbidden_key_check_still_only_fires_on_keys():
    """The other half: widening the walk must not make it refuse a bundle for
    a snippet that merely CONTAINS a forbidden word."""
    b = _bundle("R1")
    b["tracks"]["blind"]["entries"][0]["code_unit"]["code"] = (
        'notes = ["verdict", "overlap", "repo_id"]  # words, not keys\n')
    assert bundle_problem(b) is None


# ---- R3's judgement goes through the SAME door -----------------------------------------------

def test_r3_final_with_an_extra_key_is_refused():
    """`project_root` and `repo_id` are refused inside a bundle. They were
    accepted inside `final`, and stored verbatim as ground truth."""
    packet = _r3_packet_pair()
    smuggled = _r3_decide(packet)
    findings = next(i for i, c in enumerate(smuggled)
                    if c["track"] == "findings")
    smuggled[findings]["final"]["project_root"] = "E:/synthetic/workspace"
    with pytest.raises(ReviewError, match="final has unexpected keys"):
        import_r3(smuggled, packet)


def test_r3_final_prose_is_bounded_and_control_characters_are_refused():
    packet = _r3_packet_pair()
    for value, why in ((("x" * (RESULT_MAX_BYTES // 100)), "longer than"),
                       ("a reason with a \x00 in it", "control character")):
        over = _r3_decide(packet)
        findings = next(i for i, c in enumerate(over)
                        if c["track"] == "findings")
        over[findings]["final"]["reason"] = value
        with pytest.raises(ReviewError, match=why):
            import_r3(over, packet)


def _blind_case(packet: list) -> int:
    return next(i for i, c in enumerate(packet) if c["track"] == "blind")


def _blind_packet() -> list:
    """A packet with at least one Track B disagreement to arbitrate."""
    one = _returned("R1", outcome="issues_found")
    two = _returned("R2", outcome="no_issue_observed")
    return r3_packet(import_result(one, _bundle("R1")),
                     import_result(two, _bundle("R2")), _bundles(), salt=SALT)


@pytest.mark.parametrize("field, value, why", [
    ("rule_id", "N999-NEVER-SHOWN", "not in applicable_rules"),
    ("line", 9000, "outside the unit shown"),
    ("span", "not-a-span", "is not start-end"),
    ("span", "1-9000", "outside the unit shown"),
])
def test_r3_track_b_issues_are_bounded_like_a_reviewers(field, value, why):
    """THE DEFECT: `import_r3` reached `validate_blind_labels` and stopped.
    Every per-issue bound R1 and R2 must satisfy — the rule must be one this
    unit offered, the line must be inside it, the span must parse and fit —
    was skipped for the one judgement that becomes ground truth."""
    packet = _blind_packet()
    hostile = _r3_decide(packet)
    n = _blind_case(hostile)
    hostile[n]["final"]["issues"][0][field] = value
    with pytest.raises(ReviewError, match=why):
        import_r3(hostile, packet)


def test_r3_track_b_prose_and_issue_count_are_bounded():
    packet = _blind_packet()
    n = _blind_case(packet)

    long_one = _r3_decide(packet)
    long_one[n]["final"]["issues"][0]["evidence"] = "e" * 50_000
    with pytest.raises(ReviewError, match="longer than"):
        import_r3(long_one, packet)

    many = _r3_decide(packet)
    one = many[n]["final"]["issues"][0]
    many[n]["final"]["issues"] = [dict(one) for _ in range(50)]
    with pytest.raises(ReviewError, match="more than"):
        import_r3(many, packet)

    smuggled = _r3_decide(packet)
    smuggled[n]["final"]["issues"][0]["smuggled"] = "anything"
    with pytest.raises(ReviewError, match="unexpected keys"):
        import_r3(smuggled, packet)


def test_a_faithful_track_b_arbitration_with_issues_is_accepted():
    """The bounds must not make a real arbitration impossible: R3 has to be
    able to say `issues_found` and name the issue."""
    packet = _blind_packet()
    out = import_r3(_r3_decide(packet), packet)
    assert out["state"] == "accepted"
    n = _blind_case(packet)
    stored = out["resolved"][packet[n]["sample_id"]]["final"]
    assert stored["outcome"] == "issues_found" and len(stored["issues"]) == 1


def test_an_undecided_case_is_an_empty_object_and_nothing_else():
    """`final: []`, `final: 0` and `final: ""` all read as decided to a human
    and as undecided to a `if not final` test."""
    packet = _r3_packet_pair()
    for value in ([], 0, "", None):
        sneaky = _r3_decide(packet)
        sneaky[0]["final"] = value
        with pytest.raises(ReviewError):
            import_r3(sneaky, packet)


# ---- A/B anonymity depends on a secret, not on a constant in this file ------------------------

def test_the_ab_order_changes_with_the_salt():
    """THE DEFECT: the salt was a fixed string in this repository, so anyone
    holding the packet could replay `random.Random(<that string>)` and recover
    which judgement was whose. Determinism is only anonymity when the seed is
    not published."""
    a = import_result(_returned("R1", label="confirmed"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive"), _bundle("R2"))
    one = r3_packet(a, b, _bundles(), salt=SALT)
    two = r3_packet(a, b, _bundles(), salt="a-completely-different-salt-xyz")
    assert [c["judgement_A"] for c in one] != [c["judgement_A"] for c in two]


def test_r3_refuses_to_build_without_a_real_salt():
    a = import_result(_returned("R1", label="confirmed"), _bundle("R1"))
    b = import_result(_returned("R2", label="false_positive"), _bundle("R2"))
    for weak in ("", "short"):
        with pytest.raises(ReviewError, match="run salt"):
            r3_packet(a, b, _bundles(), salt=weak)


def test_the_run_salt_is_generated_locally_and_never_handed_to_r3(tmp_path):
    root = tmp_path / ".quality-local" / "rc"
    first = run_salt(root)
    assert len(first) >= 32
    assert run_salt(root) == first, "a rebuild reproduces the same packet"
    assert (root / "r3_run_salt.json").exists()
    assert first not in json.dumps(list(
        p.name for p in (root / "handoff").rglob("*"))) if (
        root / "handoff").exists() else True


# ---- agreement is between TWO people, about the SAME material ----------------------------------

def test_one_reviewers_answers_are_not_scored_against_themselves():
    """THE DEFECT: nothing checked the two results came from two people. The
    same file imported twice scores raw agreement 1.0 and clears every
    structural check — and one person agreeing with themselves is not
    inter-rater agreement."""
    same = import_result(_returned("R1"), _bundle("R1"))
    with pytest.raises(ReviewError, match="one accepted result from each"):
        agreement(same, same)


def test_two_results_claiming_one_bundle_are_refused():
    one = import_result(_returned("R1"), _bundle("R1"))
    two = import_result(_returned("R2"), _bundle("R2"))
    two["reviewer"] = "R2"
    two["bundle_id"] = one["bundle_id"]
    with pytest.raises(ReviewError, match="same bundle_id"):
        agreement(one, two)


def test_two_bundles_built_from_different_material_are_not_compared(tmp_path):
    """Same sample_ids, different claims behind them. Ids survive a rebuild;
    the material does not."""
    r1 = _bundle("R1")
    changed = _packets("R2")
    changed["findings"][0]["claim"]["detail"] = "a different claim entirely"
    r2 = build_bundle(changed, "R2")
    with pytest.raises(ReviewError, match="different material"):
        _same_material({"R1": r1, "R2": r2})
    # the honest pair passes
    _same_material({"R1": r1, "R2": _bundle("R2")})


# ---- reads are bounded in a way a test can SEE ------------------------------------------------

def test_read_json_asks_for_exactly_cap_plus_one_byte(tmp_path, monkeypatch):
    """VACUOUS BEFORE: both cap tests passed unchanged against a fully
    unbounded read, because they only observed the outcome. The contract is
    about the READ — one byte past the limit, never the whole file."""
    path = tmp_path / "r.json"
    path.write_text('{"a": 1}', encoding="utf-8")

    asked: list[int | None] = []
    real_open = Path.open

    class Watched:
        def __init__(self, fh):
            self._fh = fh

        def read(self, size=-1):
            asked.append(size)
            return self._fh.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()
            return False

    monkeypatch.setattr(Path, "open",
                        lambda self, *a, **k: Watched(real_open(self, *a, **k)))
    assert read_json(path, cap=1024) == {"a": 1}
    assert asked == [1025], asked


def test_an_oversized_file_is_refused_by_SIZE_even_when_unparseable(tmp_path):
    """An implementation that parses first cannot produce this message."""
    path = tmp_path / "big.json"
    path.write_bytes(b"[" * (RESULT_MAX_BYTES + 64))
    with pytest.raises(ReviewError, match="larger than"):
        read_json(path)


def test_deeply_nested_json_is_refused_rather_than_crashing(tmp_path):
    """A byte cap is not a bound. 400 KB of `[` is a twentieth of the cap and
    still exhausts the interpreter's stack — which reached the terminal as a
    RecursionError traceback and exit 1 instead of a refusal."""
    path = tmp_path / "deep.json"
    path.write_bytes(b"[" * 200_000 + b"]" * 200_000)
    with pytest.raises(ReviewError, match="nested"):
        read_json(path)


def test_the_cli_refuses_malformed_input_and_never_shows_a_traceback(
        tmp_path, capsys):
    root = tmp_path / ".quality-local" / "rc"
    packets = _write_packets(tmp_path)
    assert main(["--root", str(root), "bundle", "--packets",
                 str(packets)]) == 0
    capsys.readouterr()

    for content in ('{"a": 1}', "[" * 200_000, "not json at all",
                    '{"corpus": null}'):
        path = tmp_path / "junk.json"
        path.write_text(content, encoding="utf-8")
        code = main(["--root", str(root), "import", "--reviewer", "R1",
                     "--result", str(path)])
        err = capsys.readouterr().err
        assert code == 2, content[:20]
        assert err.startswith("refused:"), err
        assert "Traceback" not in err


# ---- writes stay inside .quality-local even when a link says otherwise -------------------------

def test_a_link_on_the_write_path_is_refused(tmp_path):
    """`confined_root` checked the root and nothing else, so a junction at
    `<root>/handoff` sent every bundle and every reviewer screen outside the
    local workspace while `--root` still looked obedient."""
    root = tmp_path / ".quality-local" / "rc"
    root.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    link = root / "handoff"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        # Windows refuses an unprivileged symlink but allows a junction, and
        # a junction is what an operator would plausibly end up with. Falling
        # back keeps this running on the platform the tool is used on.
        import subprocess
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link),
                               str(outside)], capture_output=True)
        if made.returncode != 0 or not link.exists():
            pytest.skip("this platform cannot create a directory link")
    with pytest.raises(ReviewError, match="resolves outside"):
        handoff_dir(root, "R1")


def test_write_atomic_refuses_a_destination_outside_the_local_workspace(
        tmp_path):
    with pytest.raises(ReviewError, match="resolves outside"):
        write_atomic(tmp_path / "escaped.json", "{}")


# ---- the reviewer screen and the importer must agree about "complete" --------------------------

def test_the_ui_and_the_importer_parse_a_line_and_a_span_the_same_way():
    """THE DEFECT, in the source: the browser trimmed a span and accepted any
    `Number.isInteger(Number(x))` line; the importer used an anchored regex
    with no trim and `int()`. One stray space reached a green "complete", a
    file not named _DRAFT, and a whole-result refusal."""
    html = render_ui("R1")
    js = html.split("function issueProblem")[1].split("function complete")[0]
    assert "/^\\d+$/.test(String(it.line))" in js, \
        "the browser must reject 110.0, 1.1e2, 0x6e and ' 110' as the " \
        "importer does"
    assert "String(it.span))" in js and "String(it.span).trim()" not in js, \
        "the browser must not trim a span the importer will not trim"


def test_the_ui_carries_the_importers_own_bounds():
    html = render_ui("R1")
    for name, value in (("REASON_MAX", REASON_MAX_CHARS),
                        ("STATEMENT_MAX", STATEMENT_MAX_CHARS),
                        ("EVIDENCE_MAX", EVIDENCE_MAX_CHARS),
                        ("MAX_ISSUES", MAX_ISSUES_PER_UNIT)):
        assert f"{name} = {value}" in html, name


def test_an_empty_bundle_cannot_export_as_complete():
    """`[].every(...)` is true, so an empty unit list exported with
    `complete: true` and no _DRAFT in the name."""
    html = render_ui("R1")
    assert "FLAT.length > 0 && FLAT.every(complete)" in html


# ---- the R3 screen can actually arbitrate ------------------------------------------------------

def test_the_r3_screen_offers_an_issue_editor_for_track_b():
    """THE DEFECT: the blind form was one `outcome` dropdown and a hard-coded
    `issues: []`. Since `issues_found` with an empty list is refused, the only
    blind judgement R3 could produce that survived import was one denying
    every issue both reviewers had found."""
    html = render_r3_ui()
    assert "function renderIssues" in html
    assert 'id="addissue"' in html
    assert "function issueProblem" in html
    assert "issues:(a.issues||[])" in html, \
        "the export must carry what R3 entered, not a fixed empty list"


def test_the_r3_screen_keys_progress_by_the_packet_itself():
    """A rebuilt packet has the same length and the same first sample_id, so
    keying by those two collides and shows R3 their earlier answers."""
    html = render_r3_ui()
    assert "function packetKey" in html
    assert "c.disputed_fields, c.material" in html


def test_the_r3_screen_refuses_an_unreadable_packet_out_loud():
    html = render_r3_ui()
    load = html.split('addEventListener("change"')[1].split("readAsText")[0]
    assert "not readable JSON" in load
    assert "not an R3 packet" in load
    assert load.count("alert(") >= 3

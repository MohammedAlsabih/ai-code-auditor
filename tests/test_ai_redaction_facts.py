"""W3-E4C1: structured redaction facts — positional, server-derived,
value-free proof that a REAL literal was masked on a sent line. A ***
already present in the source never creates one; dropped pieces drop their
facts; the facts ride in the canonical bytes (digest + consent +
PrivacyManifest); order is deterministic and the shape is a strict
allowlist. No network."""
from __future__ import annotations

import json

import pytest

import auditor.ai.audit as audit_mod
from auditor.ai.audit import (
    REDACTION_FACT_KEYS, REDACTION_FACT_TEXT, AuditContextError,
    build_audit_pack, redaction_facts)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.review import REDACTION_CATEGORIES


def _pack(tmp_path, files: dict[str, str], qid="AI003", project="api"):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    idx = RepositoryAuditIndex(tmp_path, [(project, "csharp")])
    return build_audit_pack(idx, project, query_by_id(qid))


def _facts(pack):
    piece = next((p for p in pack["pieces"]
                  if p.get("context_id") == "redaction_facts"), None)
    return piece["facts"] if piece else []


REAL = ('class Factory {\n'
        '  Db Create() {\n'
        '    return Open("Host=db;Password=hunter2realvalue");\n'
        '  }\n}\n')
PREMASKED = ('class Factory {\n'
             '  Db Create() {\n'
             '    return Open("Host=db;Password=***");\n'
             '  }\n}\n')


def test_real_masked_literal_creates_a_positional_fact(tmp_path):
    pack = _pack(tmp_path, {"api/Factory.cs": REAL})
    facts = _facts(pack)
    assert len(facts) == 1
    f = facts[0]
    assert set(f) == set(REDACTION_FACT_KEYS)          # strict allowlist
    assert f["file"] == "api/Factory.cs"               # server-derived
    assert f["line_start"] == f["line_end"] == 3       # the exact line
    assert f["redaction_class"] in REDACTION_CATEGORIES
    assert f["fact"] == REDACTION_FACT_TEXT
    # the fact is in the canonical bytes => digest + consent cover it
    assert "redaction_facts" in pack["canonical"]
    assert pack["privacy_manifest"]["redaction_facts"] == 1
    # and the ORIGINAL value appears nowhere in anything outgoing
    blob = json.dumps(pack["pieces"]) + pack["canonical"]
    assert "hunter2realvalue" not in blob


def test_premasked_source_creates_no_fact(tmp_path):
    pack = _pack(tmp_path, {"api/Factory.cs": PREMASKED})
    assert _facts(pack) == []
    assert pack["privacy_manifest"]["redaction_facts"] == 0
    # the sent text still shows *** — but with NO covering fact
    assert "Password=***" in pack["canonical"]


def test_real_vs_premasked_are_now_distinguishable(tmp_path):
    a = _pack(tmp_path / "a", {"api/Factory.cs": REAL})
    b = _pack(tmp_path / "b", {"api/Factory.cs": PREMASKED})
    # W3-E4C defect 3 closed: identical post-redaction source text, but the
    # digests differ because only the REAL literal produced a fact
    assert len(_facts(a)) == 1 and _facts(b) == []
    assert a["digest"] != b["digest"]


def test_dropped_piece_drops_its_facts(tmp_path, monkeypatch):
    # two credential-bearing files; shrink the pack cap so the reduction
    # must drop the lowest-ranked source piece — its facts must vanish
    files = {
        "api/ConnFactory.cs":
            'class ConnFactory {\n'
            '  Db Create() => Open("Host=a;Password=first0realvalue");\n'
            '}\n',
        "api/SettingsDb.cs":
            'class SettingsDb {\n'
            '  Db Create() => Open("Host=b;Password=second0realvalue");\n'
            '}\n',
    }
    full = _pack(tmp_path / "full", files)
    assert len(_facts(full)) == 2
    # a single-file pack tells us the size one source piece (+ its facts +
    # notice) needs; set the cap there so the two-file pack MUST drop one
    one = _pack(tmp_path / "one", {"api/ConnFactory.cs": files["api/ConnFactory.cs"]})
    cap = len(one["canonical"].encode("utf-8")) + 50
    monkeypatch.setattr(audit_mod, "PACK_MAX_BYTES", cap)
    reduced = _pack(tmp_path / "small", files)
    kept_cids = set(reduced["piece_map"])
    assert len(reduced["piece_map"]) == 1              # one source piece kept
    for f in _facts(reduced):
        assert f["context_id"] in kept_cids            # no orphan facts
    assert len(_facts(reduced)) == 1                   # only the kept piece's
    assert reduced["privacy_manifest"]["redaction_facts"] == len(
        _facts(reduced))


def test_fact_order_is_deterministic_and_ranges_merge():
    meta = {
        "src:2": {"file": "b.cs",
                  "line_facts": [(7, "token_kv"), (5, "token_kv"),
                                 (6, "token_kv")]},
        "src:1": {"file": "a.cs", "line_facts": [(9, "quoted_kv")]},
    }
    facts = redaction_facts(meta)
    assert [(f["context_id"], f["line_start"], f["line_end"])
            for f in facts] == [("src:1", 9, 9), ("src:2", 5, 7)]
    assert facts == redaction_facts(dict(reversed(list(meta.items()))))


def test_unknown_redaction_class_is_refused_closed():
    with pytest.raises(AuditContextError):
        redaction_facts({"src:1": {"file": "a.cs",
                                   "line_facts": [(1, "made_up_class")]}})


def test_facts_only_for_lines_actually_sent(tmp_path):
    # the credential line sits FAR from any retrieval match, outside every
    # sent window — no fact may leak information about unsent lines
    filler = "".join(f"// filler line {i}\n" for i in range(40))
    text = ('class DbFactory {\n'
            '  void Configure() { UseNpgsql(_cs); }\n'
            '}\n' + filler +
            'class Hidden { string s = "Password=far0awayvalue"; }\n')
    pack = _pack(tmp_path, {"api/DbFactory.cs": text})
    if pack is None:
        return
    spans = {m["file"]: m["spans"] for m in pack["piece_map"].values()}
    for f in _facts(pack):
        s = spans[f["file"]]
        assert any(a <= f["line_start"] and f["line_end"] <= b
                   for a, b in s), "fact outside the sent spans"


def test_prompt_and_ai003_contract_explain_the_facts():
    from auditor.ai.audit import AUDIT_PROMPT_VERSION, AUDIT_SYSTEM_INSTRUCTIONS
    assert "redaction_facts" in AUDIT_SYSTEM_INSTRUCTIONS
    assert "proves nothing" in AUDIT_SYSTEM_INSTRUCTIONS
    assert AUDIT_PROMPT_VERSION == "w3e-v4"
    q = query_by_id("AI003")
    assert q.query_version == 4
    assert "redaction_facts" in q.decision_contract
    assert "NO covering" in q.decision_contract

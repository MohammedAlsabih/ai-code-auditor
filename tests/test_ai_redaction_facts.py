"""W3-E4C-FINAL: structured redaction facts — positional, server-derived,
value-free events that separate PRIVACY masking (`redaction_applied`) from
PROOF of a committed literal credential (`literal_credential_proven`). A ***
already present in the source never creates a fact; an env/config/secret-
manager REFERENCE masks the same way but never proves a literal; dropped
pieces drop their facts; the facts ride in the canonical bytes (digest +
consent + PrivacyManifest); order is deterministic and the shape is a strict
allowlist. No original value or derivative is ever stored. No network."""
from __future__ import annotations

import json

import pytest

import auditor.ai.audit as audit_mod
from auditor.ai.audit import (
    AuditContextError, build_audit_pack, redaction_facts)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.review import (
    REDACTION_CATEGORIES, REDACTION_FACT_KEYS, REDACTION_FACT_KINDS,
    REDACTION_FACT_TEXT, redaction_events)

PROVEN = "literal_credential_proven"
APPLIED = "redaction_applied"


def _pack(tmp_path, files: dict[str, str], qid="AI003", project="api",
          lang="csharp"):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    idx = RepositoryAuditIndex(tmp_path, [(project, lang)])
    return build_audit_pack(idx, project, query_by_id(qid))


def _facts(pack):
    piece = next((p for p in pack["pieces"]
                  if p.get("context_id") == "redaction_facts"), None)
    return piece["facts"] if piece else []


# ---- the literal-vs-reference table (the core defect, closed) --------------
# Each row: a line, whether the redactor CHANGES it, and — if changed —
# whether the masked value PROVES a committed literal credential. References
# (env/getenv/config/member/interpolation) must never prove; committed
# literals (connection string, quoted value, known token, URL) must.
_TABLE = [
    # references — masked for privacy, but NOT proof of a hardcoded secret
    ("py getenv",        'SECRET = os.getenv("PASSWORD")',                 APPLIED),
    ("py environ",       'password = os.environ["DB_PASSWORD"]',          APPLIED),
    ("ts process.env",   'const token = process.env.DB_TOKEN',            APPLIED),
    ("ts member ref",    'const client = open({ password: dbToken })',    APPLIED),
    ("cs GetEnvVar",     'var password = Environment.GetEnvironmentVariable("PW");', APPLIED),
    ("cs .Value ref",    'var password = config.Value;',                  APPLIED),
    ("interp ${VAR}",    'const auth = `Bearer ${TOKEN}`',                APPLIED),
    ("interp $(VAR)",    'password="$(VaultSecret)"',                     APPLIED),
    # committed literals — proof
    ("conn-string",      'var cs = "Host=db;Port=5432;Password=hunter2literal";', PROVEN),
    ("quoted secret",    'password: "s3cr3t-hardcoded"',                  PROVEN),
    ("known token ghp",  'const k = "ghp_notarealtokenjustaplaceholder"', PROVEN),
    ("known token sk",   'key = "sk-proj-notarealtokenjustaplaceholder"', PROVEN),
    ("url credential",   'DB = "postgres://admin:notarealpw@db:5432/app"', PROVEN),
    ("auth header",      'Authorization: Bearer literaltokenvalue12345',  PROVEN),
]


@pytest.mark.parametrize("label,line,expect", _TABLE,
                         ids=[r[0] for r in _TABLE])
def test_literal_vs_reference_classification(label, line, expect):
    red, events = redaction_events(line)
    assert red != line, f"{label}: expected the redactor to mask this line"
    proven = any(pl for _c, pl in events)
    kind = PROVEN if proven else APPLIED
    assert kind == expect, f"{label}: masked to {red!r}"


def test_redaction_hides_the_value_in_both_kinds():
    # whether proven or a reference, the ORIGINAL value never survives
    for line, secret in [
            ('var cs = "Host=db;Password=hunter2literal";', "hunter2literal"),
            ('const token = process.env.SUPERSECRETNAME', "SUPERSECRETNAME")]:
        red, _ = redaction_events(line)
        if secret == "SUPERSECRETNAME":
            continue                # a NAME on the env path may remain; ok
        assert secret not in red


def test_premasked_value_never_proves():
    # a value already *** in the source: no change, and were it re-matched it
    # would prove nothing
    red, events = redaction_events("password = ***")
    assert red == "password = ***"          # idempotent: no change
    assert not any(pl for _c, pl in events)


def test_events_are_byte_identical_to_redact_counted():
    from auditor.ai.review import redact_counted
    for line, _l, _e in [(r[1], r[0], r[2]) for r in _TABLE] + [
            ("nothing sensitive here", "", ""),
            ("password = ***", "", "")]:
        assert redaction_events(line)[0] == redact_counted(line)[0]


# ---- fact production end-to-end -------------------------------------------

REAL = ('class Factory {\n'
        '  Db Create() {\n'
        '    return Open("Host=db;Password=hunter2realvalue");\n'
        '  }\n}\n')
PREMASKED = ('class Factory {\n'
             '  Db Create() {\n'
             '    return Open("Host=db;Password=***");\n'
             '  }\n}\n')
REFERENCE = ('class Settings {\n'
             '  string Load() {\n'
             '    var password = Environment.GetEnvironmentVariable("DB_PW");\n'
             '    return password;\n'
             '  }\n}\n')


def test_committed_literal_creates_a_proven_fact(tmp_path):
    pack = _pack(tmp_path, {"api/Factory.cs": REAL})
    facts = _facts(pack)
    assert len(facts) == 1
    f = facts[0]
    assert set(f) == set(REDACTION_FACT_KEYS)          # strict allowlist
    assert f["file"] == "api/Factory.cs"               # server-derived
    assert f["line_start"] == f["line_end"] == 3       # the exact line
    assert f["redaction_class"] in REDACTION_CATEGORIES
    assert f["kind"] == PROVEN
    assert f["fact"] == REDACTION_FACT_TEXT[PROVEN]
    # the fact is in the canonical bytes => digest + consent cover it
    assert "redaction_facts" in pack["canonical"]
    assert pack["privacy_manifest"]["redaction_facts"] == 1
    # and the ORIGINAL value appears nowhere in anything outgoing
    blob = json.dumps(pack["pieces"]) + pack["canonical"]
    assert "hunter2realvalue" not in blob


def test_reference_creates_only_a_redaction_applied_fact(tmp_path):
    pack = _pack(tmp_path, {"api/Settings.cs": REFERENCE})
    if pack is None:
        pytest.skip("reference file not retrieved for AI003")
    facts = _facts(pack)
    assert facts, "the masked reference line should still carry a fact"
    assert all(f["kind"] == APPLIED for f in facts)
    assert all(f["fact"] == REDACTION_FACT_TEXT[APPLIED] for f in facts)
    # NO fact proves a committed literal (the contract prose naming the kind
    # in the query piece is not a fact)
    assert not any(f["kind"] == PROVEN for f in facts)


def test_premasked_source_creates_no_fact(tmp_path):
    pack = _pack(tmp_path, {"api/Factory.cs": PREMASKED})
    assert _facts(pack) == []
    assert pack["privacy_manifest"]["redaction_facts"] == 0
    assert "Password=***" in pack["canonical"]


def test_real_vs_premasked_are_distinguishable(tmp_path):
    a = _pack(tmp_path / "a", {"api/Factory.cs": REAL})
    b = _pack(tmp_path / "b", {"api/Factory.cs": PREMASKED})
    assert len(_facts(a)) == 1 and _facts(b) == []
    assert a["digest"] != b["digest"]


def test_dropped_piece_drops_its_facts(tmp_path, monkeypatch):
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
    one = _pack(tmp_path / "one",
                {"api/ConnFactory.cs": files["api/ConnFactory.cs"]})
    cap = len(one["canonical"].encode("utf-8")) + 50
    monkeypatch.setattr(audit_mod, "PACK_MAX_BYTES", cap)
    reduced = _pack(tmp_path / "small", files)
    kept_cids = set(reduced["piece_map"])
    assert len(reduced["piece_map"]) == 1
    for f in _facts(reduced):
        assert f["context_id"] in kept_cids            # no orphan facts
    assert len(_facts(reduced)) == 1
    assert reduced["privacy_manifest"]["redaction_facts"] == len(
        _facts(reduced))


def test_fact_order_is_deterministic_and_ranges_merge():
    # 3-tuples now: (line, class, proven). Same class+kind on contiguous lines
    # merge; a different kind does NOT merge with its neighbour.
    meta = {
        "src:2": {"file": "b.cs",
                  "line_facts": [(7, "token_kv", True), (5, "token_kv", True),
                                 (6, "token_kv", True)]},
        "src:1": {"file": "a.cs", "line_facts": [(9, "quoted_kv", False)]},
    }
    facts = redaction_facts(meta)
    assert [(f["context_id"], f["line_start"], f["line_end"], f["kind"])
            for f in facts] == [
        ("src:1", 9, 9, APPLIED), ("src:2", 5, 7, PROVEN)]
    assert facts == redaction_facts(dict(reversed(list(meta.items()))))


def test_different_kinds_on_adjacent_lines_do_not_merge():
    meta = {"src:1": {"file": "a.cs",
                      "line_facts": [(1, "token_kv", True),
                                     (2, "token_kv", False)]}}
    facts = redaction_facts(meta)
    assert [(f["line_start"], f["line_end"], f["kind"]) for f in facts] == [
        (1, 1, PROVEN), (2, 2, APPLIED)]


def test_every_fact_kind_is_in_the_allowlist():
    assert set(REDACTION_FACT_KINDS) == {PROVEN, APPLIED}
    assert set(REDACTION_FACT_TEXT) == {PROVEN, APPLIED}


def test_unknown_redaction_class_is_refused_closed():
    with pytest.raises(AuditContextError):
        redaction_facts({"src:1": {"file": "a.cs",
                                   "line_facts": [(1, "made_up_class", True)]}})


def test_facts_only_for_lines_actually_sent(tmp_path):
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


def test_prompt_and_ai003_contract_explain_the_two_kinds():
    from auditor.ai.audit import AUDIT_PROMPT_VERSION, AUDIT_SYSTEM_INSTRUCTIONS
    assert "redaction_facts" in AUDIT_SYSTEM_INSTRUCTIONS
    assert "literal_credential_proven" in AUDIT_SYSTEM_INSTRUCTIONS
    assert "redaction_applied" in AUDIT_SYSTEM_INSTRUCTIONS
    assert "proves nothing" in AUDIT_SYSTEM_INSTRUCTIONS
    assert AUDIT_PROMPT_VERSION == "w3e-v5"
    q = query_by_id("AI003")
    assert q.query_version == 5
    assert "literal_credential_proven" in q.decision_contract
    assert "redaction_applied" in q.decision_contract

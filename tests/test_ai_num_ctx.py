"""W3-E4D: AUDITOR_OLLAMA_NUM_CTX — the local Ollama context window.

Server-env ONLY (never a request/browser/prompt field). Unset => 4096; a
bounded ASCII integer is honoured; a bool/float/NaN/negative/zero/malformed/
out-of-range value is a fixed config error raised BEFORE any network I/O, with
no echo. It applies to Ollama alone (inside options.num_ctx) and never reaches
an OpenAI-compatible or remote body. A 4096 run and an 8192 run of the SAME
sent data have distinct EXECUTION identities (the sent-data digest is
unchanged) so they never dedupe or stale-collide. No network."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.ai.audit import (
    audit_execution_id, build_audit_pack, candidates_from_result,
    run_audit_unit)
from auditor.ai.audit_index import RepositoryAuditIndex
from auditor.ai.audit_queries import query_by_id
from auditor.ai.contract import Provider
from auditor.ai.review import (
    OLLAMA_NUM_CTX_DEFAULT, OLLAMA_NUM_CTX_MAX, OLLAMA_NUM_CTX_MIN,
    OllamaNumCtxError, _review_body, ollama_num_ctx)

_SCHEMA = {"type": "object"}
_OLLAMA_ENV = {"OLLAMA_HOST": "http://127.0.0.1:11434"}


# ---- env parsing: unset default, accepted, rejected ------------------------

def test_unset_defaults_to_4096():
    assert ollama_num_ctx({}) == OLLAMA_NUM_CTX_DEFAULT == 4096


@pytest.mark.parametrize("raw,expected", [
    ("4096", 4096), ("8192", 8192), (" 8192 ", 8192), ("2048", 2048),
    ("32768", 32768)])
def test_accepts_bounded_whole_numbers(raw, expected):
    assert ollama_num_ctx({"AUDITOR_OLLAMA_NUM_CTX": raw}) == expected


# the message is FIXED (independent of the offending value): asserting the
# whole string equals this constant proves the value is NEVER echoed.
_FIXED_MSG = ("AUDITOR_OLLAMA_NUM_CTX must be a whole number within the "
              f"supported range [{OLLAMA_NUM_CTX_MIN}, {OLLAMA_NUM_CTX_MAX}]")


@pytest.mark.parametrize("raw", [
    "true", "True", "False",          # bool words
    "8192.0", "4096.5", ".5",         # float
    "nan", "inf", "-inf",             # NaN/inf
    "-8192", "-1",                    # negative
    "0", "00",                        # zero
    "eight", "0x2000", "8_192", "8192 x", "1e4",   # malformed
    "1024", "1", "40000", "999999",   # out of [2048, 32768]
])
def test_rejects_unsafe_values_with_no_echo(raw):
    with pytest.raises(OllamaNumCtxError) as ei:
        ollama_num_ctx({"AUDITOR_OLLAMA_NUM_CTX": raw})
    assert str(ei.value) == _FIXED_MSG          # fixed message, no echo
    assert ei.value.code == "invalid_ollama_num_ctx"


def test_empty_string_is_the_default_not_an_error():
    assert ollama_num_ctx({"AUDITOR_OLLAMA_NUM_CTX": "   "}) == 4096


# ---- the wire: Ollama only carries options.num_ctx -------------------------

def test_only_ollama_carries_num_ctx_on_the_wire():
    for provider in Provider:
        body = _review_body(provider, "m", "sys", "usr", schema=_SCHEMA,
                            max_tokens=100, num_ctx=8192)
        blob = json.dumps(body)
        if provider is Provider.OLLAMA:
            assert body["options"]["num_ctx"] == 8192
        else:
            assert "num_ctx" not in blob     # never reaches remote/compatible


def test_review_path_wire_is_unchanged_without_num_ctx():
    # the single-finding review shares the helper but never passes num_ctx =>
    # the Ollama body is byte-identical to before W3-E4D
    body = _review_body(Provider.OLLAMA, "m", "sys", "usr", schema=_SCHEMA,
                        max_tokens=100)
    assert body["options"] == {"temperature": 0, "num_predict": 100}


# ---- execution identity: 4096 vs 8192 are distinct, data digest is not -----

def test_execution_identity_distinguishes_num_ctx():
    unit = "u" * 64
    a = audit_execution_id(unit, "ollama", "qwen3:14b", "w3e-v5", 4096)
    b = audit_execution_id(unit, "ollama", "qwen3:14b", "w3e-v5", 8192)
    assert a != b
    # deterministic and stable for identical inputs
    assert a == audit_execution_id(unit, "ollama", "qwen3:14b", "w3e-v5", 4096)
    # None (non-Ollama) is its own identity, distinct from any int
    n = audit_execution_id(unit, "openai", "gpt", "w3e-v5", None)
    assert n not in (a, b)


# ---- run_audit_unit: no network on a bad value, record on a good one -------

class _Spy:
    def __init__(self):
        self.calls = 0

    def request(self, *a, **k):
        self.calls += 1
        raise AssertionError("network must not happen")


class _FakeOllama:
    """Returns a valid empty-issues audit reply in the Ollama chat envelope."""

    def __init__(self):
        self.bodies = []

    def request(self, method, url, headers, json_body, timeout):
        from auditor.ai.contract import HttpResponse
        self.bodies.append(json_body)
        reply = {"outcome": "no_issue_observed", "issues": []}
        return HttpResponse(200, json.dumps(
            {"message": {"role": "assistant",
                         "content": json.dumps(reply)}}).encode())


def _ai003_pack(tmp: Path):
    (tmp / "api").mkdir(parents=True, exist_ok=True)
    (tmp / "api" / "Db.cs").write_text(
        'class F { void C(){ UseNpgsql("Host=h;Password=p"); } }\n',
        encoding="utf-8")
    idx = RepositoryAuditIndex(tmp, [("api", "csharp")])
    return build_audit_pack(idx, "api", query_by_id("AI003"))


def test_invalid_num_ctx_makes_zero_network():
    with tempfile.TemporaryDirectory() as t:
        pack = _ai003_pack(Path(t))
        spy = _Spy()
        with pytest.raises(OllamaNumCtxError):
            run_audit_unit(pack, Provider.OLLAMA, "m", spy,
                           env={**_OLLAMA_ENV,
                                "AUDITOR_OLLAMA_NUM_CTX": "banana"})
        assert spy.calls == 0            # the wire was never touched


def test_result_records_num_ctx_and_execution_id_for_ollama():
    with tempfile.TemporaryDirectory() as t:
        pack = _ai003_pack(Path(t))
        fake = _FakeOllama()
        res = run_audit_unit(pack, Provider.OLLAMA, "qwen3:14b", fake,
                             env={**_OLLAMA_ENV,
                                  "AUDITOR_OLLAMA_NUM_CTX": "8192"})
        assert res["num_ctx"] == 8192
        assert fake.bodies[0]["options"]["num_ctx"] == 8192      # on the wire
        assert res["execution_id"] == audit_execution_id(
            pack["unit_id"], "ollama", "qwen3:14b", res["prompt_version"], 8192)
        # the sent-DATA identity is independent of num_ctx
        assert res["context_digest"] == pack["digest"]
        assert res["audit_unit_id"] == pack["unit_id"]


def test_default_num_ctx_applies_when_unset():
    with tempfile.TemporaryDirectory() as t:
        pack = _ai003_pack(Path(t))
        fake = _FakeOllama()
        res = run_audit_unit(pack, Provider.OLLAMA, "qwen3:14b", fake,
                             env=_OLLAMA_ENV)      # no AUDITOR_OLLAMA_NUM_CTX
        assert res["num_ctx"] == 4096
        assert fake.bodies[0]["options"]["num_ctx"] == 4096


# ---- the store: 4096 and 8192 rows coexist, no dedupe/stale collision ------

def test_store_keeps_4096_and_8192_as_distinct_rows():
    import auditor.ai.audit_store as store_mod
    with tempfile.TemporaryDirectory() as t:
        pack = _ai003_pack(Path(t))
        sidecar = Path(t) / "r.ai-audit.json"
        store = store_mod.AIAuditStore(sidecar)
        r4 = run_audit_unit(pack, Provider.OLLAMA, "qwen3:14b", _FakeOllama(),
                            env={**_OLLAMA_ENV,
                                 "AUDITOR_OLLAMA_NUM_CTX": "4096"})
        r8 = run_audit_unit(pack, Provider.OLLAMA, "qwen3:14b", _FakeOllama(),
                            env={**_OLLAMA_ENV,
                                 "AUDITOR_OLLAMA_NUM_CTX": "8192"})
        store.put_result(r4, candidates_from_result(r4))
        store.put_result(r8, candidates_from_result(r8))
        # both rows survive — the 8192 run did NOT overwrite the 4096 one
        got4 = store.result_for_execution(r4["execution_id"])
        got8 = store.result_for_execution(r8["execution_id"])
        assert got4 is not None and got8 is not None
        assert got4["num_ctx"] == 4096 and got8["num_ctx"] == 8192
        assert r4["execution_id"] != r8["execution_id"]


# ---- the browser cannot override it: no request field carries num_ctx ------

def test_no_audit_request_field_can_set_num_ctx():
    from auditor.web.app import AIAuditIn, AIAuditPreviewIn
    for model in (AIAuditPreviewIn, AIAuditIn):
        assert "num_ctx" not in model.model_fields    # server-set only

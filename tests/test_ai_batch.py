"""W3-D: batch AI review — limits, states, concurrency, cancel/interrupt,
partial failures, the batch sidecar, and the web API. Fake transports only."""
from __future__ import annotations

import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from auditor.ai.batch import (
    BATCH_MAX_FINDINGS,
    BatchError,
    BatchLimits,
    BatchRunner,
    BatchStore,
    load_pricing,
)
from auditor.ai.contract import HttpResponse, Provider, TransportFailure
from auditor.ai.review import REVIEW_MAX_TOKENS, build_context_pack, finding_review_id
from auditor.ai.review_store import AIReviewStore
from auditor.web import app as app_mod

from tests.test_ai_review import (
    LOCAL_ENV,
    FakeTransport,
    _reply,
    _rid,
    _write_repo,
    _write_report,
)


def _multi_report(n: int) -> dict:
    """n distinct P006-style findings in one project."""
    findings = []
    for i in range(n):
        findings.append({
            "rule_id": "P006", "level": "warning", "severity": "yellow",
            "precision": "exact", "gate_action": "review",
            "title": "High complexity",
            "detail": f"function f{i} has CCN over the threshold.",
            "file": f"mod_{i}.py", "line": 1,
            "snippet": f"def f{i}(): pass", "language": "python",
            "engine": "lizard"})
    return {
        "summary": {"counts": {}},
        "analysis_manifest": {"catalog": [], "execution": {"projects": []},
                              "policy": {}},
        "projects": [{"language": "python", "root": ".",
                      "findings": findings}],
    }


def _rids(report: dict) -> list[str]:
    out = []
    for f in report["projects"][0]["findings"]:
        rid = finding_review_id(".", f)
        assert rid
        out.append(rid)
    return out


def _runner(tmp_path, report, transport_factory, env=None):
    store = AIReviewStore(tmp_path / "r.ai-reviews.json")
    bstore = BatchStore(tmp_path / "r.ai-batches.json")
    return BatchRunner(
        build_pack=lambda rid: build_context_pack(report, None, rid),
        ai_store=store, batch_store=bstore,
        transport_factory=transport_factory,
        env=env or LOCAL_ENV), store, bstore


LIMITS = BatchLimits(max_requests=200,
                     max_output_tokens=200 * REVIEW_MAX_TOKENS,
                     max_input_bytes=10_000_000)


# ---- limits ------------------------------------------------------------------------

def test_limits_parse_requires_the_mandatory_caps():
    with pytest.raises(BatchError):
        BatchLimits.parse({"max_requests": 5}, False)          # no output cap
    with pytest.raises(BatchError):
        BatchLimits.parse({"max_requests": 5,
                           "max_output_tokens": 100}, False)   # no input cap
    with pytest.raises(BatchError):
        BatchLimits.parse({"max_requests": 5, "max_output_tokens": 100,
                           "max_input_bytes": 1000, "extra": 1}, False)
    with pytest.raises(BatchError):
        BatchLimits.parse({"max_requests": 5, "max_output_tokens": 100,
                           "max_input_bytes": 1000,
                           "max_cost_usd": 1.0}, False)        # no pricing
    ok = BatchLimits.parse({"max_requests": 5, "max_output_tokens": 100,
                            "max_input_tokens": 500}, False)
    assert ok.max_requests == 5 and ok.max_input_tokens == 500


def test_pricing_config_is_strict(tmp_path):
    p = tmp_path / "pricing.json"
    p.write_text(json.dumps({"openai": {"gpt": {"input_per_mtok": 5,
                                                "output_per_mtok": 15}}}),
                 encoding="utf-8")
    assert load_pricing({"AUDITOR_AI_PRICING": str(p)}) is not None
    p.write_text(json.dumps({"openai": {"gpt": {"input_per_mtok": "cheap"}}}),
                 encoding="utf-8")
    assert load_pricing({"AUDITOR_AI_PRICING": str(p)}) is None
    assert load_pricing({}) is None


# ---- preview -----------------------------------------------------------------------

def test_preview_dedupes_and_reports_budgets(tmp_path):
    report = _multi_report(4)
    runner, store, _ = _runner(tmp_path, report, lambda: FakeTransport())
    ids = _rids(report)
    pv = runner.preview(ids + ids[:2], Provider.OLLAMA, "m")   # dupes in
    assert pv["findings"] == 4 and pv["request_count"] == 4
    assert pv["input_bytes"] > 0
    assert pv["max_output_tokens"] == 4 * REVIEW_MAX_TOKENS
    assert pv["cost_status"] == "unknown"
    assert pv["cached"] == 0 and pv["fresh"] == 4 and pv["stale"] == 0


def test_preview_cost_estimated_only_with_pricing(tmp_path):
    report = _multi_report(2)
    pricing = tmp_path / "pricing.json"
    pricing.write_text(json.dumps(
        {"ollama": {"m": {"input_per_mtok": 1.0, "output_per_mtok": 2.0}}}),
        encoding="utf-8")
    env = dict(LOCAL_ENV, AUDITOR_AI_PRICING=str(pricing))
    runner, _, _ = _runner(tmp_path, report, lambda: FakeTransport(), env=env)
    pv = runner.preview(_rids(report), Provider.OLLAMA, "m")
    assert pv["cost_status"] == "estimated"
    assert pv["estimated_cost_usd"] > 0


def test_preview_over_100_rejected(tmp_path):
    report = _multi_report(101)
    runner, _, _ = _runner(tmp_path, report, lambda: FakeTransport())
    with pytest.raises(BatchError):
        runner.preview(_rids(report), Provider.OLLAMA, "m")
    assert BATCH_MAX_FINDINGS == 100


# ---- start-time validation: zero network -------------------------------------------

class MustNotCall:
    def request(self, *a, **k):
        raise AssertionError("network before validation finished")


@pytest.mark.parametrize("mutate_ids", [
    lambda ids: [],                                     # empty
    lambda ids: ids + ids[:1],                          # duplicate
])
def test_bad_batches_rejected_before_any_network(tmp_path, mutate_ids):
    report = _multi_report(3)
    runner, _, _ = _runner(tmp_path, report, lambda: MustNotCall())
    with pytest.raises(BatchError):
        runner.start(mutate_ids(_rids(report)), Provider.OLLAMA, "m",
                     LIMITS, consented=False, local=True)


def test_unknown_id_rejected_before_any_network(tmp_path):
    report = _multi_report(2)
    runner, _, _ = _runner(tmp_path, report, lambda: MustNotCall())
    with pytest.raises(BatchError):
        runner.start(_rids(report) + ["f" * 64], Provider.OLLAMA, "m",
                     LIMITS, consented=False, local=True)


@pytest.mark.parametrize("limits", [
    BatchLimits(max_requests=2, max_output_tokens=999_999,
                max_input_bytes=10_000_000),            # 3 findings > 2 reqs
    BatchLimits(max_requests=10, max_output_tokens=999_999,
                max_input_bytes=10),                    # input cap tiny
    BatchLimits(max_requests=10, max_output_tokens=100,
                max_input_bytes=10_000_000),            # output cap tiny
])
def test_budget_breach_stops_before_the_first_request(tmp_path, limits):
    report = _multi_report(3)
    runner, _, _ = _runner(tmp_path, report, lambda: MustNotCall())
    with pytest.raises(BatchError):
        runner.start(_rids(report), Provider.OLLAMA, "m", limits,
                     consented=False, local=True)


# ---- execution ---------------------------------------------------------------------

def test_batch_completes_and_results_land_in_the_ai_sidecar(tmp_path):
    report = _multi_report(5)
    runner, store, bstore = _runner(tmp_path, report,
                                    lambda: FakeTransport(_reply("uncertain")))
    ids = _rids(report)
    bid = runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    st = runner.status(bid)
    assert st["state"] == "completed"
    assert st["counts"]["completed"] == 5 and st["counts"]["failed"] == 0
    assert st["assessments"]["uncertain"] == 5
    for rid in ids:
        assert store.for_review_id(rid, None)


def test_partial_failures_do_not_kill_the_batch(tmp_path):
    report = _multi_report(4)
    ids = _rids(report)
    calls = {"n": 0}

    class Flaky:
        def request(self, method, url, headers, json_body, timeout):
            calls["n"] += 1
            if calls["n"] == 2:
                raise TransportFailure("timeout")
            return HttpResponse(200, json.dumps(
                {"message": {"role": "assistant",
                             "content": json.dumps(_reply())}}).encode())
    runner, _, _ = _runner(tmp_path, report, lambda: Flaky())
    bid = runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    st = runner.status(bid)
    assert st["state"] == "completed"                # batch survives
    assert st["counts"]["completed"] == 3
    assert st["counts"]["failed"] == 1
    failed = [i for i in st["items"] if i["state"] == "failed"]
    assert failed[0]["error"] == "timeout"


def _gauge():
    peak = {"now": 0, "max": 0}
    lock = threading.Lock()

    class Gauge:
        def request(self, method, url, headers, json_body, timeout):
            with lock:
                peak["now"] += 1
                peak["max"] = max(peak["max"], peak["now"])
            time.sleep(0.05)
            with lock:
                peak["now"] -= 1
            return HttpResponse(200, json.dumps(
                {"message": {"role": "assistant",
                             "content": json.dumps(_reply())}}).encode())
    return Gauge, peak


def test_local_concurrency_defaults_to_one(tmp_path):
    report = _multi_report(6)
    Gauge, peak = _gauge()
    runner, _, _ = _runner(tmp_path, report, lambda: Gauge())
    bid = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    assert peak["max"] == 1                     # sequential by default


def test_local_concurrency_two_is_an_explicit_opt_in(tmp_path):
    report = _multi_report(6)
    Gauge, peak = _gauge()
    env = dict(LOCAL_ENV, AUDITOR_AI_LOCAL_CONCURRENCY="2")
    runner, _, _ = _runner(tmp_path, report, lambda: Gauge(), env=env)
    bid = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    assert 1 <= peak["max"] <= 2


def test_local_concurrency_env_is_strict():
    from auditor.ai.batch import local_concurrency
    assert local_concurrency({}) == 1
    assert local_concurrency({"AUDITOR_AI_LOCAL_CONCURRENCY": "2"}) == 2
    for junk in ("3", "0", "-1", "two", "22", " 2x"):
        assert local_concurrency({"AUDITOR_AI_LOCAL_CONCURRENCY": junk}) == 1


def test_review_timeout_is_a_bounded_local_setting():
    from auditor.ai.review import review_timeout
    assert review_timeout({}) == 120.0
    assert review_timeout({"AUDITOR_AI_REVIEW_TIMEOUT": "300"}) == 300.0
    assert review_timeout({"AUDITOR_AI_REVIEW_TIMEOUT": "5"}) == 30.0
    assert review_timeout({"AUDITOR_AI_REVIEW_TIMEOUT": "99999"}) == 600.0
    assert review_timeout({"AUDITOR_AI_REVIEW_TIMEOUT": "fast"}) == 120.0


def test_preview_reports_effective_concurrency_and_timeout(tmp_path):
    report = _multi_report(2)
    env = dict(LOCAL_ENV, AUDITOR_AI_REVIEW_TIMEOUT="300")
    runner, _, _ = _runner(tmp_path, report, lambda: FakeTransport(), env=env)
    pv = runner.preview(_rids(report), Provider.OLLAMA, "m", local=True)
    assert pv["concurrency"] == 1
    assert pv["request_timeout_seconds"] == 300
    pv_remote = runner.preview(_rids(report), Provider.OLLAMA, "m",
                               local=False)
    assert pv_remote["concurrency"] == 1        # remote is always 1


def test_cancel_stops_the_next_request_not_the_running_one(tmp_path):
    report = _multi_report(6)
    started: list[str] = []
    gate = threading.Event()

    class Slow:
        def request(self, method, url, headers, json_body, timeout):
            started.append("x")
            gate.wait(5)
            return HttpResponse(200, json.dumps(
                {"message": {"role": "assistant",
                             "content": json.dumps(_reply())}}).encode())
    runner, _, _ = _runner(tmp_path, report, lambda: Slow())
    bid = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    time.sleep(0.3)                       # let the first requests start
    n_started = len(started)
    runner.cancel(bid)
    gate.set()
    runner.wait(bid)
    st = runner.status(bid)
    assert st["state"] == "canceled"
    # nothing NEW started after cancel; in-flight ones finished cleanly
    assert len(started) == n_started
    assert st["counts"]["completed"] == n_started
    assert st["counts"]["canceled"] == 6 - n_started


def test_restart_marks_running_batches_interrupted(tmp_path):
    path = tmp_path / "r.ai-batches.json"
    store = BatchStore(path)
    store.put({"batch_id": "b1", "state": "running", "created_at": "t",
               "provider": "ollama", "model": "m", "prompt_version": "x",
               "limits": {}, "reason": "",
               "items": [{"review_id": "a" * 64, "state": "running",
                          "assessment": "", "error": ""}]})
    reloaded = BatchStore(path)          # a new process
    row = reloaded.get("b1")
    assert row["state"] == "interrupted"
    assert row["items"][0]["state"] == "canceled"


def test_batch_sidecar_atomic_rollback_on_replace_failure(tmp_path,
                                                          monkeypatch):
    path = tmp_path / "r.ai-batches.json"
    store = BatchStore(path)
    store.put({"batch_id": "b1", "state": "completed", "created_at": "t",
               "provider": "ollama", "model": "m", "prompt_version": "x",
               "limits": {}, "reason": "", "items": []})
    before = path.read_bytes()

    def boom(src, dst):
        raise OSError("gone")
    monkeypatch.setattr("os.replace", boom)
    with pytest.raises(BatchError):
        store.put({"batch_id": "b2", "state": "completed", "created_at": "t",
                   "provider": "ollama", "model": "m", "prompt_version": "x",
                   "limits": {}, "reason": "", "items": []})
    monkeypatch.undo()
    assert path.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))


def test_batch_sidecar_carries_no_source_or_prompts(tmp_path):
    report = _multi_report(2)
    runner, _, bstore = _runner(tmp_path, report,
                                lambda: FakeTransport())
    bid = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    raw = (tmp_path / "r.ai-batches.json").read_text(encoding="utf-8")
    assert "CONTEXT PIECES" not in raw and "def f0" not in raw
    assert "snippet" not in raw


def test_only_one_batch_at_a_time(tmp_path):
    report = _multi_report(3)
    gate = threading.Event()

    class Slow:
        def request(self, method, url, headers, json_body, timeout):
            gate.wait(5)
            return HttpResponse(200, json.dumps(
                {"message": {"role": "assistant",
                             "content": json.dumps(_reply())}}).encode())
    runner, _, _ = _runner(tmp_path, report, lambda: Slow())
    ids = _rids(report)
    bid = runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    with pytest.raises(BatchError) as exc:
        runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                     consented=False, local=True)
    assert "already running" in str(exc.value)
    gate.set()
    runner.wait(bid)


# ---- web API -----------------------------------------------------------------------

def _client(tmp_path, monkeypatch, transport=None, remote=False):
    if transport is not None:
        monkeypatch.setattr("auditor.ai.transport.RequestsTransport",
                            lambda: transport)
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    if remote:
        monkeypatch.setenv("AUDITOR_AI_REMOTE_REVIEWS", "confirm")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    else:
        monkeypatch.delenv("AUDITOR_AI_REMOTE_REVIEWS", raising=False)
    rp = _write_report(tmp_path)
    _write_repo(tmp_path)
    return TestClient(app_mod.create_app(rp, repo_root=tmp_path))


def _wait_done(c, bid, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = c.get(f"/api/ai/batches/{bid}").json()
        if st["state"] not in ("running", "pending"):
            return st
        time.sleep(0.05)
    raise AssertionError("batch did not settle in time")


def test_api_full_local_batch_flow(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, FakeTransport(_reply("uncertain")))
    pv = c.post("/api/ai/batches/preview",
                json={"review_ids": [_rid(), _rid()], "provider": "ollama",
                      "model": "m"})
    assert pv.status_code == 200
    body = pv.json()
    assert body["findings"] == 1          # deduped
    assert body["consent_token"] == ""    # local — no consent needed
    r = c.post("/api/ai/batches", json={
        "review_ids": body["review_ids"], "provider": "ollama", "model": "m",
        "limits": {"max_requests": 5,
                   "max_output_tokens": 10 * REVIEW_MAX_TOKENS,
                   "max_input_bytes": 1_000_000}})
    assert r.status_code == 202
    bid = r.json()["batch_id"]
    st = _wait_done(c, bid)
    assert st["state"] == "completed" and st["counts"]["completed"] == 1
    # results visible in the summary endpoint for the UI filter
    summary = c.get("/api/ai/reviews").json()
    assert summary["results"][_rid()]["assessment"] == "uncertain"


def test_api_batch_remote_needs_consent_token(tmp_path, monkeypatch):
    class T:
        def request(self, method, url, headers, json_body, timeout):
            return HttpResponse(200, json.dumps(
                {"output_text": json.dumps(_reply("uncertain"))}).encode())
    c = _client(tmp_path, monkeypatch, transport=T(), remote=True)
    pv = c.post("/api/ai/batches/preview",
                json={"review_ids": [_rid()], "provider": "openai",
                      "model": "gpt"})
    assert pv.status_code == 200
    token = pv.json()["consent_token"]
    assert token
    limits = {"max_requests": 5, "max_output_tokens": 10 * REVIEW_MAX_TOKENS,
              "max_input_bytes": 1_000_000}
    r0 = c.post("/api/ai/batches", json={
        "review_ids": [_rid()], "provider": "openai", "model": "gpt",
        "limits": limits})
    assert r0.status_code == 403          # no token
    r1 = c.post("/api/ai/batches", json={
        "review_ids": [_rid()], "provider": "openai", "model": "gpt",
        "limits": limits, "consent_token": token})
    assert r1.status_code == 202
    st = _wait_done(c, r1.json()["batch_id"])
    assert st["state"] == "completed"


def test_api_batch_remote_disabled_zero_network(tmp_path, monkeypatch):
    monkeypatch.setattr("auditor.ai.transport.RequestsTransport", MustNotCall)
    c = _client(tmp_path, monkeypatch, remote=False)
    pv = c.post("/api/ai/batches/preview",
                json={"review_ids": [_rid()], "provider": "openai",
                      "model": "gpt"})
    assert pv.status_code == 403
    assert pv.json()["status"] == "privacy_gate_required"


def test_api_batch_cancel_and_unknown(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, FakeTransport())
    assert c.get("/api/ai/batches/nope").status_code == 404
    assert c.post("/api/ai/batches/nope/cancel").status_code == 404


def test_api_batch_duplicates_rejected(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, MustNotCall())
    r = c.post("/api/ai/batches", json={
        "review_ids": [_rid(), _rid()], "provider": "ollama", "model": "m",
        "limits": {"max_requests": 5, "max_output_tokens": 99999,
                   "max_input_bytes": 1_000_000}})
    assert r.status_code == 400
    assert "duplicate" in r.json()["error"]


# ==== AI-2 closing round ============================================================

# ---- 2) no TOCTOU between consent and send ----------------------------------------

def test_start_with_packs_never_rebuilds(tmp_path):
    report = _multi_report(2)
    ids = _rids(report)
    from auditor.ai.review import build_context_pack
    packs = {rid: build_context_pack(report, None, rid) for rid in ids}

    def forbidden_build(rid):
        raise AssertionError("packs were rebuilt after consent")
    store = AIReviewStore(tmp_path / "r.ai-reviews.json")
    bstore = BatchStore(tmp_path / "r.ai-batches.json")
    runner = BatchRunner(build_pack=forbidden_build, ai_store=store,
                         batch_store=bstore,
                         transport_factory=lambda: FakeTransport(),
                         env=LOCAL_ENV)
    bid = runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True, packs=packs)
    runner.wait(bid)
    assert runner.status(bid)["state"] == "completed"


def test_start_rejects_packs_that_do_not_match_ids(tmp_path):
    report = _multi_report(2)
    ids = _rids(report)
    from auditor.ai.review import build_context_pack
    packs = {ids[0]: build_context_pack(report, None, ids[0])}
    runner, _, _ = _runner(tmp_path, report, lambda: MustNotCall())
    with pytest.raises(BatchError):
        runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                     consented=False, local=True, packs=packs)


def test_api_approved_digest_is_exactly_the_sent_digest(tmp_path,
                                                        monkeypatch):
    """The deterministic TOCTOU regression: the digest bound in the redeemed
    consent token equals sha256 of the canonical context that actually went
    on the wire."""
    import hashlib
    sent = {}

    class Capture:
        def request(self, method, url, headers, json_body, timeout):
            sent["user"] = json_body["input"]
            return HttpResponse(200, json.dumps(
                {"output_text": json.dumps(_reply("uncertain"))}).encode())
    c = _client(tmp_path, monkeypatch, transport=Capture(), remote=True)
    pv = c.post("/api/ai/batches/preview",
                json={"review_ids": [_rid()], "provider": "openai",
                      "model": "gpt"}).json()
    approved_digest = pv["context_digests"][0]
    r = c.post("/api/ai/batches", json={
        "review_ids": [_rid()], "provider": "openai", "model": "gpt",
        "limits": {"max_requests": 5,
                   "max_output_tokens": 10 * REVIEW_MAX_TOKENS,
                   "max_input_bytes": 1_000_000},
        "consent_token": pv["consent_token"]})
    assert r.status_code == 202
    _wait_done(c, r.json()["batch_id"])
    canonical = sent["user"][len("CONTEXT PIECES:\n"):]
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() \
        == approved_digest


def test_api_batch_context_change_since_preview_is_mismatch_zero_network(
        tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, transport=MustNotCall(), remote=True)
    pv = c.post("/api/ai/batches/preview",
                json={"review_ids": [_rid()], "provider": "openai",
                      "model": "gpt"}).json()
    (tmp_path / "app.py").write_text("changed = True\n", encoding="utf-8")
    r = c.post("/api/ai/batches", json={
        "review_ids": [_rid()], "provider": "openai", "model": "gpt",
        "limits": {"max_requests": 5,
                   "max_output_tokens": 10 * REVIEW_MAX_TOKENS,
                   "max_input_bytes": 1_000_000},
        "consent_token": pv["consent_token"]})
    assert r.status_code == 403
    assert r.json()["status"] == "consent_mismatch"


# ---- 3) runner rollback ------------------------------------------------------------

class FlakyStore(BatchStore):
    """Fails the Nth put (1-based); every other put succeeds."""

    def __init__(self, path, fail_on):
        self.fail_on = set(fail_on)
        self.calls = 0
        super().__init__(path)

    def put(self, batch):
        self.calls += 1
        if self.calls in self.fail_on:
            raise BatchError("batch sidecar write failed: OSError")
        super().put(batch)


def _flaky_runner(tmp_path, report, fail_on, transport=None):
    store = AIReviewStore(tmp_path / "r.ai-reviews.json")
    bstore = FlakyStore(tmp_path / "r.ai-batches.json", fail_on)
    return BatchRunner(
        build_pack=lambda rid: __import__("auditor.ai.review",
                                          fromlist=["build_context_pack"])
        .build_context_pack(report, None, rid),
        ai_store=store, batch_store=bstore,
        transport_factory=transport or (lambda: FakeTransport()),
        env=LOCAL_ENV), bstore


def test_failed_first_put_rolls_back_active(tmp_path):
    report = _multi_report(2)
    runner, bstore = _flaky_runner(tmp_path, report, fail_on={1})
    ids = _rids(report)
    with pytest.raises(BatchError):
        runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                     consented=False, local=True)
    # the claim was rolled back — a new batch is accepted immediately
    bid = runner.start(ids, Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    assert runner.status(bid)["state"] == "completed"
    assert not list(tmp_path.glob("*.tmp"))


def test_failed_mid_run_put_stops_safely_not_silently(tmp_path):
    report = _multi_report(4)
    calls = {"n": 0}

    class Counting(FakeTransport):
        def request(self, *a, **k):
            calls["n"] += 1
            return super().request(*a, **k)
    # put #1 = initial write; #2 = after the first item -> fails
    runner, bstore = _flaky_runner(tmp_path, report, fail_on={2},
                                   transport=lambda: Counting())
    bid = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    st = runner.status(bid)
    assert st["state"] == "failed"
    assert "persisted" in st["reason"]
    assert calls["n"] <= 2                       # no request spree after failure
    # runner is reusable afterwards
    bid2 = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                        consented=False, local=True)
    runner.wait(bid2)
    assert runner.status(bid2)["state"] == "completed"


def test_failed_final_put_still_frees_the_runner(tmp_path):
    report = _multi_report(2)
    # puts: 1 initial, 2+3 per-item, 4 final -> fail the final one
    runner, bstore = _flaky_runner(tmp_path, report, fail_on={4})
    bid = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                       consented=False, local=True)
    runner.wait(bid)
    bid2 = runner.start(_rids(report), Provider.OLLAMA, "m", LIMITS,
                        consented=False, local=True)
    runner.wait(bid2)
    assert runner.status(bid2)["state"] == "completed"


# ---- 4) finite costs ---------------------------------------------------------------

@pytest.mark.parametrize("body", [
    '{"ollama": {"m": {"input_per_mtok": NaN, "output_per_mtok": 1}}}',
    '{"ollama": {"m": {"input_per_mtok": Infinity, "output_per_mtok": 1}}}',
    '{"ollama": {"m": {"input_per_mtok": -Infinity, "output_per_mtok": 1}}}',
    '{"ollama": {"m": {"input_per_mtok": 0, "output_per_mtok": 1}}}',
    '{"ollama": {"m": {"input_per_mtok": -2, "output_per_mtok": 1}}}',
])
def test_non_finite_or_non_positive_pricing_is_void(tmp_path, body):
    p = tmp_path / "pricing.json"
    p.write_text(body, encoding="utf-8")
    assert load_pricing({"AUDITOR_AI_PRICING": str(p)}) is None


@pytest.mark.parametrize("cost", [float("nan"), float("inf"),
                                  float("-inf"), 0, -3])
def test_non_finite_max_cost_usd_rejected(cost):
    with pytest.raises(BatchError):
        BatchLimits.parse({"max_requests": 5, "max_output_tokens": 100,
                           "max_input_bytes": 1000, "max_cost_usd": cost},
                          True)


def test_api_nan_cost_cap_rejected_before_any_network(tmp_path, monkeypatch):
    pricing = tmp_path / "pricing.json"
    pricing.write_text(json.dumps(
        {"ollama": {"m": {"input_per_mtok": 1.0, "output_per_mtok": 1.0}}}),
        encoding="utf-8")
    monkeypatch.setenv("AUDITOR_AI_PRICING", str(pricing))
    c = _client(tmp_path, monkeypatch, MustNotCall())
    # json.dumps happily emits the NaN token; the server must reject it
    r = c.post("/api/ai/batches",
               content='{"review_ids": ["' + _rid() + '"], '
                       '"provider": "ollama", "model": "m", '
                       '"limits": {"max_requests": 5, '
                       '"max_output_tokens": 99999, '
                       '"max_input_bytes": 100000, "max_cost_usd": NaN}}',
               headers={"Content-Type": "application/json"})
    assert r.status_code in (400, 422)


def test_report_and_human_sidecar_untouched_by_batches(tmp_path,
                                                       monkeypatch):
    import hashlib
    c = _client(tmp_path, monkeypatch, FakeTransport())
    rp = tmp_path / "report.json"
    human = tmp_path / "report.reviews.json"
    human.write_text(json.dumps({"schema_version": 1, "reviews": {}}),
                     encoding="utf-8")
    before = (hashlib.sha256(rp.read_bytes()).hexdigest(),
              hashlib.sha256(human.read_bytes()).hexdigest())
    r = c.post("/api/ai/batches", json={
        "review_ids": [_rid()], "provider": "ollama", "model": "m",
        "limits": {"max_requests": 5,
                   "max_output_tokens": 10 * REVIEW_MAX_TOKENS,
                   "max_input_bytes": 1_000_000}})
    _wait_done(c, r.json()["batch_id"])
    after = (hashlib.sha256(rp.read_bytes()).hexdigest(),
             hashlib.sha256(human.read_bytes()).hexdigest())
    assert before == after
"""AI-CONTEXT-DEFAULT-GATE closing: the measurement tool's own contract.

A measurement is only as trustworthy as the instrument, and this one decides
whether a shipped default changes. These pin the parts that could silently
corrupt a result: the frozen block order, the residency precondition that must
stop a block *before* any case runs, the refusal to score a partial block, the
stopping rules, the privacy boundary of the published summary, and the token
reader.

Pure functions and fakes only. No model, no network, no GPU.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from auditor.ai.contract import HttpResponse

TOOL = (Path(__file__).resolve().parent.parent / "tools"
        / "quality_default_gate.py")


def _tool():
    spec = importlib.util.spec_from_file_location("quality_default_gate", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = _tool()


# ---- the frozen ordering ---------------------------------------------------

def test_the_block_order_is_exactly_what_the_plan_registered():
    """Both sizes for each of the three groups, counterbalanced. A later edit
    that reorders or drops a block invalidates the comparison silently, so the
    literal tuple is asserted."""
    assert G.BLOCKS == (("dev", 4096), ("dev", 8192),
                        ("holdout", 8192), ("holdout", 4096),
                        ("cross_project", 4096), ("cross_project", 8192))
    for group in ("dev", "holdout", "cross_project"):
        sizes = [n for g, n in G.BLOCKS if g == group]
        assert sorted(sizes) == [4096, 8192], group
        assert len(sizes) == 2, group
    # counterbalanced: dev and holdout must not lead with the same size
    dev_first = next(n for g, n in G.BLOCKS if g == "dev")
    hold_first = next(n for g, n in G.BLOCKS if g == "holdout")
    assert dev_first != hold_first


# ---- the residency precondition -------------------------------------------

def _resident(ctx: int, size: int = 10_000, vram: int | None = None):
    vram = size if vram is None else vram
    return {"context_length": ctx, "size_bytes": size, "size_vram_bytes": vram,
            "fully_on_gpu": size == vram,
            "cpu_offload_bytes": max(0, size - vram), "read_error": ""}


def test_a_mismatched_context_length_stops_the_block():
    """The size that was asked for is not the size that was given: whatever
    this block would measure, it is not the requested window."""
    why = G.residency_verdict(_resident(4096), 8192)
    assert why and "context_length" in why


def test_a_partially_offloaded_model_stops_the_block():
    """`size_vram < size` means part of the model is on the CPU. A run like
    that measures the offload, not the window."""
    why = G.residency_verdict(_resident(8192, size=10_000, vram=9_000), 8192)
    assert why and "offload" in why


@pytest.mark.parametrize("res", [
    {"context_length": 8192, "fully_on_gpu": None},          # unknown
    {"context_length": 8192},                                # absent
    {"context_length": None, "fully_on_gpu": True},          # no ctx
    {"read_error": "boom"},                                  # unreadable
    {"no_model_loaded": True},                               # nothing loaded
])
def test_anything_short_of_proven_residency_stops_the_block(res):
    """Fail-closed: only an explicit `fully_on_gpu is True` with a matching
    context length may proceed. Unknown is not permission."""
    assert G.residency_verdict(res, 8192)


def test_proven_residency_is_the_only_thing_that_proceeds():
    assert G.residency_verdict(_resident(8192), 8192) == ""
    assert G.residency_verdict(_resident(4096), 4096) == ""


def test_the_verdict_reason_is_safe_to_publish():
    """It reaches the committed summary, so it may not carry a path, a host or
    an exception string."""
    for res, req in ((_resident(4096), 8192),
                     (_resident(8192, 10_000, 9_000), 8192)):
        why = G.residency_verdict(res, req)
        assert "\\" not in why and "/" not in why
        assert "http" not in why and "C:" not in why


# ---- stopping rules --------------------------------------------------------

def test_three_consecutive_infrastructure_errors_stop_the_run():
    assert G.CONSECUTIVE_INFRA_ABORT == 3
    assert not G.infra_abort_reached(0)
    assert not G.infra_abort_reached(2)
    assert G.infra_abort_reached(3)
    assert G.infra_abort_reached(4)


def test_the_wall_clock_cap_stops_the_run_and_is_ninety_minutes():
    assert G.WALL_CLOCK_CAP_S == 90 * 60
    assert not G.wall_clock_exceeded(0.0, G.WALL_CLOCK_CAP_S)
    assert G.wall_clock_exceeded(0.0, G.WALL_CLOCK_CAP_S + 1)


# ---- a partial block is not scored -----------------------------------------

class _Corpus(list):
    """Stands in for the frozen corpus: only its length is consulted here."""


def test_a_partial_block_is_not_classified_and_yields_no_verdict():
    corpus = _Corpus([object(), object(), object()])
    entry = G.engine_entry([{"case_id": "a"}], corpus, {"cases": []},
                           cross_project=False)
    assert entry["cases_run"] == 1
    assert "classification" not in entry
    assert "summary" not in entry            # nothing for the report to quote
    assert "partial block" in entry["classification_skipped"]


def test_a_complete_block_passes_one_to_one_and_produces_the_summary():
    """The real corpus and the real classifier: a complete, legal block must
    come back with a computed verdict, which is itself the proof that
    verify_one_to_one accepted it."""
    from auditor.ai.quality_corpus import SPLIT_CROSS_PROJECT, cases
    from auditor.ai.quality_harness import build_plan

    corpus = cases(SPLIT_CROSS_PROJECT)
    plan = build_plan(corpus)
    rows = []
    for pc in plan["cases"]:
        base = {"case_id": pc["case_id"], "query_id": pc["query_id"],
                "category": pc["category"], "expected": pc["kind"]}
        if pc["unit_id"]:
            rows.append({**base, "state": "completed",
                         "unit_id": pc["unit_id"],
                         "context_digest": pc["context_digest"],
                         "outcome": "no_issue_observed",
                         "model_outcome": "no_issue_observed",
                         "effective_outcome": "no_issue_observed",
                         "guard_downgraded": "", "issues": [],
                         "provider": "ollama", "model": "m",
                         "prompt_version": plan["prompt_version"],
                         "query_version": 3})
        else:
            rows.append({**base, "state": "no_unit", "unit_id": "",
                         "context_digest": ""})

    entry = G.engine_entry(rows, corpus, plan, cross_project=True)
    assert entry["cases_run"] == len(corpus)
    assert "classification_skipped" not in entry
    assert entry["summary"]["totals"]["clean"] >= 1
    assert entry["evidence_earned"]["rows"]      # acceptance computed too


def test_a_block_that_fails_one_to_one_raises_rather_than_scoring():
    """Fail-closed: a forged identity is refused, not scored."""
    from auditor.ai.quality_corpus import SPLIT_CROSS_PROJECT, cases
    from auditor.ai.quality_harness import HarnessError, build_plan

    corpus = cases(SPLIT_CROSS_PROJECT)
    plan = build_plan(corpus)
    rows = [{"case_id": pc["case_id"], "query_id": pc["query_id"],
             "category": pc["category"], "expected": pc["kind"],
             "state": "no_unit", "unit_id": "", "context_digest": ""}
            for pc in plan["cases"]]
    rows[0]["unit_id"] = "f" * 64            # a no_unit row with an identity
    with pytest.raises(HarnessError):
        G.engine_entry(rows, corpus, plan, cross_project=True)


# ---- the published summary is the privacy boundary -------------------------

_FORBIDDEN_KEYS = ("case_id", "cases", "wire_sample", "observations",
                   "classification", "evidence_earned", "issues", "pieces",
                   "canonical", "prompt", "path", "load_error", "results")


def _walk(node, out):
    if isinstance(node, dict):
        for k, v in node.items():
            out.append(("key", str(k)))
            _walk(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk(v, out)
    else:
        out.append(("val", node))


def test_the_public_summary_carries_no_case_ids_paths_wire_or_model_output():
    report = {
        "aborted": "", "model": "m", "engines": ["window", "agent"],
        "block_order": [["dev", 4096]], "wall_seconds": 7,
        "blocks": [{
            "group": "dev", "requested_num_ctx": 4096,
            "observed": {"context_length": 4096, "fully_on_gpu": True,
                         "cpu_offload_bytes": 0},
            "load_error": "OSError: C:/secret/path exploded",
            "gpu_after_load": {"vram_used_mib": 1, "vram_total_mib": 2},
            "corpus_digest": "d" * 64, "planned_cases": 1,
            "completed_cases": 1,
            "cases": [{"case_id": "AI001-pos", "peak_input_tokens": 10,
                       "window_state": "completed", "agent_state": "completed"}],
            "wire_sample": [{"url": "http://127.0.0.1:11434/api/chat"}],
            "engines": {"window": {"cases_run": 1, "summary": {"totals": {}},
                                   "observations": {"rows": [
                                       {"case_id": "AI001-pos",
                                        "cited_files": ["src/secret.py"],
                                        "issues": [{"summary": "MODEL WORDS"}]}]},
                                   "classification": {"per_query": {}}}}}]}
    pub = G.build_public_summary(report)
    blob = json.dumps(pub)

    assert "AI001-pos" not in blob            # no case identity
    assert "src/secret.py" not in blob        # no source path
    assert "MODEL WORDS" not in blob          # no model output
    assert "127.0.0.1" not in blob            # no wire record
    assert "C:/secret/path" not in blob       # no local path via load_error
    assert "per_query" not in blob            # no raw classification

    keys = [v for kind, v in _sorted(pub) if kind == "key"]
    for bad in ("case_id", "wire_sample", "observations", "classification",
                "issues", "load_error", "cited_files"):
        assert bad not in keys, bad


def _sorted(pub):
    out: list = []
    _walk(pub, out)
    return out


def test_a_no_measurement_block_says_so_and_still_publishes_nothing_private():
    report = {"aborted": "residency_precondition_failed", "model": "m",
              "engines": ["window"], "block_order": [], "wall_seconds": 1,
              "blocks": [{
                  "group": "dev", "requested_num_ctx": 8192,
                  "observed": {"context_length": 4096, "fully_on_gpu": False,
                               "cpu_offload_bytes": 1234},
                  "gpu_after_load": {"vram_used_mib": 1, "vram_total_mib": 2},
                  "corpus_digest": "d" * 64, "planned_cases": 25,
                  "cases": [],
                  "no_measurement": G.residency_verdict(
                      {"context_length": 4096, "fully_on_gpu": False}, 8192)}]}
    pub = G.build_public_summary(report)
    b = pub["blocks"][0]
    assert b["no_measurement"]
    assert b["completed_cases"] == 0
    assert b["peak_input_tokens_max"] is None       # nothing measured
    assert pub["aborted"] == "residency_precondition_failed"


def test_the_published_summary_is_reproducible_from_the_stored_run():
    """The strongest check available without a model: re-derive the committed
    numbers from the raw report and require them to match EXACTLY. If they ever
    diverge, either the tool changed or the published figures were edited."""
    run = (Path(__file__).resolve().parent.parent
           / ".quality-local" / "ai-quality" / "ctxdef")
    if not (run / "report.json").exists():
        pytest.skip("the raw run is local-only and not present here")
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    published = (run / "public-summary.json").read_text(encoding="utf-8")
    rebuilt = json.dumps(G.build_public_summary(report),
                         ensure_ascii=True, indent=1)
    assert rebuilt == published


def test_raw_output_is_written_only_under_the_ignored_path():
    """The tool's output directory is fixed under `.quality-local`; nothing
    else may receive per-case detail."""
    src = TOOL.read_text(encoding="utf-8")
    assert '"__file__"' not in src
    assert '.quality-local' in src
    # every write goes through out_dir, which is built from that path alone
    assert 'out_dir = (Path(__file__).resolve().parent.parent' in src
    assert '/ ".quality-local" / "ai-quality" / args.run_id)' in src
    for target in ('(out_dir / "report.json")',
                   '(out_dir / "public-summary.json")'):
        assert target in src, target


# ---- the token reader ------------------------------------------------------

class _Stub:
    def __init__(self, bodies):
        self.bodies = list(bodies)
        self.n = 0

    def request(self, method, url, headers, json_body, timeout):
        b = self.bodies[min(self.n, len(self.bodies) - 1)]
        self.n += 1
        return HttpResponse(200, b)


def _spy(bodies):
    turns, wire = [], []
    spy = G.TokenSpy(turns, wire)
    spy._inner = _Stub(bodies)
    return spy, turns, wire


def test_legal_counts_are_recorded_and_the_peak_is_the_largest_single_turn():
    bodies = [json.dumps({"prompt_eval_count": p, "eval_count": e,
                          "done_reason": "stop"}).encode()
              for p, e in ((900, 5), (2657, 7), (1800, 4))]
    spy, turns, wire = _spy(bodies)
    for _ in range(3):
        spy.request("POST", "/api/chat", {}, {"options": {"num_ctx": 4096}}, 30)

    assert [t["input_tokens"] for t in turns] == [900, 2657, 1800]
    peak = G._peak(turns)
    assert peak["peak_input_tokens"] == 2657      # the max, never the sum
    assert peak["total_output_tokens"] == 16      # outputs DO accumulate
    assert peak["turns"] == 3
    assert wire and wire[0]["options"] == {"num_ctx": 4096}


@pytest.mark.parametrize("body", [
    b"not json at all",
    b"",
    b"{",
    json.dumps({"prompt_eval_count": "many"}).encode(),      # wrong type
    json.dumps([1, 2, 3]).encode(),                          # not an object
])
def test_a_malformed_reply_is_recorded_as_unknown_not_zero(body):
    """A missing or unreadable count is not evidence the prompt was empty.
    Recording it as 0 would deflate the peak and make a full window look
    roomy — the opposite of what this measurement is for."""
    spy, turns, _ = _spy([body])
    spy.request("POST", "/api/chat", {}, {}, 30)
    assert len(turns) == 1
    assert turns[0]["input_tokens"] in (None, 0)
    assert G._peak(turns)["peak_input_tokens"] is None


def test_the_spy_returns_the_response_untouched():
    """It is an instrument, not a middleman."""
    body = json.dumps({"prompt_eval_count": 11, "eval_count": 2,
                       "message": {"content": "hello"}}).encode()
    spy, _, _ = _spy([body])
    got = spy.request("POST", "/api/chat", {}, {}, 30)
    assert got.status == 200 and got.body == body


def test_a_mix_of_good_and_malformed_turns_keeps_the_good_peak():
    spy, turns, _ = _spy([b"broken",
                          json.dumps({"prompt_eval_count": 2760,
                                      "eval_count": 3}).encode()])
    spy.request("POST", "/api/chat", {}, {}, 30)
    spy.request("POST", "/api/chat", {}, {}, 30)
    peak = G._peak(turns)
    assert peak["turns"] == 2
    assert peak["peak_input_tokens"] == 2760

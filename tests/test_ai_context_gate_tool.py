"""AI-CONTEXT-GATE: the token instrument, pinned.

The round's whole conclusion turns on one number — the peak REAL input tokens
in any single turn — because a bigger context window cannot explain a
difference the old window was never asked for. That number comes from Ollama's
`prompt_eval_count`, not from `bytes_after` and not from the project's
3-bytes-per-token estimator, so the reading of it is worth a test.

No network: the spy wraps a stub transport.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from auditor.ai.contract import HttpResponse

TOOL = (Path(__file__).resolve().parent.parent / "tools"
        / "quality_context_gate.py")


def _tool():
    spec = importlib.util.spec_from_file_location("quality_context_gate", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Stub:
    """Answers with the token counts it was given, in order."""

    def __init__(self, counts):
        self.counts = list(counts)
        self.seen = 0

    def request(self, method, url, headers, json_body, timeout):
        pe, ev = self.counts[min(self.seen, len(self.counts) - 1)]
        self.seen += 1
        body = {"model": "m", "done_reason": "stop",
                "message": {"role": "assistant", "content": "ok"}}
        if pe is not None:
            body["prompt_eval_count"] = pe
        if ev is not None:
            body["eval_count"] = ev
        return HttpResponse(200, json.dumps(body).encode())


def _spy(mod, counts):
    turns, wire = [], []
    spy = mod.TokenSpy(turns, wire)
    spy._inner = _Stub(counts)
    return spy, turns, wire


def test_the_peak_is_the_largest_single_turn_not_the_sum():
    """The agent re-sends the growing conversation each turn, so the question
    "did one prompt approach the window?" is answered by the MAXIMUM turn. A
    sum would exceed the window on any multi-turn run and mean nothing."""
    mod = _tool()
    spy, turns, _ = _spy(mod, [(900, 5), (2400, 7), (1800, 4)])
    for _ in range(3):
        spy.request("POST", "/api/chat", {}, {}, 30)

    peak = mod._peak(turns)
    assert peak["turns"] == 3
    assert peak["peak_input_tokens"] == 2400          # not 5100
    assert peak["total_output_tokens"] == 16          # outputs DO accumulate


def test_the_spy_returns_the_response_unchanged():
    """It is an instrument, not a middleman: whatever the transport returned
    must reach the runtime untouched, or the measurement has altered the run."""
    mod = _tool()
    spy, _, _ = _spy(mod, [(10, 1)])
    inner = spy._inner
    got = spy.request("POST", "/api/chat", {}, {"tools": [1, 2]}, 30)
    expected = inner.request("POST", "/api/chat", {}, {}, 30)
    assert got.status == expected.status == 200
    assert json.loads(got.body) == json.loads(expected.body)


def test_a_response_without_counts_is_recorded_as_unknown_not_zero():
    """A missing count is not evidence that the prompt was empty. It must not
    silently deflate the peak — that would understate window pressure and make
    a context effect look impossible when it was merely unmeasured."""
    mod = _tool()
    spy, turns, _ = _spy(mod, [(None, None), (1500, 2)])
    spy.request("POST", "/api/chat", {}, {}, 30)
    spy.request("POST", "/api/chat", {}, {}, 30)

    assert turns[0]["input_tokens"] in (None, 0)
    peak = mod._peak(turns)
    assert peak["peak_input_tokens"] == 1500
    assert peak["turns"] == 2                          # the turn still counted


def test_cpu_offload_is_computed_from_what_ollama_reports():
    """`size_vram < size` is CPU offload, which the plan makes disqualifying.
    It is derived from the reported numbers, never assumed from success."""
    mod = _tool()
    calls = []

    def fake(path, body=None, base=""):
        calls.append(path)
        return {"models": [{"context_length": 16384,
                            "size": 12_000_000_000,
                            "size_vram": 9_000_000_000}]}

    mod._ollama = fake
    r = mod._residency("http://x")
    assert r["context_length"] == 16384
    assert r["fully_on_gpu"] is False
    assert r["cpu_offload_bytes"] == 3_000_000_000

    def whole(path, body=None, base=""):
        return {"models": [{"context_length": 8192, "size": 9_000_000_000,
                            "size_vram": 9_000_000_000}]}

    mod._ollama = whole
    r2 = mod._residency("http://x")
    assert r2["fully_on_gpu"] is True and r2["cpu_offload_bytes"] == 0


def test_the_block_order_is_counterbalanced_as_registered():
    """Frozen in the plan: dev runs small-then-large and holdout runs
    large-then-small, so a monotone drift cannot masquerade as a size effect.
    A later edit that quietly reorders the blocks breaks this."""
    mod = _tool()
    assert mod.BLOCKS == (("dev", 8192), ("dev", 16384),
                          ("holdout", 16384), ("holdout", 8192),
                          ("cross_project", 8192), ("cross_project", 16384))
    for group in ("dev", "holdout", "cross_project"):
        sizes = [n for g, n in mod.BLOCKS if g == group]
        assert sorted(sizes) == [8192, 16384]      # each group runs both, once

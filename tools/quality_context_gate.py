"""AI-CONTEXT-GATE — does raising qwen3:14b's window from 8192 to 16384 help?

Measurement only. It changes no runtime, retrieval, prompt, schema or corpus:
it drives the shipped `run_agent_unit` through the harness's `run_pair` exactly
as production does, and varies ONE thing — `AUDITOR_OLLAMA_NUM_CTX`.

The plan (sample, metrics, ordering, attribution rule, recommendation
conditions, stopping rule) is pre-registered in
docs/quality/AI-CONTEXT-GATE-plan.md and fixed before any run.

The axis this tool exists to settle is not the verdict counts — it is whether
the OLD window was ever near full. A bigger window cannot explain a difference
it was never asked for, so every response's `prompt_eval_count` is read off the
wire and the PEAK real input tokens per case is recorded. `bytes_after` and the
project's 3-bytes-per-token estimator are not evidence for this.

Per-case detail is written ONLY under the gitignored
.quality-local/ai-quality/<run-id>/. The anonymized summary carries literal
counts and denominators, never content.

Usage (one pass, no retries):

    python tools/quality_context_gate.py --model qwen3:14b --run-id ctx-gate

"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from auditor.ai.contract import ERROR_CODES, Provider  # noqa: E402
from auditor.ai.quality_corpus import (  # noqa: E402
    SPLIT_CROSS_PROJECT,
    SPLIT_DEVELOPMENT,
    SPLIT_HOLDOUT,
    cases,
    corpus_digest,
)
from auditor.ai.quality_harness import (  # noqa: E402
    ENGINE_AGENT,
    HARNESS_VERSION,
    anonymized_summary,
    build_plan,
    classify,
    earned_evidence,
    observations,
    run_pair,
)
from auditor.ai.transport import RequestsTransport  # noqa: E402

GROUPS = {"dev": SPLIT_DEVELOPMENT, "holdout": SPLIT_HOLDOUT,
          "cross_project": SPLIT_CROSS_PROJECT}

# Frozen in the plan. Counterbalanced so a monotone drift cannot look like a
# size effect: dev runs small-then-large, holdout large-then-small.
BLOCKS = (("dev", 8192), ("dev", 16384),
          ("holdout", 16384), ("holdout", 8192),
          ("cross_project", 8192), ("cross_project", 16384))

WALL_CLOCK_CAP_S = 90 * 60
CONSECUTIVE_INFRA_ABORT = 3
_INFRA = ("connection_failed", "not_configured", "model_not_found")


class TokenSpy:
    """The project's real transport, wrapped so the run records what went on
    the wire AND what came back. Behaviour is unchanged — it forwards the call
    and reads the response it is already returning.

    `turns` accumulates one entry per model round-trip; `prompt_eval_count` is
    Ollama's count of the tokens it ACTUALLY tokenised for that prompt, which
    is the only honest answer to "was the window full?"."""

    def __init__(self, turns: list[dict[str, Any]],
                 wire: list[dict[str, Any]]) -> None:
        self._inner = RequestsTransport()
        self._turns = turns
        self._wire = wire

    def request(self, method, url, headers, json_body, timeout):
        self._wire.append({
            "url": url,
            "options": (json_body or {}).get("options"),
            "think": (json_body or {}).get("think"),
            "tools": len((json_body or {}).get("tools") or []),
        })
        resp = self._inner.request(method, url, headers, json_body, timeout)
        try:
            data = json.loads(resp.body.decode("utf-8"))
            self._turns.append({
                "input_tokens": int(data.get("prompt_eval_count") or 0),
                "output_tokens": int(data.get("eval_count") or 0),
                "done_reason": data.get("done_reason"),
            })
        except Exception:                                # noqa: BLE001
            # a malformed body is the runtime's problem to report, not this
            # instrument's to hide — but it must not change what is returned
            self._turns.append({"input_tokens": None, "output_tokens": None,
                                "done_reason": None})
        return resp


def _ollama(path: str, body: dict | None = None, base: str = "") -> dict:
    url = base.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if data else "GET",
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def _unload(base: str, model: str) -> None:
    """num_ctx binds at model LOAD time, so the old binding must be gone before
    the new size can take effect."""
    try:
        _ollama("/api/chat", {"model": model, "messages": [], "keep_alive": 0},
                base)
    except Exception:                                    # noqa: BLE001
        pass
    for _ in range(60):
        try:
            if not _ollama("/api/ps", None, base).get("models"):
                return
        except Exception:                                # noqa: BLE001
            return
        time.sleep(0.5)


def _load(base: str, model: str, num_ctx: int) -> str:
    """Load at the requested size with one trivial native call, and RETURN the
    failure rather than swallowing it. A load that cannot fit the model reports
    an out-of-memory error here; recording it is the difference between "the
    binding check failed" and knowing why."""
    try:
        _ollama("/api/chat", {
            "model": model, "messages": [{"role": "user", "content": "ok"}],
            "stream": False, "think": False,
            "options": {"temperature": 0, "num_predict": 1,
                        "num_ctx": num_ctx}}, base)
        return ""
    except Exception as e:                               # noqa: BLE001
        return type(e).__name__ + ": " + str(e)[:300]


def _residency(base: str) -> dict[str, Any]:
    """What Ollama says about the loaded model: the context length it actually
    gave it, and whether the whole thing sits in VRAM. `size_vram < size` is
    CPU offload — a disqualifying condition in the plan, so it is read rather
    than assumed."""
    blank = {"context_length": None, "size_bytes": None,
             "size_vram_bytes": None, "fully_on_gpu": None,
             "cpu_offload_bytes": None}
    try:
        models = _ollama("/api/ps", None, base).get("models", [])
    except Exception as e:                               # noqa: BLE001
        # "the endpoint could not be read" is not the same fact as "no model is
        # loaded", and collapsing them into one all-null dict hides which one
        # happened — which is exactly what made the first attempt opaque.
        return {**blank, "read_error": type(e).__name__ + ": " + str(e)[:200]}
    for m in models:
        size, vram = m.get("size"), m.get("size_vram")
        return {
            "context_length": m.get("context_length"),
            "size_bytes": size, "size_vram_bytes": vram,
            "fully_on_gpu": (None if size is None or vram is None
                             else size == vram),
            "cpu_offload_bytes": (None if size is None or vram is None
                                  else max(0, size - vram)),
            "read_error": "",
        }
    return {**blank, "read_error": "", "no_model_loaded": True}


def _gpu() -> dict[str, Any]:
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total,memory.used",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=20)
        total, used = out.stdout.strip().splitlines()[0].split(",")
        return {"vram_total_mib": int(total), "vram_used_mib": int(used)}
    except Exception:                                    # noqa: BLE001
        return {"vram_total_mib": None, "vram_used_mib": None}


def _peak(turns: list[dict[str, Any]]) -> dict[str, Any]:
    ins = [t["input_tokens"] for t in turns if t.get("input_tokens")]
    outs = [t["output_tokens"] for t in turns if t.get("output_tokens")]
    return {"turns": len(turns),
            "peak_input_tokens": max(ins) if ins else None,
            "total_output_tokens": sum(outs) if outs else 0}


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-CONTEXT-GATE: 8192 vs 16384")
    ap.add_argument("--model", required=True)
    ap.add_argument("--timeout", default="300")
    ap.add_argument("--base-url", default="http://127.0.0.1:11434")
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()

    out_dir = (Path(__file__).resolve().parent.parent
               / ".quality-local" / "ai-quality" / args.run_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    env = {"OLLAMA_HOST": args.base_url,
           "AUDITOR_AI_AGENT_AUDIT": "confirm",
           "AUDITOR_AI_TIMEOUT_SECONDS": str(args.timeout)}

    started = time.time()
    report: dict[str, Any] = {
        "harness_version": HARNESS_VERSION, "model": args.model,
        "engine": ENGINE_AGENT, "concurrency": 1, "runs_per_case_size": 1,
        "retries": 0, "block_order": [list(b) for b in BLOCKS],
        "gpu_before": _gpu(), "blocks": [],
    }
    aborted = ""
    pairs_by_key: dict[str, list[dict[str, Any]]] = {}

    for gname, num_ctx in BLOCKS:
        if aborted:
            break
        split = GROUPS[gname]
        corpus = cases(split)
        plan = build_plan(corpus)

        _unload(args.base_url, args.model)
        load_error = _load(args.base_url, args.model, num_ctx)
        res_before = _residency(args.base_url)
        block: dict[str, Any] = {
            "group": gname, "requested_num_ctx": num_ctx,
            "observed": res_before, "load_error": load_error,
            "gpu_after_load": _gpu(),
            "corpus_digest": corpus_digest(corpus),
            "planned_cases": len(corpus), "cases": [],
        }
        if res_before.get("context_length") != num_ctx:
            # a block that did not get the size it asked for measures nothing
            block["binding_failed"] = (
                "observed context_length does not equal the requested "
                "num_ctx; this block is not a result"
                + (f"; load reported: {load_error}" if load_error else "")
                + (f"; /api/ps reported: {res_before['read_error']}"
                   if res_before.get("read_error") else "")
                + ("; /api/ps reported no model loaded"
                   if res_before.get("no_model_loaded") else ""))
            report["blocks"].append(block)
            aborted = "num_ctx_binding_failed"
            break

        block_env = {**env, "AUDITOR_OLLAMA_NUM_CTX": str(num_ctx)}
        results: list[dict[str, Any]] = []
        wire: list[dict[str, Any]] = []
        consecutive = 0
        for case in corpus:
            if time.time() - started > WALL_CLOCK_CAP_S:
                aborted = "wall_clock_cap"
                break
            turns: list[dict[str, Any]] = []
            pair = run_pair(case, Provider.OLLAMA, args.model,
                            lambda: TokenSpy(turns, wire), env=block_env,
                            engines=(ENGINE_AGENT,))
            r = pair[ENGINE_AGENT]
            r["tokens"] = _peak(turns)
            results.append(r)
            block["cases"].append({"case_id": r["case_id"],
                                   "state": r["state"], **_peak(turns)})
            if r["state"] in _INFRA:
                consecutive += 1
                if consecutive >= CONSECUTIVE_INFRA_ABORT:
                    aborted = "consecutive_infrastructure_errors"
                    break
            else:
                consecutive = 0

        block["completed_cases"] = len(results)
        block["residency_after"] = _residency(args.base_url)
        block["gpu_after_block"] = _gpu()
        if len(results) == len(corpus):
            cl = classify(plan, results, corpus)
            block["classification"] = cl
            block["summary"] = anonymized_summary(cl)
            obs = observations(results, plan)
            block["observations"] = obs
            block["evidence_earned"] = earned_evidence(
                obs["rows"], cross_project=split == SPLIT_CROSS_PROJECT)
        else:
            block["classification_skipped"] = (
                "partial block: the one-to-one contract requires every planned "
                "case, so no verdict and no acceptance row is computed")
        block["wire_sample"] = wire[:2]
        report["blocks"].append(block)
        pairs_by_key[f"{gname}-{num_ctx}"] = results

    report["aborted"] = aborted
    report["wall_seconds"] = int(time.time() - started)
    report["gpu_after"] = _gpu()
    (out_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=True, indent=1), encoding="utf-8")
    for key, results in pairs_by_key.items():
        (out_dir / f"results-{key}.json").write_text(
            json.dumps(results, ensure_ascii=True, indent=1), encoding="utf-8")

    # the committed-safe view: counts, denominators and capacity facts only
    public: dict[str, Any] = {
        "model": report["model"], "engine": ENGINE_AGENT, "concurrency": 1,
        "runs_per_case_size": 1, "retries": 0, "aborted": aborted,
        "block_order": report["block_order"],
        "wall_seconds": report["wall_seconds"], "blocks": []}
    for b in report["blocks"]:
        peaks = [c["peak_input_tokens"] for c in b["cases"]
                 if c.get("peak_input_tokens")]
        pub: dict[str, Any] = {
            "group": b["group"], "requested_num_ctx": b["requested_num_ctx"],
            "observed_context_length": b["observed"].get("context_length"),
            "fully_on_gpu": b["observed"].get("fully_on_gpu"),
            "cpu_offload_bytes": b["observed"].get("cpu_offload_bytes"),
            "vram_used_mib_after_load": b["gpu_after_load"].get("vram_used_mib"),
            "vram_total_mib": b["gpu_after_load"].get("vram_total_mib"),
            "planned_cases": b["planned_cases"],
            "completed_cases": b.get("completed_cases", 0),
            "corpus_digest": b["corpus_digest"],
            # the attribution axis: real tokens, straight off the wire
            "peak_input_tokens_max": max(peaks) if peaks else None,
            "peak_input_tokens_median": (
                sorted(peaks)[len(peaks) // 2] if peaks else None),
            "window_fill_max_pct": (
                round(100 * max(peaks) / b["requested_num_ctx"])
                if peaks else None),
        }
        if "summary" in b:
            pub["summary"] = b["summary"]
        if "evidence_earned" in b and b["group"] == "cross_project":
            pub["acceptance"] = [
                {k: r[k] for k in ("kind", "model_outcome", "guard_downgraded",
                                   "cites_target", "sibling_reached",
                                   "meets_acceptance")}
                for r in b["evidence_earned"]["rows"]]
        pub["errors_seen"] = sorted({c["state"] for c in b["cases"]
                                     if c["state"] in ERROR_CODES})
        public["blocks"].append(pub)
    (out_dir / "public-summary.json").write_text(
        json.dumps(public, ensure_ascii=True, indent=1), encoding="utf-8")

    print(json.dumps(public, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

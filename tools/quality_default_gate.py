"""AI-CONTEXT-DEFAULT-GATE — is 4096 or 8192 the right shipped default?

Measurement only. It changes no runtime, retrieval, prompt, schema or limit,
and it does not edit the default: it drives the shipped `run_audit_unit` and
the experimental `run_agent_unit` through the harness's `run_pair` exactly as
production does, and varies ONE thing — `AUDITOR_OLLAMA_NUM_CTX`.

The plan (sample, engines, sizes, ordering, residency precondition, metrics,
decision rule, stopping rule) is pre-registered in
docs/quality/AI-CONTEXT-DEFAULT-GATE-plan.md and fixed before any run.

Two things this tool insists on, because the question cannot be answered
without them:

* **Residency is a precondition, not an observation.** A block whose model is
  not fully GPU-resident measures the CPU offload, not the window, so it is
  recorded as *no measurement* and never retried.
* **Real prompt tokens, not the byte estimator.** The decision rule turns on
  whether 4096 was ever a binding constraint, and only Ollama's own
  `prompt_eval_count` can answer that.

Per-case detail is written ONLY under the gitignored
.quality-local/ai-quality/<run-id>/. The anonymized summary carries literal
counts and denominators, never content.

Usage (one pass, no retries):

    python tools/quality_default_gate.py --model qwen3:14b --run-id ctxdef

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
    ENGINES,
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

# Frozen in the plan. Counterbalanced: each group runs the two sizes in the
# opposite order to its neighbour, so warm-up and drift cannot look like a
# size effect.
BLOCKS = (("dev", 4096), ("dev", 8192),
          ("holdout", 8192), ("holdout", 4096),
          ("cross_project", 4096), ("cross_project", 8192))

WALL_CLOCK_CAP_S = 90 * 60
CONSECUTIVE_INFRA_ABORT = 3
_INFRA = ("connection_failed", "not_configured", "model_not_found")
LOAD_TIMEOUT_S = 10.0


class TokenSpy:
    """The project's real transport, wrapped to record what came back.

    `prompt_eval_count` is Ollama's count of the tokens it ACTUALLY tokenised,
    which is the only honest answer to "was the window full?". Behaviour is
    unchanged: the response is forwarded untouched.
    """

    def __init__(self, turns: list[dict[str, Any]],
                 wire: list[dict[str, Any]]) -> None:
        self._inner = RequestsTransport()
        self._turns = turns
        self._wire = wire

    def request(self, method, url, headers, json_body, timeout):
        self._wire.append({"url": url,
                           "options": (json_body or {}).get("options"),
                           "think": (json_body or {}).get("think")})
        resp = self._inner.request(method, url, headers, json_body, timeout)
        try:
            data = json.loads(resp.body.decode("utf-8"))
            self._turns.append({
                "input_tokens": int(data.get("prompt_eval_count") or 0),
                "output_tokens": int(data.get("eval_count") or 0),
                "done_reason": data.get("done_reason")})
        except Exception:                                # noqa: BLE001
            self._turns.append({"input_tokens": None, "output_tokens": None,
                                "done_reason": None})
        return resp


def _ollama(path: str, body: dict | None = None, base: str = "") -> dict:
    url = base.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if data else "GET",
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode("utf-8"))


def _unload(base: str, model: str) -> None:
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
    """Load at the requested size, returning the failure instead of hiding it.
    A load that cannot fit reports out-of-memory here."""
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
    blank = {"context_length": None, "size_bytes": None,
             "size_vram_bytes": None, "fully_on_gpu": None,
             "cpu_offload_bytes": None}
    try:
        models = _ollama("/api/ps", None, base).get("models", [])
    except Exception as e:                               # noqa: BLE001
        return {**blank, "read_error": type(e).__name__ + ": " + str(e)[:200]}
    for m in models:
        size, vram = m.get("size"), m.get("size_vram")
        return {"context_length": m.get("context_length"),
                "size_bytes": size, "size_vram_bytes": vram,
                "fully_on_gpu": (None if size is None or vram is None
                                 else size == vram),
                "cpu_offload_bytes": (None if size is None or vram is None
                                      else max(0, size - vram)),
                "read_error": ""}
    return {**blank, "read_error": "", "no_model_loaded": True}


def _gpu() -> dict[str, Any]:
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total,memory.used,memory.free",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=20)
        total, used, free = out.stdout.strip().splitlines()[0].split(",")
        return {"vram_total_mib": int(total), "vram_used_mib": int(used),
                "vram_free_mib": int(free)}
    except Exception:                                    # noqa: BLE001
        return {"vram_total_mib": None, "vram_used_mib": None,
                "vram_free_mib": None}


def residency_verdict(res: dict[str, Any], requested: int) -> str:
    """"" if the block may be measured, else the SAFE reason it may not.

    Pure, so the precondition can be exercised without a GPU. It is the whole
    gate: a block that fails it is recorded as no-measurement and never retried,
    because a partially offloaded model measures the offload, not the window.
    """
    if res.get("context_length") != requested:
        return "observed context_length does not equal the requested num_ctx"
    if res.get("fully_on_gpu") is not True:
        return ("the model is not fully GPU-resident; a partially offloaded "
                "run measures the offload, not the window")
    return ""


def infra_abort_reached(consecutive: int) -> bool:
    """The frozen stopping rule for infrastructure failures."""
    return consecutive >= CONSECUTIVE_INFRA_ABORT


def wall_clock_exceeded(started: float, now: float) -> bool:
    """The frozen wall-clock cap. A run that trips it stops; it never retries."""
    return now - started > WALL_CLOCK_CAP_S


def engine_entry(rows: list[dict[str, Any]], corpus: Any,
                 plan: dict[str, Any], cross_project: bool) -> dict[str, Any]:
    """One engine's entry for a block.

    A PARTIAL block is not classified: the one-to-one contract requires every
    planned case, and a verdict computed over a subset would be a verdict about
    a sample nobody chose.
    """
    entry: dict[str, Any] = {"cases_run": len(rows)}
    if len(rows) != len(corpus):
        entry["classification_skipped"] = (
            "partial block: the one-to-one contract requires every "
            "planned case, so no verdict is computed")
        return entry
    cl = classify(plan, rows, corpus)
    entry["classification"] = cl
    entry["summary"] = anonymized_summary(cl)
    obs = observations(rows, plan)
    entry["observations"] = obs
    entry["evidence_earned"] = earned_evidence(
        obs["rows"], cross_project=cross_project)
    return entry


def _peak(turns: list[dict[str, Any]]) -> dict[str, Any]:
    ins = [t["input_tokens"] for t in turns if t.get("input_tokens")]
    outs = [t["output_tokens"] for t in turns if t.get("output_tokens")]
    return {"turns": len(turns),
            "peak_input_tokens": max(ins) if ins else None,
            "total_output_tokens": sum(outs) if outs else 0}


def build_public_summary(report: dict[str, Any]) -> dict[str, Any]:
    """The committed-safe view, derived from the report and NOTHING else.

    Pure and total: given the raw report it always yields the same summary,
    so the published numbers can be re-derived from the stored run without
    calling a model. It is also the privacy boundary — it names the fields
    that may leave `.quality-local`, so a case id, a path, a prompt, a wire
    record or a model's words cannot ride out by being added upstream.
    """
    # the committed-safe view: counts, denominators and capacity facts only
    public: dict[str, Any] = {
        "model": report["model"], "engines": report["engines"],
        "concurrency": 1, "runs_per_case_engine_size": 1, "retries": 0,
        "aborted": report.get("aborted", ""), "block_order": report["block_order"],
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
            "peak_input_tokens_max": max(peaks) if peaks else None,
            "peak_input_tokens_median": (
                sorted(peaks)[len(peaks) // 2] if peaks else None),
            "window_fill_max_pct": (
                round(100 * max(peaks) / b["requested_num_ctx"])
                if peaks else None),
            "engines": {}}
        if "no_measurement" in b:
            pub["no_measurement"] = b["no_measurement"]
        for engine, e in b.get("engines", {}).items():
            pe: dict[str, Any] = {"cases_run": e["cases_run"]}
            if "summary" in e:
                pe["summary"] = e["summary"]
            if "evidence_earned" in e and b["group"] == "cross_project":
                pe["acceptance"] = [
                    {k: r[k] for k in ("kind", "model_outcome",
                                       "guard_downgraded", "cites_target",
                                       "sibling_reached", "meets_acceptance")}
                    for r in e["evidence_earned"]["rows"]]
            pe["errors_seen"] = sorted(
                {c[engine + "_state"] for c in b["cases"]
                 if c.get(engine + "_state") in ERROR_CODES})
            pub["engines"][engine] = pe
        public["blocks"].append(pub)
    return public


def main() -> int:
    ap = argparse.ArgumentParser(description="4096 vs 8192 as the default")
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
        "engines": list(ENGINES), "concurrency": 1,
        "runs_per_case_engine_size": 1, "retries": 0,
        "block_order": [list(b) for b in BLOCKS],
        "gpu_before": _gpu(), "blocks": []}
    aborted = ""
    results_by_key: dict[str, list[dict[str, Any]]] = {}

    for gname, num_ctx in BLOCKS:
        if aborted:
            break
        split = GROUPS[gname]
        corpus = cases(split)
        plan = build_plan(corpus)

        _unload(args.base_url, args.model)
        load_error = _load(args.base_url, args.model, num_ctx)
        res = _residency(args.base_url)
        block: dict[str, Any] = {
            "group": gname, "requested_num_ctx": num_ctx,
            "observed": res, "load_error": load_error,
            "gpu_after_load": _gpu(),
            "corpus_digest": corpus_digest(corpus),
            "planned_cases": len(corpus), "cases": []}

        # ---- the residency precondition, applied BEFORE any case ---------
        why = residency_verdict(res, num_ctx)
        if why:
            block["no_measurement"] = (
                why
                + (f"; load reported: {load_error}" if load_error else "")
                + (f"; /api/ps reported: {res['read_error']}"
                   if res.get("read_error") else "")
                + ("; /api/ps reported no model loaded"
                   if res.get("no_model_loaded") else ""))
            report["blocks"].append(block)
            aborted = "residency_precondition_failed"
            break

        block_env = {**env, "AUDITOR_OLLAMA_NUM_CTX": str(num_ctx)}
        per_engine: dict[str, list[dict[str, Any]]] = {e: [] for e in ENGINES}
        wire: list[dict[str, Any]] = []
        consecutive = 0
        for case in corpus:
            if wall_clock_exceeded(started, time.time()):
                aborted = "wall_clock_cap"
                break
            turns: list[dict[str, Any]] = []
            pair = run_pair(case, Provider.OLLAMA, args.model,
                            lambda: TokenSpy(turns, wire), env=block_env)
            row: dict[str, Any] = {"case_id": case.case_id, **_peak(turns)}
            infra = False
            for engine in ENGINES:
                r = pair[engine]
                r["tokens"] = _peak(turns)
                per_engine[engine].append(r)
                row[engine + "_state"] = r["state"]
                infra = infra or r["state"] in _INFRA
            block["cases"].append(row)
            consecutive = consecutive + 1 if infra else 0
            if infra_abort_reached(consecutive):
                aborted = "consecutive_infrastructure_errors"
                break

        block["completed_cases"] = len(per_engine[ENGINES[0]])
        block["residency_after"] = _residency(args.base_url)
        block["gpu_after_block"] = _gpu()
        block["engines"] = {}
        for engine in ENGINES:
            rows = per_engine[engine]
            block["engines"][engine] = engine_entry(
                rows, corpus, plan, split == SPLIT_CROSS_PROJECT)
            results_by_key[f"{gname}-{num_ctx}-{engine}"] = rows
        block["wire_sample"] = wire[:2]
        report["blocks"].append(block)

    report["aborted"] = aborted
    report["wall_seconds"] = int(time.time() - started)
    report["gpu_after"] = _gpu()
    (out_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=True, indent=1), encoding="utf-8")
    for key, rows in results_by_key.items():
        (out_dir / f"results-{key}.json").write_text(
            json.dumps(rows, ensure_ascii=True, indent=1), encoding="utf-8")

    public = build_public_summary(report)
    (out_dir / "public-summary.json").write_text(
        json.dumps(public, ensure_ascii=True, indent=1), encoding="utf-8")

    print(json.dumps(public, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""W3-E6 Agent Quality Gate — run BOTH audit engines over the SAME units and
the SAME source snapshot, once each, and record the comparison.

Measurement only. It changes no runtime, retrieval, prompt or schema: it drives
the shipped `build_audit_pack`/`run_audit_unit` and the experimental
`run_agent_unit` exactly as production does, through the harness's `run_pair`.

The plan (sample, metrics, denominators, stopping rule, configuration) is
pre-registered in docs/quality/W3-E6-agent-quality-gate-plan.md and is fixed
before any run. This tool implements that plan and nothing else.

Per-case detail — model outputs, traces, packs, file paths, source text — is
written ONLY under the gitignored .quality-local/ai-quality/<run-id>/. The
anonymized summary carries literal counts and denominators, never content.

Usage (one pass, no retries):

    python tools/quality_agent_gate.py --group all --model qwen3:14b

"""
from __future__ import annotations

import argparse
import json
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
    ENGINE_WINDOW,
    ENGINES,
    HARNESS_VERSION,
    anonymized_summary,
    build_plan,
    classify,
    run_pair,
)
from auditor.ai.transport import RequestsTransport  # noqa: E402

GROUPS = {"dev": SPLIT_DEVELOPMENT, "holdout": SPLIT_HOLDOUT,
          "cross_project": SPLIT_CROSS_PROJECT}

# --- pre-registered stopping rule (plan section 6) --------------------------
WALL_CLOCK_CAP_S = 90 * 60
CONSECUTIVE_INFRA_ABORT = 3
_INFRA_CODES = ("connection_failed", "timeout")


class Spy:
    """The project's real transport, wrapped so the run records what actually
    went on the wire (endpoint + the options block) without changing any
    runtime behaviour."""

    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self._inner = RequestsTransport()
        self._sink = sink

    def request(self, method, url, headers, json_body, timeout):
        self._sink.append({
            "url": url,
            "options": (json_body or {}).get("options"),
            "think": (json_body or {}).get("think"),
            "tools": len((json_body or {}).get("tools") or []),
        })
        return self._inner.request(method, url, headers, json_body, timeout)


def _ollama(path: str, body: dict | None = None, base: str = "") -> dict:
    url = base.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if data else "GET",
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def _bind_num_ctx(base: str, model: str) -> Any:
    """num_ctx binds at model LOAD time, so unload first and report the context
    length Ollama actually gave the reloaded model."""
    try:
        _ollama("/api/chat", {"model": model, "messages": [], "keep_alive": 0},
                base)
    except Exception:                                    # noqa: BLE001
        pass
    for _ in range(60):
        try:
            if not _ollama("/api/ps", None, base).get("models"):
                break
        except Exception:                                # noqa: BLE001
            break
        time.sleep(0.5)
    return None


def _observed_ctx(base: str) -> Any:
    try:
        for m in _ollama("/api/ps", None, base).get("models", []):
            if m.get("context_length"):
                return m["context_length"]
    except Exception:                                    # noqa: BLE001
        pass
    return None


def _split_by_engine(pairs: list[dict[str, Any]], engine: str) -> list[dict]:
    return [p[engine] for p in pairs if engine in p]


def _observations(results: list[dict[str, Any]],
                  plan: dict[str, Any]) -> dict[str, Any]:
    """The non-scoring axes from plan section 4 — reported BESIDE the scoring
    counters, never folded into them."""
    by_id = {c["case_id"]: c for c in plan["cases"]}
    rows = []
    for r in results:
        pc = by_id.get(r["case_id"], {})
        target = pc.get("target")
        planned = pc.get("sent_spans") or {}
        rows.append({
            "case_id": r["case_id"],
            "kind": r["expected"],
            "state": r["state"],
            "outcome": r.get("outcome"),
            # could the FIXED-WINDOW pack contain the target at all? where this
            # is false a window `missed` is a retrieval limit, not a model miss
            "target_in_planned_pack": (
                None if target is None else target[0] in planned),
            "files_sent": r.get("files_sent"),
            "bytes_after": r.get("bytes_after"),
            "latency_ms": r.get("latency_ms"),
            "tool_calls": r.get("tool_calls"),
            "repeated_calls": r.get("repeated_calls"),
            "stop_reason": r.get("stop_reason"),
            "cross_project_reached": r.get("cross_project_reached"),
            "cited_files": sorted({e["file"] for i in r.get("issues", [])
                                   for e in i["evidence"]}),
        })
    return {"rows": rows}


def _earned(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """A cross-project negative that answers correctly WITHOUT reading the
    sibling is right for the wrong reason. The scoring classifier records it as
    `clean`; this records whether the evidence was actually earned."""
    out = []
    for r in rows:
        reached = r.get("cross_project_reached") or []
        out.append({"case_id": r["case_id"], "kind": r["kind"],
                    "outcome": r.get("outcome"),
                    "sibling_reached": bool(reached),
                    "evidence_earned": bool(reached)})
    return {"rows": out}


def main() -> int:
    ap = argparse.ArgumentParser(description="W3-E6 agent quality gate")
    ap.add_argument("--group", default="all",
                    choices=[*GROUPS, "all"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--num-ctx", default="8192")
    ap.add_argument("--timeout", default="300")
    ap.add_argument("--base-url", default="http://127.0.0.1:11434")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", default=".quality-local/ai-quality")
    args = ap.parse_args()

    env = {
        "OLLAMA_HOST": args.base_url,
        "AUDITOR_OLLAMA_NUM_CTX": str(args.num_ctx),
        "AUDITOR_AI_REVIEW_TIMEOUT": str(args.timeout),
        "AUDITOR_AI_AGENT_AUDIT": "confirm",
    }
    groups = list(GROUPS) if args.group == "all" else [args.group]

    out_dir = Path(args.out) / args.run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    _bind_num_ctx(args.base_url, args.model)
    started = time.time()
    report: dict[str, Any] = {
        "harness_version": HARNESS_VERSION,
        "model": args.model, "requested_num_ctx": int(args.num_ctx),
        "concurrency": 1, "runs_per_case_engine": 1, "retries": 0,
        "groups": {},
    }
    aborted = ""

    for gname in groups:
        split = GROUPS[gname]
        corpus = cases(split)
        plan = build_plan(corpus)
        wire: list[dict[str, Any]] = []
        pairs: list[dict[str, Any]] = []
        consecutive_infra = 0

        for case in corpus:
            if time.time() - started > WALL_CLOCK_CAP_S:
                aborted = "wall_clock_cap"
                break
            pair = run_pair(case, Provider.OLLAMA, args.model,
                            lambda: Spy(wire), env=env)
            pairs.append(pair)
            states = {pair[e]["state"] for e in ENGINES if e in pair}
            if states & set(_INFRA_CODES):
                consecutive_infra += 1
                if consecutive_infra >= CONSECUTIVE_INFRA_ABORT:
                    aborted = "infrastructure"
                    break
            else:
                consecutive_infra = 0
            print(f"  {case.case_id:24s} "
                  f"win={pair[ENGINE_WINDOW]['state']:16s} "
                  f"agent={pair[ENGINE_AGENT]['state']}", flush=True)

        g: dict[str, Any] = {
            "split": split, "planned_cases": len(corpus),
            "completed_cases": len(pairs),
            "corpus_digest": corpus_digest(corpus),
            "engines": {},
        }
        for engine in ENGINES:
            res = _split_by_engine(pairs, engine)
            entry: dict[str, Any] = {"cases_run": len(res)}
            if len(res) == len(corpus):
                cl = classify(plan, res, corpus)
                entry["classification"] = cl
                entry["summary"] = anonymized_summary(cl)
            else:
                entry["classification_skipped"] = (
                    "partial run: the one-to-one contract requires every "
                    "planned case, so no verdict is computed")
            obs = _observations(res, plan)
            entry["observations"] = obs
            entry["evidence_earned"] = _earned(obs["rows"])
            g["engines"][engine] = entry
        g["wire_sample"] = wire[:3]
        report["groups"][gname] = g

        (out_dir / f"pairs-{gname}.json").write_text(
            json.dumps(pairs, ensure_ascii=True, indent=1), encoding="utf-8")
        (out_dir / f"plan-{gname}.json").write_text(
            json.dumps(plan, ensure_ascii=True, indent=1), encoding="utf-8")
        if aborted:
            break

    report["observed_context_length"] = _observed_ctx(args.base_url)
    report["aborted"] = aborted
    report["wall_seconds"] = int(time.time() - started)
    (out_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=True, indent=1), encoding="utf-8")

    # the committed-safe view: counts and denominators only
    public: dict[str, Any] = {
        "model": report["model"], "requested_num_ctx": report["requested_num_ctx"],
        "observed_context_length": report["observed_context_length"],
        "concurrency": 1, "runs_per_case_engine": 1, "retries": 0,
        "aborted": aborted, "groups": {}}
    for gname, g in report["groups"].items():
        pub_g: dict[str, Any] = {
            "planned_cases": g["planned_cases"],
            "completed_cases": g["completed_cases"],
            "corpus_digest": g["corpus_digest"], "engines": {}}
        for engine, e in g["engines"].items():
            pub_e: dict[str, Any] = {"cases_run": e["cases_run"]}
            if "summary" in e:
                pub_e["summary"] = e["summary"]
            kinds: dict[str, int] = {}
            for row in e["observations"]["rows"]:
                kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1
            pub_e["denominators_by_kind"] = kinds
            pub_e["errors_seen"] = sorted(
                {r["state"] for r in e["observations"]["rows"]
                 if r["state"] in ERROR_CODES})
            pub_g["engines"][engine] = pub_e
        public["groups"][gname] = pub_g
    (out_dir / "public-summary.json").write_text(
        json.dumps(public, ensure_ascii=True, indent=1), encoding="utf-8")

    print(json.dumps(public, ensure_ascii=True, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

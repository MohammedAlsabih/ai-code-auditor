"""W3-B: single-result evaluator — one AI review result vs one human label.

Links the AI review layer to the W2-B2.8D quality baseline WITHOUT running
the corpus: given the local labels file, one sample_id, and one stored
AIReviewResult, it reports how the AI assessment relates to the human
validity label. Honest abstention is a DISTINCT outcome, never a failure:

- agreement                   both decided, same verdict
- disagreement                both decided, opposite verdicts
- ai_abstained                human decided, AI answered uncertain (valid)
- human_uncertain_ai_decided  AI claims a verdict the human could not — it
                              counts only if the AI cited new valid evidence
                              (nupkg metadata, cross-file context); that
                              judgment stays with the human reviewer
- both_uncertain              honest on both sides

This tool deliberately evaluates ONE result per invocation. Corpus-wide AI
quality rates are out of scope until a full, pre-registered W3-B measurement
round; three smoke cases are not a statistic.
"""
from __future__ import annotations

import json
from pathlib import Path

OUTCOMES = ("agreement", "disagreement", "ai_abstained",
            "human_uncertain_ai_decided", "both_uncertain")

_NOTES = {
    "agreement": "AI matches the human verdict.",
    "disagreement": "AI contradicts the human verdict — inspect before "
                    "trusting either.",
    "ai_abstained": "AI abstained where the human decided. Calibrated "
                    "abstention is valid, not a failure.",
    "human_uncertain_ai_decided": "AI claims a verdict the human review "
                                  "could not settle from source. It counts "
                                  "only if the cited evidence is new and "
                                  "valid — verify the citations.",
    "both_uncertain": "Both honest about the limit of the evidence.",
}


class EvalError(Exception):
    """Bad inputs. Messages never echo file contents."""


def evaluate_single(human_validity: str, ai_assessment: str) -> dict:
    if human_validity not in ("confirmed", "false_positive", "uncertain"):
        raise EvalError("human validity label is not a legal value")
    if ai_assessment not in ("confirmed", "false_positive", "uncertain"):
        raise EvalError("AI assessment is not a legal value")
    if human_validity == "uncertain" and ai_assessment == "uncertain":
        outcome = "both_uncertain"
    elif human_validity == "uncertain":
        outcome = "human_uncertain_ai_decided"
    elif ai_assessment == "uncertain":
        outcome = "ai_abstained"
    elif human_validity == ai_assessment:
        outcome = "agreement"
    else:
        outcome = "disagreement"
    return {"human_validity": human_validity, "ai_assessment": ai_assessment,
            "outcome": outcome, "note": _NOTES[outcome]}


def evaluate_from_files(labels_path: Path, sample_id: str,
                        result_path: Path) -> dict:
    try:
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise EvalError(f"input unreadable: {e.__class__.__name__}") from e
    if not isinstance(labels, dict) or labels.get("schema_version") != 3:
        raise EvalError("labels file must be the schema_version 3 local file")
    row = next((e for e in labels.get("labels", [])
                if isinstance(e, dict) and e.get("sample_id") == sample_id),
               None)
    if row is None:
        raise EvalError("sample_id not found in the labels file")
    if not isinstance(result, dict):
        raise EvalError("result file must be one AIReviewResult object")
    out = evaluate_single(str(row.get("validity")),
                          str(result.get("assessment")))
    return {"sample_id": sample_id, **out,
            "ai_confidence": result.get("confidence"),
            "ai_model": result.get("model"),
            "prompt_version": result.get("prompt_version")}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("usage: quality_eval.py <labels.json> <sample_id> "
              "<ai_result.json>")
        raise SystemExit(2)
    try:
        verdict = evaluate_from_files(Path(sys.argv[1]), sys.argv[2],
                                      Path(sys.argv[3]))
    except EvalError as e:
        print(f"error: {e}")
        raise SystemExit(2) from None
    print(json.dumps(verdict, ensure_ascii=True, indent=1))

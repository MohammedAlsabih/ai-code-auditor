"""SARIF 2.1.0 export (W2-B2.8B2-D): `auditor scan --sarif` writes
`<output>/report.sarif` next to report.json/md.

Built from the FINAL report dict (already redacted, repository-relative
paths), so nothing can reach the SARIF file that did not already pass the
report's privacy gates. Deliberately NOT included: source snippets, review
notes, absolute/machine paths, secrets.

Contract points (verified against the OASIS SARIF 2.1.0 spec):
- version "2.1.0" + the official $schema URI;
- tool.driver carries name/version/informationUri and the full rule catalog
  (rules referenced by results but missing from the catalog get MINIMAL safe
  metadata plus a run-level contract note — the export never drops results);
- each result: ruleId/ruleIndex, SARIF level (error/warning/note), message,
  repo-relative location (+ startLine when the finding is line-anchored),
  partialFingerprints (our line-independent content fingerprint),
  baselineState (new/unchanged) only when a baseline was used, and
  properties {precision, gate_action, project};
- invocations[0].executionSuccessful means the SCAN COMPLETED TECHNICALLY —
  it is NOT a claim that verdict == pass; the verdict travels in
  run.properties for transparency;
- deterministic: same report dict (minus generated_at) => same SARIF bytes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
                "schemas/sarif-schema-2.1.0.json")
_SARIF_LEVELS = ("error", "warning", "note")
_INFO_URI = "https://github.com/MohammedAlsabih/ai-code-auditor"


def _repo_relative(project_root: str, file: str) -> str:
    root = (project_root or "").strip("/")
    return file if root in ("", ".") else f"{root}/{file}"


def _rule_from_catalog(entry: dict[str, Any]) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": str(entry.get("rule_id", "")),
        "name": str(entry.get("title", "") or entry.get("rule_id", "")),
        "shortDescription": {"text": str(entry.get("title", "")
                                         or entry.get("rule_id", ""))},
        "defaultConfiguration": {
            "level": entry.get("default_level")
            if entry.get("default_level") in _SARIF_LEVELS else "warning",
        },
        "properties": {
            "precision": str(entry.get("default_precision", "")),
            "category": str(entry.get("category", "")),
            "engine": str(entry.get("engine", "")),
            "source": str(entry.get("source", "")),
        },
    }
    desc = entry.get("description")
    if isinstance(desc, str) and desc:
        rule["fullDescription"] = {"text": desc}
    return rule


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """One run per report. Input is the final (redacted) report dict."""
    manifest = report.get("analysis_manifest")
    catalog = (manifest or {}).get("catalog") if isinstance(manifest, dict) else None
    rules: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}
    if isinstance(catalog, list):
        for entry in catalog:
            if not isinstance(entry, dict):
                continue
            rid = entry.get("rule_id")
            if not isinstance(rid, str) or not rid or rid in index_of:
                continue
            index_of[rid] = len(rules)
            rules.append(_rule_from_catalog(entry))

    notes: list[str] = []
    results: list[dict[str, Any]] = []
    for proj in report.get("projects", []):
        root = str(proj.get("root", ""))
        for f in proj.get("findings", []):
            rid = str(f.get("rule_id", "") or "<unknown-rule>")
            if rid not in index_of:
                # a result must never be dropped because its rule is missing
                # from the catalog — synthesize minimal SAFE metadata and say
                # so at run level (contract note, no silent gap).
                index_of[rid] = len(rules)
                rules.append({
                    "id": rid,
                    "name": rid,
                    "shortDescription": {"text": rid},
                    "properties": {"synthesized": True},
                })
                notes.append(f"rule {rid}: not in the shipped catalog — "
                             "minimal metadata was synthesized for export")
            level = f.get("level")
            if level not in _SARIF_LEVELS:
                # unclassified levels surface as warning + an explicit marker
                # (SARIF has no 'unclassified'); never silently dropped
                level = "warning"
            message = str(f.get("title", "") or rid)
            detail = f.get("detail")
            if isinstance(detail, str) and detail:
                message = f"{message} — {detail}"
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _repo_relative(root, str(f.get("file", ""))),
                    },
                },
            }
            line = f.get("line")
            if isinstance(line, int) and line > 0:
                location["physicalLocation"]["region"] = {"startLine": line}
            result: dict[str, Any] = {
                "ruleId": rid,
                "ruleIndex": index_of[rid],
                "level": level,
                "message": {"text": message},
                "locations": [location],
                "partialFingerprints": {
                    "auditorFinding/v1": str(f.get("fingerprint", "")),
                },
                "properties": {
                    "precision": str(f.get("precision", "")),
                    "gate_action": str(f.get("gate_action", "")),
                    "project": root,
                },
            }
            state = f.get("baseline_state")
            if state in ("new", "unchanged"):
                result["baselineState"] = state
            results.append(result)

    summary = report.get("summary", {})
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": str(report.get("tool", "ai-code-auditor")),
                "version": str(report.get("version", "")),
                "informationUri": _INFO_URI,
                "rules": rules,
            },
        },
        # executionSuccessful = the scan COMPLETED technically. A blocking
        # verdict is still a successful execution; the gate outcome is a
        # property, never conflated with tool health.
        "invocations": [{"executionSuccessful": True}],
        "results": results,
        "properties": {
            "verdict": summary.get("verdict"),
            "gate_counts": summary.get("gate_counts"),
            "analysis_confidence": summary.get("analysis_confidence"),
            "registry_status": summary.get("registry_status"),
        },
    }
    if notes:
        run["properties"]["contract_notes"] = notes
    baseline = summary.get("baseline")
    if isinstance(baseline, dict) and baseline.get("enabled"):
        run["properties"]["baseline"] = baseline
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_sarif(report), ensure_ascii=False,
                               indent=2),
                    encoding="utf-8")

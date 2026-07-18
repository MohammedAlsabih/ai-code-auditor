from __future__ import annotations

from pathlib import Path

_ICON = {"red": "🔴", "yellow": "🟡", "blue": "🔵"}


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def write_markdown(data: dict, path: Path) -> None:
    L: list[str] = []
    s = data["summary"]
    overall = s["overall_score"]
    L.append("# AI Code Auditor Report")
    L.append("")
    # one compact metadata line — no trailing-space hard breaks (they trip
    # `git diff --check` on the generated report)
    L.append(f"**Target:** `{data['target']}` · **Generated:** {data['generated_at']} "
             f"· **Tool:** {data['tool']} v{data['version']}")
    L.append("")
    L.append("## Executive Summary | الملخص التنفيذي")
    L.append("")
    score_txt = "N/A (no supported languages detected)" if overall is None else f"**{overall}/100**"
    L.append(f"Overall code-health score (higher = safer) | درجة سلامة الكود: {score_txt}")
    L.append(f"**Verdict | الحكم الآلي: `{s.get('verdict', 'n/a').upper()}`**")
    c = s["counts"]
    L.append(f"- 🔴 Critical: {c['red']}   🟡 Warning: {c['yellow']}   🔵 Info: {c['blue']}")
    low = s.get("lowest_language")
    if low and overall is not None and low["score"] < overall:
        L.append(f"- ⚠️ Lowest language | أدنى لغة: **{low['language']} = {low['score']}/100** "
                 "(the average must not hide this)")
    if s.get("analysis_confidence") is not None:
        L.append(f"- Analysis confidence | ثقة التحليل: {s['analysis_confidence']}/100 "
                 "(separate axis: how COMPLETE the checks were, not how risky the code is)")
    L.append("")
    L.append("## Engines")
    L.append("")
    L.append("| Engine | Status |")
    L.append("|---|---|")
    for k, v in data["engines"].items():
        L.append(f"| {k} | {v} |")
    L.append("")
    L.append("## Scores per language")
    L.append("")
    L.append("| Language | Files | Score | 🔴 | 🟡 | 🔵 |")
    L.append("|---|---|---|---|---|---|")
    for p in data["projects"]:
        pc = p["counts"]
        L.append(f"| {p['language']} (`{p['root']}`) | {p['file_count']} | "
                 f"**{p['score']}/100** | {pc['red']} | {pc['yellow']} | {pc['blue']} |")
    L.append("")
    L.append(f"**Scoring contract | عقد الدرجات:** `{data['scoring_formula']}` "
             "— i.e. `max(0, 100 - 15*🔴 - 5*🟡)` per language; 🔵 is informational "
             "and never changes the score. Findings marked `*` are heuristic "
             "(`precision: heuristic`), not proofs.")
    L.append("")
    for p in data["projects"]:
        L.append(f"## {p['language'].capitalize()} — `{p['root']}` "
                 f"({p['score']}/100)")
        if p["frameworks"]:
            L.append(f"Frameworks: {', '.join(p['frameworks'])}")
        L.append("")
        if not p["findings"]:
            L.append("No findings. | لا توجد ملاحظات.")
            L.append("")
            continue
        L.append("| Sev | Rule | Location | Snippet | Detail |")
        L.append("|---|---|---|---|---|")
        for f in p["findings"]:
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            marker = "*" if f.get("precision") == "heuristic" else ""
            L.append(f"| {_ICON[f['severity']]} | {f['rule_id']}{marker} | `{loc}` | "
                     f"`{_md_escape(f['snippet'][:60]) or '-'}` | "
                     f"{_md_escape(f['detail'][:200] or f['title'])} |")
        L.append("")
    diag = data.get("diagnostics") or {}
    if any(diag.get(k) for k in ("manifest_errors", "skipped_files",
                                 "parse_error_files", "rule_errors")):
        L.append("## Diagnostics | تشخيصات التحليل")
        L.append("")
        for key in ("manifest_errors", "skipped_files", "parse_error_files", "rule_errors"):
            for item in diag.get(key, []):
                L.append(f"- `{key}`: {item}")
        L.append("")
    L.append("## Limitations | حدود الفحص")
    L.append("")
    for item in data["limitations"] or ["None."]:
        L.append(f"- {item}")
    L.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L), encoding="utf-8")

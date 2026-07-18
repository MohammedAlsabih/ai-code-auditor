from __future__ import annotations

import lizard

from auditor.core.models import Finding, Severity, SourceFile

THRESHOLD = 10


def complexity_findings(files: list[SourceFile], threshold: int = THRESHOLD,
                        diag=None) -> list[Finding]:
    out: list[Finding] = []
    for sf in files:
        # per-FILE attempt/failure accounting: a swallowed lizard exception must
        # still reach rule_failures, or rule_health stays 1.0 and the verdict can
        # PASS (independent-sweep catch: same class as the project_rules bug)
        if diag is not None:
            diag.rule_attempted += 1
        try:
            analysis = lizard.analyze_file.analyze_source_code(
                str(sf.path), sf.text.decode("utf-8", errors="replace"))
        except Exception as e:
            if diag is not None:
                diag.rule_failures += 1
                diag.rule_errors.append(f"complexity on {sf.rel}: {e.__class__.__name__}")
            continue
        for fn in analysis.function_list:
            if fn.cyclomatic_complexity > threshold:
                out.append(Finding(
                    rule_id="P006", severity=Severity.YELLOW,
                    title="Cyclomatic complexity above 10",
                    file=sf.rel, line=fn.start_line,
                    snippet=fn.name,
                    detail=f"{fn.name} has cyclomatic complexity "
                           f"{fn.cyclomatic_complexity} (> {threshold}).",
                    language=sf.language, engine="auditor"))
    return out

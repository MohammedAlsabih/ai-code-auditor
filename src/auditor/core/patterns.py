from __future__ import annotations

from pathlib import Path

from auditor.core.complexity import complexity_findings
from auditor.core.models import Diagnostics, Finding, SourceFile
from auditor.core.rules_common import common_rules
from auditor.core.treesitter import parse_source


def run_pattern_engine(adapter, project_root: Path, files: list[SourceFile],
                       frameworks: list[str], diag: Diagnostics | None = None) -> list[Finding]:
    rules = [*common_rules(adapter.syntax()), *adapter.language_rules()]
    active = [r for r in rules
              if not r.frameworks or set(r.frameworks) & set(frameworks)]
    findings: list[Finding] = []
    for sf in files:
        try:
            parse_source(sf)
        except Exception as e:
            _note(diag, "parse_error_files", f"{sf.rel}: {e.__class__.__name__}")
            continue
        if sf.tree.root_node.has_error:
            _note(diag, "parse_error_files", f"{sf.rel}: partial parse (syntax errors)")
        for rule in active:
            if diag is not None:
                diag.rule_attempted += 1
            try:
                findings += rule.check(sf)
            except Exception as e:
                if diag is not None:
                    diag.rule_failures += 1
                _note(diag, "rule_errors", f"{rule.id} on {sf.rel}: {e.__class__.__name__}")
    # complexity and project_rules are rule invocations too — count them so a
    # failure lowers confidence and forbids pass (a project_rules exception must
    # hit rule_failures, not rule_errors alone, or confidence stays 100 and the
    # verdict PASSes). complexity does its OWN per-file attempt/failure
    # accounting inside complexity_findings; this wrapper only covers a
    # catastrophic whole-call raise.
    try:
        findings += complexity_findings(files, diag=diag)
    except Exception as e:
        if diag is not None:
            diag.rule_attempted += 1
            diag.rule_failures += 1
        _note(diag, "rule_errors", f"complexity({adapter.name}): {e.__class__.__name__}")
    if diag is not None:
        diag.rule_attempted += 1
    try:
        findings += adapter.project_rules(project_root, frameworks)
    except Exception as e:
        if diag is not None:
            diag.rule_failures += 1
        _note(diag, "rule_errors", f"project_rules({adapter.name}): {e.__class__.__name__}")
    return dedupe(findings)


def _note(diag: Diagnostics | None, field_name: str, message: str) -> None:
    if diag is not None:
        entries = getattr(diag, field_name)
        if message not in entries:
            entries.append(message)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """v2 policy: engines are complementary by design, so a finding is NEVER
    dropped just for sharing a (rule, file, line) with another. Only findings
    that are IDENTICAL in every field collapse — two different secrets on one
    line, or two SQL fragments with distinct detail/snippet, are BOTH kept
    (CP-8: keying on (rule_id,file,line) alone silently ate real findings)."""
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in sorted(findings, key=lambda f: (f.file, f.line, f.rule_id, f.engine,
                                             f.snippet, f.detail)):
        key = (f.rule_id, f.severity, f.title, f.file, f.line, f.snippet,
               f.detail, f.language, f.engine, f.precision)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

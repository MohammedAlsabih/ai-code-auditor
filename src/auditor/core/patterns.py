from __future__ import annotations

from pathlib import Path

from auditor.core.complexity import complexity_findings
from auditor.core.models import Diagnostics, Finding, SourceFile
from auditor.core.rules_common import common_rules
from auditor.core.treesitter import parse_source


def run_pattern_engine(adapter, project_root: Path, files: list[SourceFile],
                       frameworks: list[str], diag: Diagnostics | None = None,
                       ledger=None) -> list[Finding]:
    rules = [*common_rules(adapter.syntax()), *adapter.language_rules()]
    # a framework-gated rule with no matching framework is NOT ELIGIBLE — it
    # never appears in the ledger at all (0 attempts must not read as "ran")
    active = [r for r in rules
              if not r.frameworks or set(r.frameworks) & set(frameworks)]
    findings: list[Finding] = []
    for sf in files:
        # every active rule was SCHEDULED for this file — eligibility is
        # recorded before parsing so blocked inputs still count as eligible
        if ledger is not None:
            for rule in active:
                ledger.eligible(rule.output_ids)
        try:
            parse_source(sf)
            parsed = True
        except Exception as e:
            _note(diag, "parse_error_files", f"{sf.rel}: {e.__class__.__name__}")
            parsed = False
        if parsed:
            partial = sf.tree.root_node.has_error
            if partial:
                _note(diag, "parse_error_files", f"{sf.rel}: partial parse (syntax errors)")
            for rule in active:
                findings += _invoke(rule, sf, diag, ledger,
                                    partial=partial and rule.requires_syntax_tree)
        else:
            # parse FAILED: tree rules are blocked; text-only rules read sf.text
            # and still run (they can emit real findings from a broken file)
            for rule in active:
                if rule.requires_syntax_tree:
                    if ledger is not None:
                        ledger.blocked(rule.output_ids)
                else:
                    findings += _invoke(rule, sf, diag, ledger, partial=False)
    # complexity and project_rules are rule invocations too — count them so a
    # failure lowers confidence and forbids pass (a project_rules exception must
    # hit rule_failures, not rule_errors alone, or confidence stays 100 and the
    # verdict PASSes). complexity does its OWN per-file attempt/failure
    # accounting inside complexity_findings (diag AND ledger); this wrapper
    # only covers a catastrophic whole-call raise and deliberately does NOT
    # touch the ledger — the per-file counters already recorded must not be
    # double-counted by the wrapper.
    try:
        findings += complexity_findings(files, diag=diag, ledger=ledger)
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


def _invoke(rule, sf: SourceFile, diag: Diagnostics | None, ledger,
            partial: bool) -> list[Finding]:
    """Run ONE rule on ONE file with full ledger/diag accounting. Exactly one
    of attempted_ok / attempted_failed fires per invocation, so `attempted`
    stays 1. A raising check, a bad-shaped return, a non-Finding element, or an
    undeclared id are all a SINGLE failed invocation; valid Findings are always
    kept and later rules always continue."""
    if diag is not None:
        diag.rule_attempted += 1
    if ledger is not None and partial:
        ledger.partial_parse(rule.output_ids)
    try:
        out = rule.check(sf)
    except Exception as e:
        if diag is not None:
            diag.rule_failures += 1
        _note(diag, "rule_errors", f"{rule.id} on {sf.rel}: {e.__class__.__name__}")
        if ledger is not None:
            ledger.attempted_failed(rule.output_ids)
        return []
    valid, contract_failed = _validate_output(rule, out, sf, diag, ledger)
    if contract_failed:
        if diag is not None:
            diag.rule_failures += 1
        if ledger is not None:
            ledger.attempted_failed(rule.output_ids)   # attempted=1, failures=1
    elif ledger is not None:
        ledger.attempted_ok(rule.output_ids)           # attempted=1
    return valid


def _validate_output(rule, out, sf: SourceFile, diag: Diagnostics | None,
                     ledger) -> tuple[list[Finding], bool]:
    """Validate a check's return. Returns (valid_findings, contract_failed).
    A single invocation is failed AT MOST ONCE regardless of how many
    violations it contains. Non-Finding elements are dropped; a valid Finding
    with an undeclared id is KEPT (data is never swallowed) but marks the
    invocation failed."""
    declared = rule.output_ids

    def _record(message: str) -> None:
        _note(diag, "rule_errors", f"contract: {message}")
        if ledger is not None:
            ledger.contract_error(message)

    if not isinstance(out, list):
        _record(f"rule {rule.id} returned {type(out).__name__}, expected "
                f"list[Finding], on {sf.rel}")
        return [], True
    valid: list[Finding] = []
    contract_failed = False
    for item in out:
        if not isinstance(item, Finding):
            contract_failed = True
            _record(f"rule {rule.id} returned a non-Finding item "
                    f"({type(item).__name__}) on {sf.rel}")
            continue
        if item.rule_id not in declared:
            contract_failed = True
            _record(f"rule {rule.id} emitted undeclared id {item.rule_id} on "
                    f"{sf.rel} (declared: {', '.join(declared)})")
        valid.append(item)          # kept even when undeclared
    return valid, contract_failed


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

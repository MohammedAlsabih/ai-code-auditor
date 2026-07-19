"""Execution ledger for the scanner's rule invocations (W2-B2.7B).

Factual counters only — the ledger answers: was the rule eligible, how many
inputs it had, how often it was invoked, how many invocations failed, were
blocked (parse failed), ran on a partial tree, were not applicable (no
inputs), or unavailable (had work but the engine could not run). It
deliberately computes NO status, NO verdict, and NO "pass"; execution is never
inferred from the presence of findings (zero findings with attempted>0 still
proves the rule ran).

Coverage so far:
- B1  — builtin FILE rules: P001–P007 (incl. P006 complexity), R001–R007,
  N001–N005, J001–J002, D001–D003 (wired through run_pattern_engine).
- B2-A — the H/registry DECISION paths (H001–H010, H012) inside
  audit_hallucinations, including offline unavailable/not_applicable facts.

Still out of scope (later slices): P008, N006, N001-via-env, external
Semgrep S:* rules, status computation, and writing analysis_manifest.execution.

The ledger is NOT serialized into report.json yet — wiring a half-finished
contract into asdict-driven reports would leak it; report integration is a
later slice.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class RuleExecution:
    eligible_inputs: int = 0        # files this rule was scheduled to run on
    attempted: int = 0              # check() invocations that started (even -> [])
    failures: int = 0               # invocations that raised
    blocked_inputs: int = 0         # eligible files never reaching check (parse failed)
    partial_parse_inputs: int = 0   # check ran on a tree carrying syntax errors
    # facts of NON-execution — a rule that did not run because it did not apply
    # (no inputs) or could not run (e.g. registry needed but offline). These are
    # NEVER recorded once the rule actually ran (see the ledger guards).
    not_applicable_reasons: list[str] = field(default_factory=list)
    unavailable_reasons: list[str] = field(default_factory=list)


@dataclass
class ExecutionLedger:
    """Counters for ONE project context (language + root). Multi-project runs
    keep one ledger per project — see merge_ledgers, which never mixes
    counters across contexts."""
    language: str = ""
    root: str = ""
    rules: dict[str, RuleExecution] = field(default_factory=dict)
    contract_errors: list[str] = field(default_factory=list)

    def _rec(self, rule_id: str) -> RuleExecution:
        return self.rules.setdefault(rule_id, RuleExecution())

    def eligible(self, output_ids: Iterable[str], n: int = 1) -> None:
        for rid in output_ids:
            self._rec(rid).eligible_inputs += n

    def blocked(self, output_ids: Iterable[str]) -> None:
        for rid in output_ids:
            self._rec(rid).blocked_inputs += 1

    def attempted_ok(self, output_ids: Iterable[str]) -> None:
        for rid in output_ids:
            self._rec(rid).attempted += 1

    def attempted_failed(self, output_ids: Iterable[str]) -> None:
        for rid in output_ids:
            rec = self._rec(rid)
            rec.attempted += 1
            rec.failures += 1

    def partial_parse(self, output_ids: Iterable[str]) -> None:
        for rid in output_ids:
            self._rec(rid).partial_parse_inputs += 1

    def not_applicable(self, output_ids: Iterable[str], reason: str) -> None:
        # not_applicable means "no inputs" — rejected if the rule had ANY
        # eligible input OR any attempt. Reasons unique + ordered.
        for rid in output_ids:
            rec = self._rec(rid)
            if rec.eligible_inputs > 0 or rec.attempted > 0:
                continue
            if reason not in rec.not_applicable_reasons:
                rec.not_applicable_reasons.append(reason)

    def unavailable(self, output_ids: Iterable[str], reason: str) -> None:
        # unavailable means "had work to do but the engine could not run" —
        # rejected ONLY when the rule actually attempted. eligible>0 with
        # attempted==0 (e.g. 5 files ready but the external engine is not
        # installed) is exactly when an unavailable reason IS valid. blocked
        # stays an independent fact and never becomes unavailable on its own.
        for rid in output_ids:
            rec = self._rec(rid)
            if rec.attempted > 0:
                continue
            if reason not in rec.unavailable_reasons:
                rec.unavailable_reasons.append(reason)

    def contract_error(self, message: str) -> None:
        if message not in self.contract_errors:
            self.contract_errors.append(message)


def merge_ledgers(ledgers: Iterable[ExecutionLedger]) -> list[ExecutionLedger]:
    """Combining project ledgers PRESERVES context: one entry per project,
    counters never summed across languages/roots. (A flat sum would let a
    fully-blocked project hide behind a healthy one.)"""
    return list(ledgers)

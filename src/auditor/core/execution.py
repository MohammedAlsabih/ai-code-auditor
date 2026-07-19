"""Execution ledger for BUILTIN FILE RULES (W2-B2.7B1).

Factual counters only — the ledger answers: was the rule eligible, how many
files were its inputs, how often was it invoked, how many invocations failed
or were blocked by parsing. It deliberately computes NO status, NO verdict,
and NO "pass"; execution is never inferred from the presence of findings
(zero findings with attempted>0 still proves the rule ran).

Scope in B1: P001–P007 (incl. complexity), R001–R007, N001–N005, J001–J002,
D001–D003. Out of scope: H*, P008, N006 and external S:* rules.

Deliberately INDEPENDENT of Diagnostics and NOT serialized into report.json
yet — wiring a half-finished contract into asdict-driven reports would leak
it; report integration is a later slice.
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

    def contract_error(self, message: str) -> None:
        if message not in self.contract_errors:
            self.contract_errors.append(message)


def merge_ledgers(ledgers: Iterable[ExecutionLedger]) -> list[ExecutionLedger]:
    """Combining project ledgers PRESERVES context: one entry per project,
    counters never summed across languages/roots. (A flat sum would let a
    fully-blocked project hide behind a healthy one.)"""
    return list(ledgers)

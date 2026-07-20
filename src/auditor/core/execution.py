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
- B2-B — the special builtin PROJECT passes: P008 (stdlib drift vs
  requires-python), the Next module-graph group (N002/N004/N005/N006, with
  N003 supersession), and N001 via .env* files (via record_project_pass).
- B2-C — external Semgrep/OpenGrep S:* rules (record_semgrep_execution in
  semgrep_runner.py): per-project, per-descriptor facts driven by the
  STRUCTURED SemgrepRun evidence, never by parsing the human status text and
  never inferred from findings. S:* attempts are NOT added to
  Diagnostics.rule_attempted/rule_failures — those counters belong to the
  builtin rules and semgrep already carries its own confidence factor.

- B2-D — status derivation (derive_execution_status: a PURE function of one
  RuleExecution's counters/reasons, never of findings) and serialization
  (execution_manifest -> analysis_manifest.execution, explicit allowlist).
  An execution status describes whether and how a rule RAN — never code
  safety: a rule that ran and returned zero findings is "executed", not
  "passed"; pass/clean/safe are not statuses.

Still out of scope: the Rule Coverage UI.

Since B2-D the ledgers ARE serialized: execution_manifest() emits
analysis_manifest.execution (its own schema_version) through an explicit
field allowlist — repo-relative roots only, legal reason strings only, and
derive_execution_status() computed per record at serialization time.
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
    # facts about HOW an attempted run went (require attempted>0), and the
    # user's own choice to disable an engine (mutually exclusive with
    # unavailable — a deliberate skip is not an inability):
    partial_reasons: list[str] = field(default_factory=list)
    failure_reasons: list[str] = field(default_factory=list)
    skipped_reasons: list[str] = field(default_factory=list)


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

    def blocked(self, output_ids: Iterable[str], n: int = 1) -> None:
        for rid in output_ids:
            self._rec(rid).blocked_inputs += n

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
        # A user-DISABLED engine (skipped) is not an inability: never both.
        for rid in output_ids:
            rec = self._rec(rid)
            if rec.attempted > 0 or rec.skipped_reasons:
                continue
            if reason not in rec.unavailable_reasons:
                rec.unavailable_reasons.append(reason)

    def skipped(self, output_ids: Iterable[str], reason: str) -> None:
        # skipped = the USER disabled the engine (e.g. --no-semgrep): work
        # existed, the engine was never asked to run. Rejected after any
        # attempt, and never alongside an unavailable fact (a deliberate skip
        # is not an inability).
        for rid in output_ids:
            rec = self._rec(rid)
            if rec.attempted > 0 or rec.unavailable_reasons:
                continue
            if reason not in rec.skipped_reasons:
                rec.skipped_reasons.append(reason)

    def partial_reason(self, output_ids: Iterable[str], reason: str) -> None:
        # partial describes HOW an attempted run went — meaningless (and
        # rejected) without an attempt.
        for rid in output_ids:
            rec = self._rec(rid)
            if rec.attempted == 0:
                continue
            if reason not in rec.partial_reasons:
                rec.partial_reasons.append(reason)

    def failure_reason(self, output_ids: Iterable[str], reason: str) -> None:
        # a failure reason requires a recorded failure (attempted_failed first)
        for rid in output_ids:
            rec = self._rec(rid)
            if rec.failures == 0:
                continue
            if reason not in rec.failure_reasons:
                rec.failure_reasons.append(reason)

    def contract_error(self, message: str) -> None:
        if message not in self.contract_errors:
            self.contract_errors.append(message)


def record_project_pass(ledger, diag, group: Iterable[str], findings,
                        *, failed: bool = False, partial: bool = False) -> list:
    """Account ONE project-level pass against its WHOLE output group and return
    the KEPT findings. Core-neutral: `group` is plain data, no rule-id or
    language branching. eligible + attempted increment once per group id;
    Diagnostics syncs ONCE (rule_attempted += 1, rule_failures += 1 only on
    failure). `partial` marks partial_parse once for the group.

    Output hardening — the SAME contract as the file-rule and H paths:
    findings must be list[Finding]. None or any non-list is one contract
    failure returning [] (never a crash); a non-Finding element is DROPPED;
    a valid Finding with an id outside the group is KEPT (data is never
    swallowed). However many violations one invocation contains — plus an
    explicit `failed` — it is failed AT MOST ONCE (attempted stays 1) and
    the next invocation always continues."""
    from auditor.core.models import Finding
    group = tuple(group)
    if ledger is not None:
        ledger.eligible(group)
        if partial:
            ledger.partial_parse(group)
    if diag is not None:
        diag.rule_attempted += 1
    contract_failed = False

    def _record(msg: str) -> None:
        nonlocal contract_failed
        contract_failed = True
        if ledger is not None:
            ledger.contract_error(msg)
        if diag is not None and hasattr(diag, "rule_errors") \
                and f"contract: {msg}" not in diag.rule_errors:
            diag.rule_errors.append(f"contract: {msg}")

    if not isinstance(findings, list):
        _record(f"project pass returned {type(findings).__name__}, expected "
                f"list[Finding] (group {group})")
        findings = []
    kept = []
    for f in findings:
        if not isinstance(f, Finding):
            _record(f"project pass returned a non-Finding item "
                    f"({type(f).__name__}) in group {group}")
            continue
        if f.rule_id not in group:
            _record(f"project pass emitted id {f.rule_id} outside group {group}")
        kept.append(f)                     # valid Finding: kept even undeclared
    is_fail = failed or contract_failed
    if ledger is not None:
        if is_fail:
            ledger.attempted_failed(group)
        else:
            ledger.attempted_ok(group)
    if diag is not None and is_fail:
        diag.rule_failures += 1
    return kept


EXECUTION_SCHEMA_VERSION = 1
EXECUTION_STATUSES = ("executed", "partial", "failed", "blocked", "unavailable",
                      "skipped", "not_applicable", "not_recorded", "inconsistent")
_COUNTER_FIELDS = ("eligible_inputs", "attempted", "failures", "blocked_inputs",
                   "partial_parse_inputs")
_REASON_FIELDS = ("not_applicable_reasons", "unavailable_reasons",
                  "partial_reasons", "failure_reasons", "skipped_reasons")


def derive_execution_status(record: RuleExecution) -> str:
    """PURE derivation of an execution status from ONE record's counters and
    reasons. Describes whether and how the rule RAN — never code safety, and
    findings play no part in the decision (executed+0 findings is still just
    "executed"). Contradictory facts are reported as "inconsistent" — the data
    is never repaired or silently dropped."""
    counters = [getattr(record, f) for f in _COUNTER_FIELDS]
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 0
           for v in counters):
        return "inconsistent"
    for f in _REASON_FIELDS:
        if not _valid_reasons(getattr(record, f)):
            return "inconsistent"
    if record.failures > record.attempted:
        return "inconsistent"
    if record.blocked_inputs > record.eligible_inputs:
        return "inconsistent"
    if record.partial_parse_inputs > record.attempted:
        return "inconsistent"
    if record.failure_reasons and record.failures == 0:
        return "inconsistent"
    if record.partial_reasons and record.attempted == 0:
        return "inconsistent"
    if record.attempted > 0 and (record.unavailable_reasons
                                 or record.skipped_reasons
                                 or record.not_applicable_reasons):
        return "inconsistent"
    # the three NON-execution explanations are mutually exclusive categories:
    # ANY two (or all three) together are contradictory facts. blocked_inputs
    # stays an independent fact — it never conflicts with them by itself.
    categories = sum(1 for reasons in (record.not_applicable_reasons,
                                       record.unavailable_reasons,
                                       record.skipped_reasons) if reasons)
    if categories > 1:
        return "inconsistent"
    if record.not_applicable_reasons and (record.eligible_inputs > 0
                                          or record.blocked_inputs > 0):
        return "inconsistent"
    if record.attempted > 0:
        if record.failures == record.attempted:
            return "failed"
        if record.failures or record.blocked_inputs \
                or record.partial_parse_inputs or record.partial_reasons:
            return "partial"
        return "executed"
    if record.skipped_reasons:
        return "skipped"
    if record.unavailable_reasons:
        return "unavailable"
    if record.not_applicable_reasons:
        return "not_applicable"
    if record.blocked_inputs > 0:
        return "blocked"
    return "not_recorded"    # eligible with no attempt and no explanation,
    #                          or no facts at all — both are unrecorded gaps


def _encodable(s: str) -> bool:
    """A lone surrogate cannot be written as UTF-8 JSON — such a string is
    not serializable evidence."""
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _valid_reasons(value) -> bool:
    """A reasons field is a list of NON-EMPTY, UTF-8-encodable strings with
    no duplicates — anything else is a contradictory record, never repaired
    in derive."""
    if not isinstance(value, list):
        return False
    if any(not isinstance(x, str) or not x.strip() or not _encodable(x)
           for x in value):
        return False
    return len(set(value)) == len(value)


def _safe_root(root) -> tuple[str, bool]:
    """Repository-relative POSIX roots only: '.' or sane '/'-separated
    components (no drive/colon, no backslash, no leading '/', no '..' or
    empty parts). Anything else is replaced by a fixed placeholder — the raw
    value never reaches the JSON."""
    if root == ".":
        return ".", True
    if not isinstance(root, str) or not root or not _encodable(root):
        return "<invalid-project-root>", False
    if "\\" in root or ":" in root or root.startswith("/"):
        return "<invalid-project-root>", False
    parts = root.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "<invalid-project-root>", False
    return root, True


def _clean_reasons(value) -> tuple[list[str], bool]:
    """(serializable_reasons, was_valid): legal strings only, deterministic
    dedupe preserving first occurrence. Non-list input or non-string/empty
    elements are NEVER printed — they are dropped from the JSON and flagged
    by the caller via a value-free contract error."""
    if not isinstance(value, list):
        return [], False
    ok = True
    out: list[str] = []
    for x in value:
        if isinstance(x, str) and x.strip() and _encodable(x):
            if x not in out:
                out.append(x)
            else:
                ok = False                      # duplicate: deduped + flagged
        else:
            ok = False      # junk / unencodable (lone surrogate): dropped + flagged
    return out, ok


def execution_manifest(ledgers: Iterable[ExecutionLedger],
                       catalog_ids: Iterable[str]) -> dict:
    """analysis_manifest.execution (schema v1): the per-project ledgers as
    JSON-ready facts. EXPLICIT allowlist (never a bare asdict), deterministic
    order (projects by root then language; rule ids sorted), repo-relative
    roots only, and no findings/snippets/source. Every ledger record appears —
    even inconsistent ones; a recorded id absent from the catalog is kept with
    status=inconsistent plus a visible contract error, never dropped."""
    known = set(catalog_ids)
    projects = []
    for led in sorted(ledgers, key=lambda led: (str(led.root), led.language)):
        contract_errors = list(led.contract_errors)
        root, root_ok = _safe_root(led.root)
        if not root_ok:
            # project-level metadata fault: the placeholder replaces the raw
            # value and the rule statuses are NOT punished for it
            msg = "execution project root is not repository-relative"
            if msg not in contract_errors:
                contract_errors.append(msg)
        rules = {}
        for rid in sorted(led.rules):
            rec = led.rules[rid]
            status = derive_execution_status(rec)
            if rid not in known:
                status = "inconsistent"
                msg = (f"rule {rid} recorded in the execution ledger but "
                       "absent from the rule catalog")
                if msg not in contract_errors:
                    contract_errors.append(msg)
            entry: dict = {"status": status}
            for f in _COUNTER_FIELDS:
                entry[f] = getattr(rec, f)
            for f in _REASON_FIELDS:
                cleaned, ok = _clean_reasons(getattr(rec, f))
                entry[f] = cleaned          # legal strings only, deduped
                if not ok:
                    # names the rule and the FIELD only — the offending value
                    # (which may carry a path or a secret) is never echoed
                    msg = f"rule {rid}: invalid entries in {f}"
                    if msg not in contract_errors:
                        contract_errors.append(msg)
            rules[rid] = entry
        projects.append({"language": led.language, "root": root,
                         "rules": rules, "contract_errors": contract_errors})
    return {"schema_version": EXECUTION_SCHEMA_VERSION, "projects": projects}


def merge_ledgers(ledgers: Iterable[ExecutionLedger]) -> list[ExecutionLedger]:
    """Combining project ledgers PRESERVES context: one entry per project,
    counters never summed across languages/roots. (A flat sum would let a
    fully-blocked project hide behind a healthy one.)"""
    return list(ledgers)

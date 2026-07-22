"""Gate policy (W2-B2.8B2-A): what a finding DOES to the verdict.

The verdict consumes per-finding `gate_action`, never the level or the legacy
color alone. Default contract:

    level    precision        gate_action
    error    exact            block
    error    heuristic        review        (promotable to block by policy)
    warning  exact/heuristic  review
    note     exact/heuristic  informational

A heuristic error is a strong signal, NOT a proof — by default it demands a
human review instead of blocking the gate. A project may promote heuristic
errors to `block` via `.auditor.toml` schema v2 (`[policy]
heuristic_errors = "block"`), and may override a rule's effective level via
`[rule_levels]`. An override changes the finding's EFFECTIVE level (and
therefore its gate_action and its code_health bucket — that is the intended
policy) while keeping the original as `default_level` with
`level_source = "project_policy"` for transparency. `finding.level` is never
silently rewritten because of precision alone.

code_health stays a severity-ordering metric; it is not a safety claim and
takes no part in gating.
"""
from __future__ import annotations

from dataclasses import dataclass, field

GATE_ACTIONS = ("block", "review", "informational")

# note: "block" here is the only policy-selectable promotion; anything else
# in config is rejected at parse time (config.py), never normalized silently.
HEURISTIC_ERROR_ACTIONS = ("review", "block")

POLICY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class GatePolicy:
    """The resolved gate policy for one scan. Defaults are the tool contract;
    `source` records where the values came from (display-safe: 'default' or
    the config display name, never a machine path)."""
    heuristic_errors: str = "review"          # "review" | "block"
    rule_levels: dict[str, str] = field(default_factory=dict)  # rule_id -> level
    source: str = "default"

    def __post_init__(self) -> None:
        if self.heuristic_errors not in HEURISTIC_ERROR_ACTIONS:
            raise ValueError("heuristic_errors must be 'review' or 'block'")
        for lvl in self.rule_levels.values():
            if lvl not in ("error", "warning", "note"):
                raise ValueError("rule level override must be error/warning/note")


def gate_action(level: str, precision: str, policy: GatePolicy) -> str:
    """The gate contribution of ONE finding, from its EFFECTIVE level and its
    precision. Unclassified levels gate as `review` — an unreadable severity
    must never slip through as informational."""
    if level == "error":
        if precision == "heuristic":
            return policy.heuristic_errors
        return "block"
    if level == "warning":
        return "review"
    if level == "note":
        return "informational"
    return "review"


def effective_level(rule_id: str, base_level: str,
                    policy: GatePolicy) -> tuple[str, str | None]:
    """(effective level, original level when overridden else None).

    A `[rule_levels]` override applies to every finding of that rule; the
    original level is preserved for the report's `default_level` field."""
    override = policy.rule_levels.get(rule_id)
    if override is None or override == base_level:
        return base_level, None
    return override, base_level


def policy_manifest(policy: GatePolicy) -> dict:
    """The safe serialization for analysis_manifest.policy. Rule ids here were
    validated against the tool catalog before the scan ran (cli), so echoing
    them is safe; free-form config values never reach this dict."""
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "heuristic_errors": policy.heuristic_errors,
        "rule_level_overrides": {k: policy.rule_levels[k]
                                 for k in sorted(policy.rule_levels)},
        "source": policy.source,
        "note": ("gate_action drives the verdict: exact errors block; "
                 "heuristic errors do NOT block by default (review); "
                 "notes are informational."),
    }

"""SARIF-compatible result levels — the ONE normalization source tool-wide.

Contract (verified against the official OASIS SARIF 2.1.0 artifacts, result
`level` property §3.27.10; JSON schema enum ["none", "note", "warning",
"error"], default "warning"): our findings use the three active levels
    error / warning / note
and the legacy color severities map onto them as
    red -> error, yellow -> warning, blue -> note.
This makes finding LEVELS SARIF-compatible; report.json itself is NOT a SARIF
log file and we never claim it is.
"""
from __future__ import annotations

from typing import Any

CANONICAL_LEVELS = ("error", "warning", "note")

LEGACY_SEVERITY_TO_LEVEL = {"red": "error", "yellow": "warning", "blue": "note"}


def normalize_level(level: Any, severity: Any) -> str | None:
    """Resolve a finding's semantic level:
    - the legacy-severity fallback applies ONLY when `level` is ABSENT (None);
    - a VALID present `level` (error/warning/note) wins, even over a
      conflicting legacy severity;
    - a PRESENT but invalid `level` ("none", "", "bogus", dict, list, ...)
      returns None — the finding is unclassified; it never falls back to
      severity and is never silently promoted."""
    if level is None:
        if isinstance(severity, str) and severity in LEGACY_SEVERITY_TO_LEVEL:
            return LEGACY_SEVERITY_TO_LEVEL[severity]
        return None
    if isinstance(level, str) and level in CANONICAL_LEVELS:
        return level
    return None

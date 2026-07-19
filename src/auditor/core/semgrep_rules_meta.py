"""Descriptors for the semgrep/opengrep YAML rules the tool SHIPS.

Owner adjacency: the YAML file itself is the rule implementation; this module
sits beside the semgrep integration and derives descriptors FROM that shipped
file — never from a hand-copied list that could drift. Shipping a YAML rule is
a CAPABILITY statement only; whether a semgrep binary actually ran is a
separate execution record (not part of this catalog).

Parsing is STRUCTURED (yaml.safe_load) and FAIL-CLOSED: an unsupported
language, unknown severity, missing message/languages/metadata-precision, or a
malformed document raises SemgrepRulesError — the catalog build fails loudly
rather than guessing values or claiming all languages for a rule we cannot
interpret. languages=() keeps exactly ONE meaning tool-wide (core-neutral
fill-in); a shipped semgrep descriptor is never emitted with empty languages.

Canonical identity: the runner emits findings as "S:<check_id>", so the
descriptor rule_id carries the SAME "S:" prefix — finding ids match catalog
ids literally, with no normalization anywhere.
"""
from __future__ import annotations

from importlib import resources

import yaml

from auditor.core.catalog import RuleDescriptor

_SEV_TO_LEVEL = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}
# semgrep language names -> our adapter language names (javascript files are
# analyzed by the typescript adapter in this tool)
_LANG_MAP = {"python": "python", "typescript": "typescript",
             "javascript": "typescript", "java": "java", "csharp": "csharp"}
_PRECISIONS = ("exact", "heuristic")


class SemgrepRulesError(Exception):
    """The shipped YAML cannot be interpreted — capability must not be
    guessed. Messages are file-local (rule ids / field names), no paths."""


def _shipped_yaml_text() -> str:
    return (resources.files("auditor") / "semgrep_rules" /
            "auditor-extra.yml").read_text(encoding="utf-8")


def shipped_semgrep_descriptors() -> list[RuleDescriptor]:
    try:
        data = yaml.safe_load(_shipped_yaml_text())
    except yaml.YAMLError as e:
        raise SemgrepRulesError(f"shipped semgrep YAML is not parseable: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise SemgrepRulesError("shipped semgrep YAML must be a mapping with a "
                                "'rules' list")
    out: list[RuleDescriptor] = []
    seen_ids: set[str] = set()
    for i, rule in enumerate(data["rules"]):
        if not isinstance(rule, dict):
            raise SemgrepRulesError(f"rules[{i}] is not a mapping")
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid.strip():
            raise SemgrepRulesError(f"rules[{i}] has no valid id")
        if rid in seen_ids:
            # a duplicated id inside ONE shipped file is an authoring error —
            # rejected here, never silently merged downstream
            raise SemgrepRulesError(f"rule {rid}: duplicate id in shipped YAML")
        seen_ids.add(rid)
        message = rule.get("message")
        if not isinstance(message, str) or not message.strip():
            raise SemgrepRulesError(f"rule {rid}: missing message")
        # type checks BEFORE any membership/dict lookup: YAML happily yields
        # lists/dicts where strings were meant, and those are unhashable
        severity = rule.get("severity")
        if not isinstance(severity, str) or severity not in _SEV_TO_LEVEL:
            raise SemgrepRulesError(
                f"rule {rid}: unsupported severity {severity!r} "
                f"(expected one of {', '.join(_SEV_TO_LEVEL)})")
        langs_raw = rule.get("languages")
        if not isinstance(langs_raw, list) or not langs_raw:
            raise SemgrepRulesError(f"rule {rid}: missing languages")
        non_str = [x for x in langs_raw if not isinstance(x, str)]
        if non_str:
            raise SemgrepRulesError(
                f"rule {rid}: languages entries must be strings, got "
                f"{non_str!r}")
        unmapped = [x for x in langs_raw if x not in _LANG_MAP]
        if unmapped:
            raise SemgrepRulesError(
                f"rule {rid}: unsupported language(s) {unmapped!r} — refusing "
                "to guess or claim all languages")
        langs = tuple(sorted({_LANG_MAP[x] for x in langs_raw}))
        meta = rule.get("metadata")
        precision = meta.get("auditor-precision") if isinstance(meta, dict) else None
        if precision not in _PRECISIONS:
            raise SemgrepRulesError(
                f"rule {rid}: metadata.auditor-precision must be one of "
                f"{_PRECISIONS} — the YAML metadata is the single source of "
                "truth for precision")
        out.append(RuleDescriptor(
            rule_id=f"S:{rid.strip()}",     # canonical: matches runner output literally
            title=message.strip(),
            description=message.strip(),
            category="semgrep",
            default_level=_SEV_TO_LEVEL[severity],
            default_precision=precision,
            engine="semgrep",
            languages=langs,
            scope="external",
            source="semgrep-or-opengrep",
        ))
    return out

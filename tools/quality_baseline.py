"""W2-B2.8D quality-baseline tool (deterministic, offline, no AI).

Loads a LOCAL labels file (per-finding, multi-axis classifications that live
in an ignored directory — they carry file paths, snippets, fingerprints and
free-text evidence and must never be committed), validates its schema,
verifies the labels bind ONE-TO-ONE to the deterministic sample, and computes
an ANONYMIZED aggregate that IS safe to commit: per (repo alias, rule) counts
across five independent axes, plus derived rates with explicit numerator/
denominator and an evidence class per rule.

schema_version 3: every label is bound to exactly one sampled finding via a
deterministic `sample_id` (see tools/quality_sample.py) and carries the full
identity (alias, rule, project, file, line, fingerprint, review_id when
available) plus a non-empty free-text `evidence`. Identity and evidence stay
LOCAL — the public summary contains only aliases, rule ids, integer counts,
and fixed enum strings.

The five axes are kept SEPARATE by contract — detection validity, level
appropriateness, gate appropriateness, and actionability are distinct
questions and are never collapsed into one number:

- validity:          confirmed | false_positive | uncertain
- level_assessment:  correct | too_high | too_low | uncertain
- gate_assessment:   correct | too_strict | too_lenient | uncertain
- actionability:     actionable | needs_context | non_actionable
- reason_code:       a short value from a fixed enum (aggregated as counts)

Privacy is enforced structurally: `assert_anonymized` walks the summary with
a strict ALLOWLIST of keys and legal values — any extra key, any string that
is not a legal enum value / alias / rule id / fixed text, or any non-integer
count fails the gate. Because arbitrary strings are rejected outright, real
repository names, filesystem paths (any drive letter, UNC, POSIX), snippets,
fingerprints, review ids, evidence text, and secrets are all rejected
regardless of case. Error messages never echo the offending value. This
module performs NO network and NO model calls.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from quality_sample import sample_id as _compute_sample_id

VALIDITY = ("confirmed", "false_positive", "uncertain")
LEVEL_ASSESSMENT = ("correct", "too_high", "too_low", "uncertain")
GATE_ASSESSMENT = ("correct", "too_strict", "too_lenient", "uncertain")
ACTIONABILITY = ("actionable", "needs_context", "non_actionable")
REASON_CODES = (
    "true_defect", "intentional_but_flagged", "test_or_fixture_credential",
    "local_dev_credential", "parameterized_or_safe", "sanitized_or_guarded",
    "public_by_design", "package_id_ne_namespace", "metadata_gap",
    "complexity_over_threshold", "index_key_low_impact", "other",
)
EVIDENCE_CLASSES = ("insufficient_evidence", "needs_hardening",
                    "provisionally_credible")
_ALIAS_RE = re.compile(r"^repo-[a-z]$")
_RULE_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

METHOD_TEXT = "manual source review; deterministic stratified sample; no AI"
NOTE_TEXT = ("Rates are observed on this deterministic stratified sample "
             "only; they are NOT a probabilistic estimate of product-wide "
             "precision and carry no confidence interval.")
_SAMPLING = ("all", "stratified_cap")


class QualityError(Exception):
    """Malformed labels file or a privacy violation. Messages are safe to
    print — they never echo file contents, paths, or offending values."""


@dataclass(frozen=True)
class RuleStat:
    alias: str
    rule: str
    population: int
    reviewed: int
    validity: dict            # label -> count
    level_assessment: dict
    gate_assessment: dict
    actionability: dict
    reason_codes: dict = field(default_factory=dict)

    @property
    def confirmed(self) -> int:
        return self.validity.get("confirmed", 0)

    @property
    def false_positive(self) -> int:
        return self.validity.get("false_positive", 0)

    @property
    def uncertain(self) -> int:
        return self.validity.get("uncertain", 0)

    @property
    def decided(self) -> int:
        return self.confirmed + self.false_positive

    def as_row(self) -> dict:
        return {
            "repo": self.alias, "rule": self.rule,
            "population": self.population, "reviewed": self.reviewed,
            "validity": {k: self.validity.get(k, 0) for k in VALIDITY},
            "level_assessment": {k: self.level_assessment.get(k, 0)
                                 for k in LEVEL_ASSESSMENT},
            "gate_assessment": {k: self.gate_assessment.get(k, 0)
                                for k in GATE_ASSESSMENT},
            "actionability": {k: self.actionability.get(k, 0)
                              for k in ACTIONABILITY},
            "reason_code_counts": {k: v for k, v in
                                   sorted(self.reason_codes.items()) if v},
            "sampling": "all" if self.reviewed >= self.population else "stratified_cap",
            "evidence_class": evidence_class(self),
        }


@dataclass
class Aggregate:
    rules: list[RuleStat] = field(default_factory=list)
    corpus: dict = field(default_factory=dict)   # alias -> findings count

    def totals(self) -> dict:
        c = sum(s.confirmed for s in self.rules)
        fp = sum(s.false_positive for s in self.rules)
        u = sum(s.uncertain for s in self.rules)
        reviewed = sum(s.reviewed for s in self.rules)
        decided = c + fp
        lvl = _axis_totals(self.rules, "level_assessment", LEVEL_ASSESSMENT)
        gate = _axis_totals(self.rules, "gate_assessment", GATE_ASSESSMENT)
        act = _axis_totals(self.rules, "actionability", ACTIONABILITY)
        reasons = _axis_totals(self.rules, "reason_codes", REASON_CODES)
        lvl_resolved = reviewed - lvl["uncertain"]
        gate_resolved = reviewed - gate["uncertain"]
        return {
            "reviewed": reviewed, "confirmed": c, "false_positive": fp,
            "uncertain": u, "decided": decided,
            # rates as explicit numerator/denominator — never a bare percent
            "observed_confirmed_rate": _ratio(c, decided),
            "uncertainty_rate": _ratio(u, reviewed),
            "level_agreement": _ratio(lvl["correct"], lvl_resolved),
            "gate_agreement": _ratio(gate["correct"], gate_resolved),
            "actionable_rate": _ratio(act["actionable"], reviewed),
            "reason_code_counts": {k: v for k, v in sorted(reasons.items())
                                   if v},
        }


def _axis_totals(rules, axis: str, labels) -> dict:
    out = {k: 0 for k in labels}
    for s in rules:
        for k, v in getattr(s, axis).items():
            out[k] = out.get(k, 0) + v
    return out


def _ratio(num: int, den: int) -> dict:
    return {"numerator": num, "denominator": den,
            "value": round(num / den, 4) if den else None}


def evidence_class(s: RuleStat) -> str:
    """A BENCHMARK decision (never a product-policy change): how much this
    sample supports trusting the rule."""
    if s.decided == 0 or s.uncertain > s.decided:
        return "insufficient_evidence"
    fp_share = s.false_positive / s.decided
    if fp_share >= 0.34:
        return "needs_hardening"
    if fp_share == 0.0 and s.uncertain <= s.decided:
        return "provisionally_credible"
    return "needs_hardening" if fp_share > 0 else "provisionally_credible"


def _axis_field(entry: dict, name: str, legal):
    v = entry.get(name)
    if v not in legal:
        raise QualityError(f"label entry has an invalid {name}")
    return v


_IDENTITY_FIELDS = ("alias", "rule", "project", "file", "line", "fingerprint")


def load_labels(path: Path) -> dict:
    """Load and validate a schema_version 3 labels file. Returns
    {"corpus": {alias: int}, "labels": [entry...]} with every entry bound to
    one finding identity."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise QualityError(f"labels file unreadable: {e.__class__.__name__}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise QualityError(f"labels file is not valid JSON: line {e.lineno}") from e
    if not isinstance(data, dict) or data.get("schema_version") != 3 \
            or not isinstance(data.get("labels"), list) \
            or not isinstance(data.get("corpus"), dict):
        raise QualityError(
            "labels file must be {schema_version:3, corpus:{...}, labels:[...]}")
    corpus = {}
    for alias, n in data["corpus"].items():
        if not (isinstance(alias, str) and _ALIAS_RE.match(alias)):
            raise QualityError("corpus has an invalid repo alias")
        if not (isinstance(n, int) and n > 0):
            raise QualityError("corpus counts must be positive integers")
        corpus[alias] = n
    out = []
    seen_ids: set[str] = set()
    for entry in data["labels"]:
        if not isinstance(entry, dict):
            raise QualityError("each label entry must be an object")
        sid = entry.get("sample_id")
        if not (isinstance(sid, str) and _HEX_RE.match(sid)):
            raise QualityError("label entry has an invalid sample_id")
        if sid in seen_ids:
            raise QualityError("duplicate sample_id in labels")
        seen_ids.add(sid)
        alias, rule = entry.get("alias"), entry.get("rule")
        pop = entry.get("population")
        if not (isinstance(alias, str) and _ALIAS_RE.match(alias)):
            raise QualityError("label entry has an invalid repo alias")
        if alias not in corpus:
            raise QualityError("label alias missing from corpus header")
        if not (isinstance(rule, str) and _RULE_RE.match(rule)):
            raise QualityError("label entry has an invalid rule id")
        if not (isinstance(pop, int) and pop > 0):
            raise QualityError("population must be a positive integer")
        for f in ("project", "file"):
            if not (isinstance(entry.get(f), str) and entry[f]):
                raise QualityError(f"label entry has an invalid {f}")
        if not isinstance(entry.get("line"), int) or entry["line"] < 0:
            raise QualityError("label entry has an invalid line")
        if not (isinstance(entry.get("fingerprint"), str)
                and entry["fingerprint"]):
            raise QualityError("label entry has an invalid fingerprint")
        rid = entry.get("review_id")
        if rid is not None and not (isinstance(rid, str) and rid):
            raise QualityError("review_id must be null or a non-empty string")
        ev = entry.get("evidence")
        if not (isinstance(ev, str) and ev.strip()):
            raise QualityError("label entry must carry non-empty evidence")
        # the stored sample_id must be DERIVABLE from the identity — a value
        # that merely matches some other file is not enough
        if sid != _compute_sample_id(alias, entry["project"], entry["file"],
                                     entry["line"], rule,
                                     entry["fingerprint"]):
            raise QualityError(
                "label sample_id does not match its own identity")
        out.append({
            "sample_id": sid, "alias": alias, "rule": rule,
            "population": pop, "project": entry["project"],
            "file": entry["file"], "line": entry["line"],
            "fingerprint": entry["fingerprint"], "review_id": rid,
            "evidence": ev,
            "validity": _axis_field(entry, "validity", VALIDITY),
            "level_assessment": _axis_field(entry, "level_assessment",
                                            LEVEL_ASSESSMENT),
            "gate_assessment": _axis_field(entry, "gate_assessment",
                                           GATE_ASSESSMENT),
            "actionability": _axis_field(entry, "actionability",
                                         ACTIONABILITY),
            "reason_code": _axis_field(entry, "reason_code", REASON_CODES),
        })
    return {"corpus": corpus, "labels": out}


def verify_one_to_one(labels: list[dict], sample: list[dict]) -> None:
    """Every sampled finding has exactly one label and vice versa; identity
    fields match literally; result is independent of either list's order."""
    by_sid = {}
    for s in sample:
        if not isinstance(s, dict):
            raise QualityError("each sample entry must be an object")
        sid = s.get("sample_id")
        if not (isinstance(sid, str) and _HEX_RE.match(sid)):
            raise QualityError("sample entry has a missing or invalid "
                               "sample_id")
        try:
            expected = _compute_sample_id(s["alias"], s["project"],
                                          s["file"], s["line"], s["rule"],
                                          s["fingerprint"])
        except KeyError as e:
            raise QualityError(
                "sample entry is missing an identity field") from e
        if sid != expected:
            raise QualityError(
                "sample entry sample_id does not match its own identity")
        if sid in by_sid:
            raise QualityError("duplicate sample_id in sample")
        by_sid[sid] = s
    seen: set[str] = set()
    for lab in labels:
        sid = lab.get("sample_id")
        try:
            expected = _compute_sample_id(lab["alias"], lab["project"],
                                          lab["file"], lab["line"],
                                          lab["rule"], lab["fingerprint"])
        except KeyError as e:
            raise QualityError(
                "label entry is missing an identity field") from e
        if sid != expected:
            raise QualityError(
                "label sample_id does not match its own identity")
        if sid in seen:
            raise QualityError("duplicate sample_id in labels")
        seen.add(sid)
        match = by_sid.get(sid)
        if match is None:
            raise QualityError("label refers to a finding outside the sample")
        for f in _IDENTITY_FIELDS + ("population",):
            if lab[f] != match[f]:
                raise QualityError(f"label {f} does not match the sample")
    missing = set(by_sid) - seen
    if missing:
        raise QualityError(
            f"{len(missing)} sampled finding(s) have no label")


def aggregate(loaded: dict | list) -> Aggregate:
    """Aggregate labels per (alias, rule). Accepts the load_labels() result;
    output is independent of label order (keys are sorted)."""
    if isinstance(loaded, dict):
        labels, corpus = loaded["labels"], dict(loaded.get("corpus", {}))
    else:
        labels, corpus = loaded, {}
    keys: dict[tuple[str, str], dict] = {}
    for e in labels:
        k = (e["alias"], e["rule"])
        b = keys.setdefault(k, {"population": e["population"], "reviewed": 0,
                                "validity": {}, "level_assessment": {},
                                "gate_assessment": {}, "actionability": {},
                                "reason_codes": {}})
        if e["population"] != b["population"]:
            raise QualityError(f"inconsistent population for {k}")
        b["reviewed"] += 1
        for axis in ("validity", "level_assessment", "gate_assessment",
                     "actionability"):
            b[axis][e[axis]] = b[axis].get(e[axis], 0) + 1
        rc = e["reason_code"]
        b["reason_codes"][rc] = b["reason_codes"].get(rc, 0) + 1
    agg = Aggregate(corpus=corpus)
    for (alias, rule), b in sorted(keys.items()):
        if sum(b["reason_codes"].values()) != b["reviewed"]:
            raise QualityError(f"reason_code counts do not sum to reviewed "
                               f"for {(alias, rule)}")
        agg.rules.append(RuleStat(
            alias=alias, rule=rule, population=b["population"],
            reviewed=b["reviewed"], validity=b["validity"],
            level_assessment=b["level_assessment"],
            gate_assessment=b["gate_assessment"],
            actionability=b["actionability"],
            reason_codes=b["reason_codes"]))
    return agg


def public_summary(agg: Aggregate) -> dict:
    return {
        "schema_version": 3,
        "corpus": {alias: {"findings": n}
                   for alias, n in sorted(agg.corpus.items())},
        "method": METHOD_TEXT,
        "axes": {"validity": list(VALIDITY),
                 "level_assessment": list(LEVEL_ASSESSMENT),
                 "gate_assessment": list(GATE_ASSESSMENT),
                 "actionability": list(ACTIONABILITY),
                 "reason_code": list(REASON_CODES)},
        "evidence_classes": list(EVIDENCE_CLASSES),
        "note": NOTE_TEXT,
        "rules": [s.as_row() for s in agg.rules],
        "totals": agg.totals(),
    }


# ---- structural anonymization gate ------------------------------------------------

def _need_int(v, where: str) -> None:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise QualityError(f"non-count value at {where}")


def _need_axis_dict(v, legal, where: str, subset: bool = False) -> None:
    if not isinstance(v, dict):
        raise QualityError(f"unexpected structure at {where}")
    for k, n in v.items():
        if k not in legal:
            raise QualityError(f"unexpected key at {where}")
        _need_int(n, where)
    if not subset and set(v) != set(legal):
        raise QualityError(f"missing axis keys at {where}")


def _need_ratio(v, where: str) -> None:
    if not isinstance(v, dict) or set(v) != {"numerator", "denominator",
                                             "value"}:
        raise QualityError(f"unexpected structure at {where}")
    _need_int(v["numerator"], where)
    _need_int(v["denominator"], where)
    if v["value"] is not None and not isinstance(v["value"], (int, float)):
        raise QualityError(f"unexpected value type at {where}")


_ROW_KEYS = {"repo", "rule", "population", "reviewed", "validity",
             "level_assessment", "gate_assessment", "actionability",
             "reason_code_counts", "sampling", "evidence_class"}
_TOTAL_RATIOS = ("observed_confirmed_rate", "uncertainty_rate",
                 "level_agreement", "gate_agreement", "actionable_rate")
_TOTAL_KEYS = {"reviewed", "confirmed", "false_positive", "uncertain",
               "decided", "reason_code_counts", *_TOTAL_RATIOS}
_TOP_KEYS = {"schema_version", "corpus", "method", "axes",
             "evidence_classes", "note", "rules", "totals"}


def assert_anonymized(summary: dict) -> None:
    """Structural allowlist walk over the public summary. Rejects any extra
    key and any value that is not a legal enum string, repo alias, rule id,
    fixed text, or non-negative count — which excludes real repository
    names, file paths, projects, snippets, fingerprints, review ids,
    evidence text, and secrets, in any letter case. Never echoes the
    offending value."""
    if not isinstance(summary, dict):
        raise QualityError("summary must be an object")
    if set(summary) != _TOP_KEYS:
        raise QualityError("unexpected top-level key set in summary")
    if summary["schema_version"] != 3:
        raise QualityError("summary schema_version must be 3")
    if not isinstance(summary["corpus"], dict) or not summary["corpus"]:
        raise QualityError("unexpected structure at corpus")
    for alias, v in summary["corpus"].items():
        if not (isinstance(alias, str) and _ALIAS_RE.match(alias)):
            raise QualityError("non-anonymized alias in corpus")
        if not isinstance(v, dict) or set(v) != {"findings"}:
            raise QualityError("unexpected structure at corpus entry")
        _need_int(v["findings"], "corpus findings")
    if summary["method"] != METHOD_TEXT or summary["note"] != NOTE_TEXT:
        raise QualityError("method/note text does not match the fixed copy")
    expected_axes = {"validity": list(VALIDITY),
                     "level_assessment": list(LEVEL_ASSESSMENT),
                     "gate_assessment": list(GATE_ASSESSMENT),
                     "actionability": list(ACTIONABILITY),
                     "reason_code": list(REASON_CODES)}
    if summary["axes"] != expected_axes \
            or summary["evidence_classes"] != list(EVIDENCE_CLASSES):
        raise QualityError("axes/evidence_classes do not match the fixed copy")
    if not isinstance(summary["rules"], list):
        raise QualityError("rules must be a list")
    for i, row in enumerate(summary["rules"]):
        where = f"rules[{i}]"
        if not isinstance(row, dict) or set(row) != _ROW_KEYS:
            raise QualityError(f"unexpected key set at {where}")
        if not (isinstance(row["repo"], str) and _ALIAS_RE.match(row["repo"])):
            raise QualityError(f"non-anonymized repo at {where}")
        if not (isinstance(row["rule"], str) and _RULE_RE.match(row["rule"])):
            raise QualityError(f"non-anonymized rule at {where}")
        _need_int(row["population"], where)
        _need_int(row["reviewed"], where)
        _need_axis_dict(row["validity"], VALIDITY, where)
        _need_axis_dict(row["level_assessment"], LEVEL_ASSESSMENT, where)
        _need_axis_dict(row["gate_assessment"], GATE_ASSESSMENT, where)
        _need_axis_dict(row["actionability"], ACTIONABILITY, where)
        _need_axis_dict(row["reason_code_counts"], REASON_CODES, where,
                        subset=True)
        if sum(row["reason_code_counts"].values()) != row["reviewed"]:
            raise QualityError(f"reason_code_counts do not sum to reviewed "
                               f"at {where}")
        if row["sampling"] not in _SAMPLING:
            raise QualityError(f"illegal sampling value at {where}")
        if row["evidence_class"] not in EVIDENCE_CLASSES:
            raise QualityError(f"illegal evidence_class at {where}")
    t = summary["totals"]
    if not isinstance(t, dict) or set(t) != _TOTAL_KEYS:
        raise QualityError("unexpected key set at totals")
    for k in ("reviewed", "confirmed", "false_positive", "uncertain",
              "decided"):
        _need_int(t[k], f"totals.{k}")
    for k in _TOTAL_RATIOS:
        _need_ratio(t[k], f"totals.{k}")
    _need_axis_dict(t["reason_code_counts"], REASON_CODES,
                    "totals.reason_code_counts", subset=True)
    if sum(t["reason_code_counts"].values()) != t["reviewed"]:
        raise QualityError("totals reason_code_counts do not sum to reviewed")


def build_public_summary(labels_path: Path, sample_path: Path) -> dict:
    """Build the anonymized summary. The sample is a MANDATORY input — there
    is no legal path to a public summary that skips the one-to-one binding
    check against the deterministic sample."""
    loaded = load_labels(labels_path)
    if not isinstance(sample_path, Path):
        raise QualityError("sample_path must be a filesystem path")
    try:
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise QualityError(
            f"sample file unreadable: {e.__class__.__name__}") from e
    if not isinstance(sample, list):
        raise QualityError("sample file must be a JSON list")
    verify_one_to_one(loaded["labels"], sample)
    summary = public_summary(aggregate(loaded))
    assert_anonymized(summary)
    return summary


DEFAULT_LABELS = Path(".quality-local/labels.json")
DEFAULT_SAMPLE = Path(".quality-local/sample.json")
DEFAULT_SUMMARY = Path("docs/quality/baseline-summary.json")


def main(argv: list[str]) -> str:
    src = Path(argv[0]) if len(argv) > 0 else DEFAULT_LABELS
    dst = Path(argv[1]) if len(argv) > 1 else DEFAULT_SUMMARY
    smp = Path(argv[2]) if len(argv) > 2 else DEFAULT_SAMPLE
    out = build_public_summary(src, smp)
    dst.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    t = out["totals"]
    return (f"wrote {dst}: {t['reviewed']} reviewed, confirmed "
            f"{t['observed_confirmed_rate']['numerator']}/"
            f"{t['observed_confirmed_rate']['denominator']}")


if __name__ == "__main__":
    import sys
    print(main(sys.argv[1:]))

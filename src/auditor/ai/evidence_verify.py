"""W3-E4C2: deterministic evidence-content verification.

Runs AFTER the model reply, on the model result and the EXACT canonical pack
that was sent — it reads no new files and never rewrites the model's words.
For every issue it decides, from the cited lines' actual content (plus the
redaction facts and the unresolved facts already in the pack), whether the
cited evidence SUPPORTS the claimed category:

  supported            — the cited lines carry the category's positive
                         evidence and no counter-evidence contradicts it.
  unsupported          — the cited lines do not carry that evidence (a
                         structurally legal citation whose content is off-
                         claim, e.g. a credential claim on lines with no
                         literal and no redaction fact), or clear counter-
                         evidence is present.
  insufficient_evidence — the deciding context is not in the payload (the
                         sink/validator/callee is an unsent symbol, a
                         dependency claim without a manifest, or a missing-
                         control claim whose relevant context is unresolved).

Only `supported` issues are promoted to actionable AI candidates; the rest
stay in the result for transparency, shown as unverified. Reason codes are a
fixed, safe enum — never a snippet or a local path.
"""
from __future__ import annotations

import re
from typing import Any

VERIFY_SUPPORTED = "supported"
VERIFY_UNSUPPORTED = "unsupported"
VERIFY_INSUFFICIENT = "insufficient_evidence"
VERIFY_STATES = (VERIFY_SUPPORTED, VERIFY_UNSUPPORTED, VERIFY_INSUFFICIENT)

# fixed, safe reason codes (no snippets, no paths)
REASON_CODES = (
    "cited_lines_carry_category_evidence",
    "cited_lines_lack_category_evidence",
    "counter_evidence_present",
    "credential_claim_without_literal_or_fact",
    "deciding_context_not_in_payload",
    "dependency_claim_without_manifest",
    "missing_control_context_unresolved",
    "citation_not_in_sent_pieces",
    # W3-E4C closing: fail-closed — a candidate that was never screened (a
    # missing/corrupt verification field, a legacy schema-1 sidecar) is
    # insufficient_evidence with this reason; it is NEVER a screened pass.
    "verification_missing",
    # a C#-style namespace import cannot be mapped to a package id
    # deterministically (id != namespace) — the comparison is ambiguous.
    "namespace_package_ambiguous",
)

_CRED = re.compile(
    r"password|secret|api[_-]?key|apikey|token|connectionstring|pwd\s*=",
    re.I)
_SINK = re.compile(
    r"\bexecute\b|\bquery\(|innerhtml|os\.system|subprocess|popen|\beval\("
    r"|\bexec\(|fromsql|executesql|\.raw\(|\bsystem\(", re.I)
_CONCAT = re.compile(r"\+\s*\w|f['\"]|\$\{|\bformat\(|%\s*\(|%s")
_INPUT = re.compile(r"request\.|req\.body|params|\bargs\[|get_json|\.body\b",
                    re.I)
_ENDPOINT = re.compile(
    r"mapget|mappost|mapput|mapdelete|\[http|\[route|app\.(get|post|put|delete)"
    r"|export\s+(async\s+)?function\s+(get|post|put|patch|delete)"
    r"|public\s+\w+\s+\w+\s*\(|def\s+\w+\s*\(\s*(self\s*,\s*)?request", re.I)
_CONCURRENCY = re.compile(
    r"savechanges|\.commit\(|task\.run|begintransaction|\block\b|interlocked"
    r"|threading|\.lock\b", re.I)
_TX = re.compile(r"begintransaction|using\s+var\s+tx|\block\s*\(|with\s+self\._lock"
                 r"|\.lock\b|interlocked", re.I)
_SWALLOW = re.compile(
    r"^\s*pass\s*$|return\s+(true|none|null|'ok'|\"ok\"|\{)", re.I)
_PROPAGATE = re.compile(r"\braise\b|\bthrow\b|rethrow", re.I)
# a SPECIFIC field access used in an expression: a subscript ['key'] or an
# attribute followed by an arithmetic operator. Passing the whole payload
# (`request.json`, `payload`) to a callee is NOT a field use.
_FIELD_USE = re.compile(r"\[['\"]\w+['\"]\]|\.\w+\s*[*+/-]")
_VALIDATE = re.compile(
    r"validate|schema|basemodel|\bzod\b|model_validate|\.parse\(|required"
    r"|frombody|bindproperty", re.I)
_IMPORT = re.compile(r"^\s*(import|from|using|require\(|const\s+\w+\s*=\s*require)",
                     re.I | re.M)
_STUB = re.compile(
    r"notimplemented|throw\s+new\s+notimplemented|raise\s+notimplemented"
    r"|\bstub\b|\bplaceholder\b", re.I)
# a bare private/injected delegate call: `_x.method(...)`, `self._x...`
_DELEGATE = re.compile(r"\b_\w+\.\w+\s*\(|\bself\._\w+")


def _lines_by_cid(pack: dict[str, Any]) -> dict[str, dict[int, str]]:
    """Reconstruct {context_id: {line_no: content}} from the SENT pieces —
    the exact bytes the model saw, minus the 'N: ' rendering prefix."""
    out: dict[str, dict[int, str]] = {}
    for p in pack.get("pieces", []):
        cid = p.get("context_id")
        if "text" not in p or cid is None:
            continue
        rows: dict[int, str] = {}
        for ln in p["text"].split("\n"):
            m = re.match(r"^(\d+): (.*)$", ln)
            if m:
                rows[int(m.group(1))] = m.group(2)
        out[cid] = rows
    return out


# the redaction classes that PROVE a masked literal secret (today: all of the
# redactor's classes are secret-shaped; the allowlist still matters — a fact of
# any OTHER class can never prove a credential citation)
CREDENTIAL_FACT_CLASSES = frozenset(
    {"credential_url", "auth_header", "quoted_kv", "token_kv", "known_token"})
# W3-E4C-FINAL: the ONE fact kind that proves a committed literal credential.
LITERAL_CREDENTIAL_KIND = "literal_credential_proven"


def _proves_credential(cls_kind: tuple[str, str] | None) -> bool:
    """A cited fact proves a masked literal credential ONLY when it is a
    credential-class fact AND its kind is literal_credential_proven — a
    redaction_applied fact (a possible env/config reference masked for
    privacy) proves nothing, and a fact of any other class never proves it."""
    if cls_kind is None:
        return False
    cls, kind = cls_kind
    return cls in CREDENTIAL_FACT_CLASSES and kind == LITERAL_CREDENTIAL_KIND


def _fact_lines(pack: dict[str, Any]) -> dict[tuple[str, int], tuple[str, str]]:
    """{(file, line): (redaction_class, kind)} for every fact line. W3-E4C-
    FINAL: a credential citation is proven ONLY by a fact whose kind is
    `literal_credential_proven` AT that line; a `redaction_applied` fact
    (privacy masking of a possible env/config reference) never proves it."""
    facts = next((p for p in pack.get("pieces", [])
                  if p.get("context_id") == "redaction_facts"), None)
    out: dict[tuple[str, int], tuple[str, str]] = {}
    if facts:
        for f in facts["facts"]:
            cls_kind = (f["redaction_class"],
                        f.get("kind", "redaction_applied"))
            for n in range(f["line_start"], f["line_end"] + 1):
                out[(f["file"], n)] = cls_kind
    return out


def _has_unresolved(pack: dict[str, Any]) -> bool:
    return any(p.get("context_id") == "unresolved"
               for p in pack.get("pieces", []))


def _has_manifest(pack: dict[str, Any]) -> bool:
    return any(str(p.get("context_id", "")).startswith("manifest:")
               for p in pack.get("pieces", []))


def _cited_text(issue: dict[str, Any],
                by_cid: dict[str, dict[int, str]]) -> str:
    parts: list[str] = []
    ok = False
    for ev in issue.get("evidence", []):
        rows = by_cid.get(ev.get("context_id"), {})
        for n in range(ev.get("line_start", 0), ev.get("line_end", -1) + 1):
            if n in rows:
                parts.append(rows[n])
                ok = True
    return ("\n".join(parts)) if ok else "\x00"    # \x00 => nothing citable


def _manifest_text(pack: dict[str, Any]) -> str:
    return "\n".join(p.get("text", "") for p in pack.get("pieces", [])
                     if str(p.get("context_id", "")).startswith("manifest:")
                     ).casefold()


_JS_FROM = re.compile(r"""from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]""")
_PY_IMPORT = re.compile(r"^\s*(?:import|from)\s+([\w.]+)", re.M)
_CS_USING = re.compile(r"^\s*using\s+[\w.]+\s*;", re.M)


def _imported_names(text: str) -> list[str] | None:
    """Top-level package names imported on the cited lines. Returns None for
    C#-style namespace imports (package id != namespace — a deterministic
    comparison is impossible)."""
    if _CS_USING.search(text):
        return None
    names: list[str] = []
    for m in _JS_FROM.finditer(text):
        spec = m.group(1) or m.group(2) or ""
        if not spec or spec.startswith((".", "@/")):
            continue                          # local/relative — not a package
        parts = spec.split("/")
        names.append("/".join(parts[:2]) if spec.startswith("@") else parts[0])
    for m in _PY_IMPORT.finditer(text):
        names.append(m.group(1).split(".")[0])
    return sorted(set(names))


def _declared(name: str, manifest: str) -> bool:
    """Package `name` appears in the manifest text (hyphen/underscore folded —
    PyPI treats them as equivalent)."""
    n = name.casefold()
    return n in manifest or n.replace("_", "-") in manifest \
        or n.replace("-", "_") in manifest


def _delegates_to_unsent(text: str, pack: dict[str, Any]) -> bool:
    """The cited line delegates to a private/injected symbol whose definition
    is nowhere in the sent canonical bytes — the deciding logic is unsent."""
    if not _DELEGATE.search(text):
        return False
    canonical = pack.get("canonical", "")
    for m in re.finditer(r"_(\w+)\.(\w+)\s*\(", text):
        method = m.group(2)
        # a definition of that method anywhere in the payload?
        if re.search(rf"\bdef\s+{re.escape(method)}\b"
                     rf"|\b{re.escape(method)}\s*\([^)]*\)\s*(=>|\{{)",
                     canonical):
            return False
    return True


# a LITERAL credential value actually visible on the cited lines: a secret-
# named key assigned a quoted, non-*** value. A masked value relies on a fact.
_CRED_LITERAL = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|connectionstring)"
    r"\s*['\"]?\s*[=:]\s*['\"][^'\"*]{4,}['\"]", re.I)
# an env/config/secret-manager REFERENCE — the opposite of a committed literal
_CRED_REF = re.compile(
    r"process\.env|getenv|os\.environ|environ\[|secretsmanager|keyvault"
    r"|\bvault\b|registry\.get|_settings\b|configuration\[", re.I)
# unsafe composition of the value that reaches a sink (concat / f-string /
# template / format) — required for an injection claim, not just a sink call
_UNSAFE_COMPOSE = re.compile(r"\+\s*\w|f['\"]|\$\{|\.format\(|%\s*\w|'\s*\+")
# parameterized/bound/sanitized markers on the SAME cited lines
_PARAMETERIZED = re.compile(
    r"%s['\"]\s*,|\?\s*['\"]?\s*,\s*[\[(]|dompurify\.sanitize|\.filter\(",
    re.I)
_FIRE_AND_FORGET = re.compile(r"task\.run\s*\(", re.I)
_PERSIST = re.compile(r"savechanges|\.commit\(|\.persist\(|\.save\(", re.I)


def verify_issue(issue: dict[str, Any], pack: dict[str, Any],
                 by_cid: dict[str, dict[int, str]],
                 fact_lines: dict[tuple[str, int], tuple[str, str]]
                 ) -> tuple[str, str]:
    text = _cited_text(issue, by_cid)
    if text == "\x00":
        return VERIFY_UNSUPPORTED, "citation_not_in_sent_pieces"
    cat = issue.get("category")
    low = text.lower()

    if cat == "credentials":
        # 1) an explicit quoted literal secret on the cited lines always wins
        if _CRED_LITERAL.search(text):
            return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
        # 2) an env/config/secret-manager READ in the cited text is COUNTER-
        #    evidence — a reference is not a committed literal (a key NAME
        #    alone proves nothing), and it beats a fact elsewhere in the range
        if _CRED_REF.search(text):
            return VERIFY_UNSUPPORTED, "counter_evidence_present"
        # 3) a redaction fact AT a cited line proves a masked literal WITHOUT
        #    exposing it — but ONLY when its kind is literal_credential_proven.
        #    A redaction_applied fact (privacy masking of a possible env/config
        #    reference) never proves a committed credential.
        cited_fact = any(
            _proves_credential(
                fact_lines.get((_ev_file(issue, pack, ev), n)))
            for ev in issue["evidence"]
            for n in range(ev["line_start"], ev["line_end"] + 1))
        if cited_fact:
            return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
        # 4) a secret-shaped NAME with no visible value/fact/reference — the
        #    provenance is decided elsewhere
        if _CRED.search(text):
            return VERIFY_INSUFFICIENT, "deciding_context_not_in_payload"
        return VERIFY_UNSUPPORTED, "credential_claim_without_literal_or_fact"

    if cat == "input_handling":
        if _PARAMETERIZED.search(text):
            # bound placeholders / ORM binding / real sanitizer on the cited
            # lines — the claimed injection is contradicted where it is cited
            return VERIFY_UNSUPPORTED, "counter_evidence_present"
        if _SINK.search(text):
            # a sink alone is not an injection: the claim needs the input
            # provenance AND the unsafe composition on the SENT path
            if _INPUT.search(text) and _UNSAFE_COMPOSE.search(text):
                return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
            return VERIFY_INSUFFICIENT, "deciding_context_not_in_payload"
        if _delegates_to_unsent(text, pack):
            return VERIFY_INSUFFICIENT, "deciding_context_not_in_payload"
        return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"

    if cat == "authorization":
        # the citation must land on an endpoint/handler (an off-endpoint
        # citation does not support a missing-authorization claim). Whether an
        # authorization control that IS present actually COVERS this route is
        # a path-scoping judgement the model makes; the verifier does not
        # override it (that is exactly where scoped-vs-covering differs). But
        # a high-confidence missing-control claim whose protection context is
        # NOT in the payload (unresolved middleware/backend) is downgraded.
        if not _ENDPOINT.search(text):
            if _has_unresolved(pack):
                return VERIFY_INSUFFICIENT, "missing_control_context_unresolved"
            return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"
        if issue.get("confidence") == "high" and _has_unresolved(pack):
            return VERIFY_INSUFFICIENT, "missing_control_context_unresolved"
        return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"

    if cat == "concurrency":
        if _TX.search(text):
            return VERIFY_UNSUPPORTED, "counter_evidence_present"
        # a STRUCTURAL hazard is required: an unobserved fire-and-forget task,
        # or TWO+ persists straddling work in the cited window. One
        # SaveChanges/commit alone is atomic — never a hazard.
        if _FIRE_AND_FORGET.search(text) \
                or len(_PERSIST.findall(low)) >= 2:
            return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
        if _delegates_to_unsent(text, pack):
            return VERIFY_INSUFFICIENT, "deciding_context_not_in_payload"
        return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"

    if cat == "error_handling":
        has_handler = ("except" in low or "catch" in low)
        if has_handler and _PROPAGATE.search(text):
            return VERIFY_UNSUPPORTED, "counter_evidence_present"
        if has_handler and _SWALLOW.search(text):
            return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
        if _delegates_to_unsent(text, pack):
            return VERIFY_INSUFFICIENT, "deciding_context_not_in_payload"
        return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"

    if cat == "api_contract":
        if _VALIDATE.search(text):
            return VERIFY_UNSUPPORTED, "counter_evidence_present"
        if _INPUT.search(text) and _FIELD_USE.search(text):
            return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
        if _delegates_to_unsent(text, pack) or _INPUT.search(text):
            return VERIFY_INSUFFICIENT, "deciding_context_not_in_payload"
        return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"

    if cat == "dependency_integration":
        if not _IMPORT.search(text):
            return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"
        if not _has_manifest(pack):
            return VERIFY_INSUFFICIENT, "dependency_claim_without_manifest"
        # compare the ACTUAL imported names with the manifest declarations —
        # the mere presence of import + manifest proves nothing
        names = _imported_names(text)
        if names is None:                    # C#-style namespace import:
            return (VERIFY_INSUFFICIENT,     # package id != namespace
                    "namespace_package_ambiguous")
        if not names:
            return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"
        manifest = _manifest_text(pack)
        undeclared = [n for n in names if not _declared(n, manifest)]
        if undeclared:
            return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
        return VERIFY_UNSUPPORTED, "counter_evidence_present"

    if cat == "incomplete_code":
        if _STUB.search(text):
            return VERIFY_SUPPORTED, "cited_lines_carry_category_evidence"
        # a TODO/FIXME appearing only in a comment referencing an external
        # call is not a live stub
        return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"

    return VERIFY_UNSUPPORTED, "cited_lines_lack_category_evidence"


def _ev_file(issue: dict[str, Any], pack: dict[str, Any],
             ev: dict[str, Any]) -> str:
    """The file for a citation, from the pack's server-side piece map (never
    the model's echoed file field)."""
    return pack.get("piece_map", {}).get(ev.get("context_id"), {}).get(
        "file", ev.get("file", ""))


def fail_closed(verification: Any, reason: Any) -> tuple[str, str]:
    """FAIL-CLOSED: a missing, unknown, or malformed screening verdict is
    NEVER treated as a pass. It resolves to insufficient_evidence with the
    fixed `verification_missing` reason — the ONE place a default is chosen,
    and it is the safe one. Every consumer (store, API, CLI, UI) must route
    an unscreened candidate through this, not through `... or supported`."""
    if verification not in VERIFY_STATES or reason not in REASON_CODES:
        return VERIFY_INSUFFICIENT, "verification_missing"
    return verification, reason


def verify_result(result: dict[str, Any],
                  pack: dict[str, Any]) -> dict[str, Any]:
    """Return the SAME result with a `verification`/`verification_reason` on
    every issue. The model's words are never changed. Deterministic."""
    by_cid = _lines_by_cid(pack)
    fact_lines = _fact_lines(pack)
    for issue in result.get("issues", []):
        state, reason = verify_issue(issue, pack, by_cid, fact_lines)
        # even the verifier's own output is routed through fail_closed, so an
        # illegal pair can never slip past as a pass
        issue["verification"], issue["verification_reason"] = fail_closed(
            state, reason)
    return result

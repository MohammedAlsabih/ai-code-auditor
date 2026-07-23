from __future__ import annotations

import re

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_SQL_RE = re.compile(r"\b(SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b",
                     re.I | re.S)
# B2.8C1 (closing): `sql` recognizes SQL-execution APIs whose name does not
# carry execute/query/raw/command — e.g. EF's FromSqlInterpolated/FromSql.
# An EF-PROVEN interpolating sink is cleared earlier by sql_parameterizing;
# a non-EF `*Sql*` method receiving composed SQL is a real injection sink.
_SINK_RE = re.compile(r"(execute|query|raw|command|sql)", re.I)

_TOKEN_PATTERNS = [
    ("AWS access key", re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|github_pat_[A-Za-z0-9_]{22,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("URL with credentials", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"]{1,64}:[^@/\s'\"]{4,}@")),
    ("Connection string password", re.compile(r"(?i)(?=.*\b(?:server|data source|host)\s*=)(?:.*)\b(?:password|pwd)\s*=\s*[^;\s\"']{4,}")),
]
_GENERIC_CRED = re.compile(r"(?i)\b(api_?key|secret|token|passwd|password)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']")
_PLACEHOLDER = re.compile(r"(?i)(changeme|example|placeholder|your[_\-]|xxx+|dummy|sample|"
                          r"<[^>]*>|\{\{|\$\{|process\.env|os\.environ|getenv)")
# B2.8C-C: incompleteness markers live in COMMENTS. The bare word
# "placeholder" is NOT evidence — it is everyday UI vocabulary (a JSX/HTML
# placeholder attribute, a prop/type/parameter, a CSS `placeholder:` class, a
# translation key, user-facing copy). Only classic work markers
# (TODO/FIXME/HACK/XXX) and EXPLICIT incompleteness phrases count, and only
# inside a comment.
_SMELLS = re.compile(r"(?i)(in a real (?:app|application|project|system)|TODO\b:?|FIXME\b:?|"
                     r"HACK\b:?|\bXXX\b|not implemented|for demo purposes|"
                     r"in production,? you (?:would|should)|"
                     r"placeholder (?:implementation|logic|value|code|for now)|"
                     r"(?:temporary|temp) (?:stub|placeholder|implementation|hack)|"
                     r"stubbed? out|just a (?:stub|placeholder)|"
                     r"simplified (?:for|version)|replace (?:this )?with (?:your|actual|real)|"
                     r"left as an exercise|mock implementation)")


def _mk_finding(rule_id: str, severity: Severity, title: str, sf: SourceFile,
                line: int, snippet: str, detail: str,
                precision: str = "exact") -> Finding:
    return Finding(rule_id=rule_id, severity=severity, title=title, file=sf.rel,
                   line=line, snippet=snippet[:120], detail=detail,
                   language=sf.language, engine="auditor", precision=precision)


class EmptyCatch(Rule):
    id = "P001"
    severity = Severity.YELLOW
    title = "Empty or exception-swallowing catch/except block"

    def __init__(self, profile):
        self.profile = profile   # SyntaxProfile from the adapter — core stays language-free

    def check(self, sf: SourceFile) -> list[Finding]:
        if not self.profile.catch_query:
            return []
        out = []
        for clause in captures(sf.language, sf.tree.root_node, self.profile.catch_query).get("c", []):
            body = clause.child_by_field_name("body") \
                or next((c for c in clause.named_children
                         if c.type in self.profile.catch_body_types), None)
            if body is None:
                continue
            stmts = [c for c in body.named_children
                     if c.type not in self.profile.comment_types]
            swallows = not stmts or all(self.profile.is_swallow_stmt(s) for s in stmts)
            if swallows:
                out.append(_mk_finding(self.id, self.severity, self.title, sf,
                                       line_of(clause), node_text(clause).splitlines()[0],
                                       "Exception is silently swallowed — failures become invisible."))
        return out


# B2.8C-E2: a PEM HEADER alone is not a private key. A real key carries a
# base64 body (MII... — 40+ base64 chars). "-----BEGIN PRIVATE KEY-----
# \nMIIBROKEN\n-----END..." (a deliberately mangled test value) is neither a
# valid key nor an exact secret.
_PEM_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")


class SecretsRule(Rule):
    id = "P002"  # emits P002 and P003
    output_ids = ("P002", "P003")
    requires_syntax_tree = False   # scans sf.text line-by-line; parse-independent
    severity = Severity.RED
    title = "Hardcoded secret (known token format)"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        lines = sf.text.decode("utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines, 1):
            hit = next(((label, m) for label, rx in _TOKEN_PATTERNS
                        for m in [rx.search(line)] if m), None)
            if hit:
                label, m = hit
                if label == "Private key block" and not self._pem_has_body(lines, i, m):
                    continue   # header without a plausible key body: not a key
                masked = line.replace(m.group(0), m.group(0)[:4] + "***")
                if label == "Private key block":
                    # the body IS the secret — mask any base64 run on the line
                    masked = _PEM_BODY.sub("***", masked)
                # B2.8C1: a NON-EMPTY literal connection-string password is a
                # hardcoded secret regardless of host — localhost / design-time
                # / "dev only" are context recorded in the detail (never an
                # exemption). Deliberate suppression is a baseline/config
                # decision, not something the detector decides. (An empty or
                # missing password never matched _TOKEN_PATTERNS in the first
                # place, so it produces no finding.) The value stays masked.
                out.append(_mk_finding("P002", Severity.RED, self.title, sf, i,
                                       masked.strip(), f"{label} committed in source."))
                continue
            gm = _GENERIC_CRED.search(line)
            if gm and not _PLACEHOLDER.search(line):
                masked = line.replace(gm.group(2), gm.group(2)[:2] + "***")
                out.append(_mk_finding("P003", Severity.YELLOW,
                                       "Suspicious credential assignment", sf, i,
                                       masked.strip(),
                                       "Literal credential-like value assigned in code."))
        return out

    @staticmethod
    def _pem_has_body(lines: list[str], lineno: int, m) -> bool:
        """A plausible base64 body must follow the BEGIN header — on the SAME
        line (string literals with \\n escapes) or within the next 3 physical
        lines (real multi-line PEM)."""
        same = lines[lineno - 1][m.end():]
        if _PEM_BODY.search(same.split("-----END", 1)[0]):
            return True
        for nxt in lines[lineno:lineno + 3]:
            if "-----END" in nxt and not _PEM_BODY.search(nxt.split("-----END", 1)[0]):
                return False
            if _PEM_BODY.search(nxt):
                return True
        return False


class SqlStringBuild(Rule):
    id = "P004"  # emits P004 and P005
    output_ids = ("P004", "P005")
    severity = Severity.YELLOW
    title = "SQL built via string composition"
    precision = "heuristic"   # syntactic — no data-flow; documented in reports

    def __init__(self, profile):
        self.profile = profile

    def check(self, sf: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        seen_lines: set[int] = set()
        if self.profile.sql_concat_query:
            for node in captures(sf.language, sf.tree.root_node,
                                 self.profile.sql_concat_query).get("n", []):
                self._judge(node, sf, out, seen_lines, needs_dynamic=False)
        if self.profile.sql_interp_query:
            for node in captures(sf.language, sf.tree.root_node,
                                 self.profile.sql_interp_query).get("n", []):
                self._judge(node, sf, out, seen_lines, needs_dynamic=True)
        return out

    def _judge(self, node, sf: SourceFile, out: list, seen_lines: set,
               needs_dynamic: bool) -> None:
        text = node_text(node)
        if not _SQL_RE.search(text):
            return
        # B2.8C-A: a captured binary node must actually be STRING
        # CONCATENATION. Generic-call ambiguity (`X<T>(args)`) parses as a
        # `<`/`>` binary_expression wrapping the whole call — a parse
        # artifact, not composition. Any REAL `+`-concat inside it is a
        # separate capture and is still judged on its own.
        if not needs_dynamic and not self._is_plus_concat(node):
            return
        if needs_dynamic and not self._is_dynamic(node):
            return
        # B2.8C1: an enclosing call that PARAMETERIZES interpolation holes (EF
        # ExecuteSqlInterpolated*/FromSqlInterpolated*, proven by receiver
        # shape) makes this composition safe — neither P004 nor P005.
        if self.profile.sql_parameterizing is not None \
                and self.profile.sql_parameterizing(node, sf):
            return
        # B2.8C-A: a composition whose every leaf is a plain string literal is
        # a COMPILE-TIME CONSTANT ("SELECT ..." + "AND x = @p") — parameterized
        # SQL split over lines, not string-building. Never a finding.
        if not needs_dynamic and self._all_literal_leaves(node):
            return
        # B2.8C-A: a DYNAMIC composition whose parts are all provably trusted
        # (EF model metadata, consts, literal-arg local helpers) per the
        # adapter's provenance oracle is not user-influenceable.
        if self.profile.sql_trusted is not None \
                and self.profile.sql_trusted(node, sf):
            return
        line = line_of(node)
        if line in seen_lines:
            return
        seen_lines.add(line)
        sink = self._enclosing_sink(node)
        if sink:
            out.append(_mk_finding("P005", Severity.RED,
                                   "String-composed SQL reaches an execution sink", sf, line,
                                   text, f"Composed SQL is passed to '{sink}' — SQL injection risk; "
                                   "use parameterized queries.", precision=self.precision))
        else:
            out.append(_mk_finding("P004", Severity.YELLOW, self.title, sf, line, text,
                                   "SQL assembled from dynamic strings; prefer parameterized queries.",
                                   precision=self.precision))

    @staticmethod
    def _is_plus_concat(node) -> bool:
        op = node.child_by_field_name("operator")
        if op is not None:
            return node_text(op) == "+"
        # no operator field (e.g. python's binary_operator exposes it as an
        # anonymous child): accept unless a non-'+' operator token is visible
        ops = [c for c in node.children if not c.is_named]
        return not ops or any(node_text(c) == "+" for c in ops)

    def _is_dynamic(self, node) -> bool:
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type in self.profile.sql_dynamic_types:
                return True
            stack.extend(cur.named_children)
        return False

    # node kinds that merely GROUP a composition (never introduce dynamism)
    _COMPOSITION_TYPES = frozenset({
        "binary_expression", "parenthesized_expression", "binary_operator",
        "concatenated_string",
    })

    def _all_literal_leaves(self, node) -> bool:
        """True when the composition bottoms out in string literals only —
        the profile names its literal types; without them the answer is False
        (prior behavior preserved for languages without the hook)."""
        lits = self.profile.sql_literal_types
        if not lits:
            return False
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type in lits:
                continue                      # literal leaf — never descended
            if cur.type in self._COMPOSITION_TYPES:
                stack.extend(cur.named_children)
                continue
            return False                      # anything else = not provably constant
        return True

    def _enclosing_sink(self, node) -> str | None:
        cur = node.parent
        while cur is not None:
            # B2.8C-A: a lambda/local-function boundary ends the search — the
            # sink must receive the SQL in the same executable expression; an
            # outer MapGet/MapPost wrapper is never the sink.
            if cur.type in self.profile.sql_boundary_types:
                return None
            if cur.type in self.profile.sql_sink_call_types:
                fn = cur.child_by_field_name("function") or cur.child_by_field_name("name") \
                    or cur.child_by_field_name("type")
                if fn is not None:
                    name = node_text(fn)
                    if _SINK_RE.search(name):
                        return name.split("(")[0][-60:]
            cur = cur.parent
        return None


class SmellComments(Rule):
    id = "P007"
    severity = Severity.BLUE
    title = "AI-style incompleteness comment"

    # B2.8C-C closing round: markers are read from REAL COMMENT NODES of the
    # syntax tree, never from a regex over raw lines — `"https://x/TODO:..."`
    # inside a string carries `//` but is not a comment and never fires.
    _DEFAULT_COMMENT_TYPES = ("comment", "line_comment", "block_comment")

    def __init__(self, profile=None):
        self.comment_types = tuple(getattr(profile, "comment_types", None)
                                   or self._DEFAULT_COMMENT_TYPES)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        tree = getattr(sf, "tree", None)
        if tree is None:
            return []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in self.comment_types:
                base = line_of(node)
                for off, text in enumerate(node_text(node).splitlines()):
                    m = _SMELLS.search(text)
                    if m:
                        out.append(_mk_finding(
                            self.id, self.severity, self.title, sf, base + off,
                            text.strip(), f"Marker '{m.group(0)}' suggests "
                            "incomplete/demo-grade code left by generation."))
                continue
            stack.extend(node.named_children)
        return sorted(out, key=lambda f: f.line)


def common_rules(profile) -> list[Rule]:
    return [EmptyCatch(profile), SecretsRule(), SqlStringBuild(profile),
            SmellComments(profile)]


# ── Rule Capability Catalog (owned HERE; multi-output checks describe EVERY
#    emitted id separately: P002/P003 and P004/P005) ────────────────────────
from auditor.core.catalog import RuleDescriptor as _RD  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

from typing import Any as _Any  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

_P: "dict[str, _Any]" = dict(engine="pattern-engine", scope="file", source="builtin")
DESCRIPTORS = [
    _RD("P001", "Empty or exception-swallowing catch/except block",
        "A catch/except block silently swallows errors (empty or bare pass/ignore).",
        category="quality", default_level="warning", default_precision="exact", **_P),
    _RD("P002", "Hardcoded secret (known token format)",
        "A literal matches a known credential/token shape; the value is masked in reports.",
        category="security", default_level="error", default_precision="exact", **_P),
    _RD("P003", "Suspicious credential assignment",
        "A credential-named variable is assigned a literal value.",
        category="security", default_level="warning", default_precision="exact", **_P),
    _RD("P004", "String-composed SQL",
        "SQL text is built via string concatenation/interpolation.",
        category="security", default_level="warning", default_precision="exact", **_P),
    _RD("P005", "String-composed SQL reaches an execution sink",
        "String-built SQL flows into an execution call (injection candidate).",
        category="security", default_level="error", default_precision="heuristic", **_P),
    _RD("P007", "AI-style incompleteness comment",
        "A TODO/placeholder comment typical of AI-generated incomplete code.",
        category="hygiene", default_level="note", default_precision="exact", **_P),
]

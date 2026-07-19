from __future__ import annotations

import re

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_SQL_RE = re.compile(r"\b(SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b",
                     re.I | re.S)
_SINK_RE = re.compile(r"(execute|query|raw|command)", re.I)

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
_SMELLS = re.compile(r"(?i)(in a real (?:app|application|project|system)|TODO:?\s*implement|"
                     r"not implemented|placeholder|for demo purposes|in production,? you (?:would|should)|"
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


class SecretsRule(Rule):
    id = "P002"  # emits P002 and P003
    severity = Severity.RED
    title = "Hardcoded secret (known token format)"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for i, line in enumerate(sf.text.decode("utf-8", errors="replace").splitlines(), 1):
            hit = next(((label, m) for label, rx in _TOKEN_PATTERNS
                        for m in [rx.search(line)] if m), None)
            if hit:
                label, m = hit
                masked = line.replace(m.group(0), m.group(0)[:4] + "***")
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


class SqlStringBuild(Rule):
    id = "P004"  # emits P004 and P005
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
        if needs_dynamic and not self._is_dynamic(node):
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

    def _is_dynamic(self, node) -> bool:
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type in self.profile.sql_dynamic_types:
                return True
            stack.extend(cur.named_children)
        return False

    def _enclosing_sink(self, node) -> str | None:
        cur = node.parent
        while cur is not None:
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

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for i, line in enumerate(sf.text.decode("utf-8", errors="replace").splitlines(), 1):
            m = _SMELLS.search(line)
            if m:
                out.append(_mk_finding(self.id, self.severity, self.title, sf, i,
                                       line.strip(), f"Marker '{m.group(0)}' suggests "
                                       "incomplete/demo-grade code left by generation."))
        return out


def common_rules(profile) -> list[Rule]:
    return [EmptyCatch(profile), SecretsRule(), SqlStringBuild(profile), SmellComments()]


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

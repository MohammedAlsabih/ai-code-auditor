from __future__ import annotations

import re

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_RAW_SQL_APIS = re.compile(r"(FromSqlRaw|ExecuteSqlRaw|SqlQueryRaw|SqlCommand)")


def _finding(rule: Rule, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule.id, severity=rule.severity, title=rule.title,
                   file=sf.rel, line=line_of(node), snippet=node_text(node)[:120],
                   detail=detail, language=sf.language, engine="auditor",
                   precision=rule.precision)


class AsyncVoidMethod(Rule):
    id = "D001"
    severity = Severity.YELLOW
    title = "async void method outside event handlers"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for m in captures("csharp", sf.tree.root_node, "(method_declaration) @m").get("m", []):
            mods = [node_text(c) for c in m.children if c.type == "modifier"]
            ret = m.child_by_field_name("returns") or m.child_by_field_name("type")
            if "async" not in mods or ret is None or node_text(ret) != "void":
                continue
            params = m.child_by_field_name("parameters")
            ptext = node_text(params) if params is not None else ""
            if "EventArgs" in ptext and "sender" in ptext:
                continue  # conventional event-handler signature
            out.append(_finding(self, sf, m,
                                "async void cannot be awaited and its exceptions crash the "
                                "process; return Task instead."))
        return out


class BlockingTaskWait(Rule):
    id = "D002"
    severity = Severity.YELLOW
    title = "Blocking on task (.Result / .Wait() / GetAwaiter().GetResult())"
    precision = "heuristic"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        root = sf.tree.root_node
        for node in captures("csharp", root, "(member_access_expression) @a").get("a", []):
            name = node.child_by_field_name("name")
            obj = node.child_by_field_name("expression")
            if name is None or obj is None:
                continue
            prop = node_text(name)
            objt = node_text(obj)
            async_obj = obj.type == "invocation_expression" and "Async" in objt
            if prop == "Result" and async_obj:
                out.append(_finding(self, sf, node,
                                    ".Result on an async call blocks the thread (deadlock risk); await it."))
            elif prop in ("Wait", "GetResult") and (async_obj or "GetAwaiter" in objt):
                out.append(_finding(self, sf, node.parent if node.parent is not None else node,
                                    "Synchronous wait on a task (deadlock risk); use await."))
        return out


class RawSqlInterpolation(Rule):
    id = "D003"
    severity = Severity.RED
    title = "Interpolated/concatenated SQL passed to raw-SQL API"
    precision = "heuristic"

    # B2.8C-A: judge the SQL STRING argument itself, never the whole argument
    # list — `SqlQueryRaw("... {0} ...", (object?)x ?? DBNull.Value)` uses EF
    # positional placeholders with SEPARATE parameter args; the `??` in a
    # PARAMETER is not SQL composition. A dynamic SQL argument is cleared only
    # when the provenance analysis proves every part trusted (EF model
    # metadata, consts, literal-arg local helpers).
    _STRINGY = ("string_literal", "verbatim_string_literal",
                "raw_string_literal", "interpolated_string_expression",
                "binary_expression", "identifier", "conditional_expression",
                "parenthesized_expression", "invocation_expression")

    @staticmethod
    def _invoked_name(fn) -> str:
        """The name of the method THIS call invokes — for a member access,
        the final member only. `db.Database.SqlQueryRaw(...).FirstOrDefaultAsync(ct)`
        must never classify the OUTER FirstOrDefaultAsync call as a raw-SQL
        API just because the receiver text mentions one (that would judge
        `ct` as the SQL argument)."""
        if fn.type in ("member_access_expression", "member_binding_expression"):
            name = fn.child_by_field_name("name")
            return node_text(name) if name is not None else node_text(fn)
        return node_text(fn)

    def check(self, sf: SourceFile) -> list[Finding]:
        from auditor.adapters.dotnet.sql_trust import trusted_sql_expr
        out = []
        for call in captures("csharp", sf.tree.root_node, "(invocation_expression) @i").get("i", []):
            fn = call.child_by_field_name("function")
            if fn is None or not _RAW_SQL_APIS.search(self._invoked_name(fn)):
                continue
            args = call.child_by_field_name("arguments")
            if args is None or not args.named_children:
                continue
            sql_arg = next((a.named_children[0] for a in args.named_children
                            if a.named_children
                            and a.named_children[0].type in self._STRINGY), None)
            if sql_arg is None:
                continue
            if sql_arg.type in ("string_literal", "verbatim_string_literal",
                                "raw_string_literal"):
                continue                      # constant SQL (+ separate params)
            # closing round: an IDENTIFIER SQL argument is resolved to its
            # local initializer — literal/trusted composition is safe, but a
            # parameter, member, external call, or unknown initializer is a
            # raw-SQL sink fed by unproven text: D003 (heuristic).
            if sql_arg.type == "identifier":
                from auditor.adapters.dotnet.sql_trust import local_initializer
                init = local_initializer(sql_arg, sf)
                if init is not None and (
                        init.type in ("string_literal",
                                      "verbatim_string_literal",
                                      "raw_string_literal")
                        or trusted_sql_expr(init, sf)):
                    continue
                out.append(_finding(self, sf, call,
                                    "Raw-SQL API receives a variable whose SQL text "
                                    "cannot be proven constant — SQL injection risk; "
                                    "use parameters (e.g. FromSqlInterpolated or "
                                    "SqlParameter)."))
                continue
            # a non-identifier argument must itself contain interpolation/
            # concat; separate parameter arguments after the SQL are never
            # judged as SQL
            dynamic = False
            stack = [sql_arg]
            while stack:
                cur = stack.pop()
                if cur.type in ("interpolation", "binary_expression"):
                    dynamic = True
                    break
                stack.extend(cur.named_children)
            if not dynamic:
                continue
            if trusted_sql_expr(sql_arg, sf):
                continue                      # provably trusted composition
            out.append(_finding(self, sf, call,
                                "Raw-SQL API receives interpolated/concatenated input — "
                                "SQL injection; use parameters (e.g. FromSqlInterpolated "
                                "or SqlParameter)."))
        return out


# ── Rule Capability Catalog (owned HERE) ────────────────────────────────────
from auditor.core.catalog import RuleDescriptor as _RD  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

from typing import Any as _Any  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

_D: "dict[str, _Any]" = dict(category="dotnet", engine="pattern-engine", scope="file",
          source="builtin", languages=("csharp",))
DESCRIPTORS = [
    _RD("D001", "async void method",
        "async void methods hide exceptions from callers; use async Task.",
        default_level="warning", default_precision="exact", **_D),
    _RD("D002", "Blocking on async (.Result/.Wait)",
        ".Result/.Wait() on tasks risks deadlocks in sync contexts.",
        default_level="warning", default_precision="exact", **_D),
    _RD("D003", "Raw SQL string interpolation",
        "Interpolated/concatenated strings flow into raw SQL APIs.",
        default_level="error", default_precision="exact", **_D),
]

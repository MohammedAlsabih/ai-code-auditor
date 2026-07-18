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

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call in captures("csharp", sf.tree.root_node, "(invocation_expression) @i").get("i", []):
            fn = call.child_by_field_name("function")
            if fn is None or not _RAW_SQL_APIS.search(node_text(fn)):
                continue
            args = call.child_by_field_name("arguments")
            if args is None:
                continue
            dynamic = False
            stack = list(args.named_children)
            while stack:
                cur = stack.pop()
                if cur.type in ("interpolation", "binary_expression"):
                    dynamic = True
                    break
                stack.extend(cur.named_children)
            if dynamic:
                out.append(_finding(self, sf, call,
                                    "Raw-SQL API receives interpolated/concatenated input — "
                                    "SQL injection; use parameters (e.g. FromSqlInterpolated "
                                    "or SqlParameter)."))
        return out

from __future__ import annotations

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_RESOURCE_TYPES = frozenset({
    "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
    "BufferedReader", "BufferedWriter", "Scanner", "PrintWriter",
    "Socket", "ServerSocket", "RandomAccessFile",
})


def _finding(rule: Rule, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule.id, severity=rule.severity, title=rule.title,
                   file=sf.rel, line=line_of(node), snippet=node_text(node)[:120],
                   detail=detail, language=sf.language, engine="auditor",
                   precision=rule.precision)


class StringEqualsCompare(Rule):
    id = "J001"
    severity = Severity.YELLOW
    title = "String compared with =="

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for node in captures("java", sf.tree.root_node, "(binary_expression) @b").get("b", []):
            op = node.child_by_field_name("operator")
            if op is None or node_text(op) not in ("==", "!="):
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if any(n is not None and n.type == "string_literal" for n in (left, right)):
                out.append(_finding(self, sf, node,
                                    "== compares object identity, not content; use .equals()."))
        return out


class MissingTryWithResources(Rule):
    id = "J002"
    severity = Severity.YELLOW
    title = "Resource opened without try-with-resources"
    precision = "heuristic"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for node in captures("java", sf.tree.root_node,
                             "(object_creation_expression) @o").get("o", []):
            type_node = node.child_by_field_name("type")
            if type_node is None:
                continue
            simple = node_text(type_node).split(".")[-1]
            if simple not in _RESOURCE_TYPES:
                continue
            cur = node.parent
            in_resources = False
            while cur is not None:
                if cur.type == "resource_specification":
                    in_resources = True
                    break
                cur = cur.parent
            if not in_resources:
                out.append(_finding(self, sf, node,
                                    f"new {simple}(...) outside try-with-resources; the handle "
                                    "leaks if an exception occurs before close()."))
        return out

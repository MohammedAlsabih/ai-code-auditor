"""Standalone prototype of the planned tree-sitter React rules.

Source of truth: <repo>\\docs\\superpowers\\plans\\2026-07-17-ai-code-auditor-mvp.md
  - Task 3  -> tree-sitter helpers (get_language/get_parser/parse_source/captures/node_text/line_of)
  - Task 12 -> R001 HookInConditional, R002 HookInNestedCallback, R003 HookOutsideComponent + helpers
  - Task 13 -> R004/R005 EffectDeps (+_component_reactive_names)
  - Task 14 -> N003 ClientApiInServerComponent + has_use_client (used only for the nextdemo run)

ADAPTATIONS vs the plan (recorded for the report; algorithms untouched):
  A1. `from auditor.core...` imports replaced by inlined models (Severity, Finding,
      SourceFile) and a minimal Rule base class — structural only.
  A2. Task 3 get_language() trimmed to the "typescript"/"tsx" branches (only
      tree-sitter-typescript is installed in this venv). Branch bodies verbatim.
  A3. A __main__ runner (scan/emit JSON) appended — not part of any plan rule.
Any *algorithm* change forced by grammar/API reality must be logged in ADAPTATION_LOG.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from tree_sitter import Language, Parser, Query, QueryCursor

ADAPTATION_LOG: list[str] = []  # runtime-discovered mismatches get appended here

# --------------------------------------------------------------------------
# Inlined models (plan Task 2, trimmed to fields the rules touch)  [A1]
# --------------------------------------------------------------------------


class Severity(str, Enum):
    RED = "red"
    YELLOW = "yellow"
    BLUE = "blue"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    file: str
    line: int
    snippet: str = ""
    detail: str = ""
    language: str = ""
    engine: str = "auditor"


@dataclass
class SourceFile:
    path: Path
    rel: str
    language: str
    text: bytes
    tree: object | None = None


class Rule:
    id: str
    severity: Severity
    title: str
    frameworks: tuple[str, ...] = ()


# --------------------------------------------------------------------------
# Task 3: tree-sitter helpers (verbatim; get_language trimmed per [A2])
# --------------------------------------------------------------------------

_LANGS: dict[str, Language] = {}


def get_language(name: str) -> Language:
    if name not in _LANGS:
        if name == "typescript":
            import tree_sitter_typescript as mod
            ptr = mod.language_typescript()
        elif name == "tsx":
            import tree_sitter_typescript as mod
            ptr = mod.language_tsx()
        else:
            raise ValueError(f"unsupported tree-sitter language: {name}")
        _LANGS[name] = Language(ptr)
    return _LANGS[name]


def get_parser(name: str) -> Parser:
    return Parser(get_language(name))


def parse_source(sf: SourceFile) -> None:
    if sf.tree is None:
        sf.tree = get_parser(sf.language).parse(sf.text)


def captures(lang_name: str, node, query_src: str) -> dict[str, list]:
    query = Query(get_language(lang_name), query_src)
    return QueryCursor(query).captures(node)


def node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def line_of(node) -> int:
    return node.start_point[0] + 1


# --------------------------------------------------------------------------
# Task 12: helpers + R001, R002, R003 (verbatim)
# --------------------------------------------------------------------------

_HOOK_RE = re.compile(r"^use[A-Z]")
_FUNC_TYPES = frozenset({
    "function_declaration", "function_expression", "arrow_function",
    "method_definition", "generator_function", "generator_function_declaration",
})
_CONTROL_TYPES = frozenset({
    "if_statement", "for_statement", "for_in_statement", "while_statement",
    "do_statement", "switch_statement", "ternary_expression", "try_statement",
    "catch_clause",
})
_CALL_QUERY = "(call_expression function: (identifier) @callee)"


def is_hook_name(name: str) -> bool:
    return bool(_HOOK_RE.match(name))


def enclosing_functions(node) -> list:
    chain = []
    cur = node.parent
    while cur is not None:
        if cur.type in _FUNC_TYPES:
            chain.append(cur)
        cur = cur.parent
    return chain


def function_name(fn_node) -> str:
    name = fn_node.child_by_field_name("name")
    if name is not None:
        return node_text(name)
    parent = fn_node.parent
    if parent is not None and parent.type == "variable_declarator":
        ident = parent.child_by_field_name("name")
        if ident is not None:
            return node_text(ident)
    if parent is not None and parent.type == "pair":
        key = parent.child_by_field_name("key")
        if key is not None:
            return node_text(key)
    return ""


def hook_calls(sf: SourceFile) -> list[tuple[object, str]]:
    out = []
    for callee in captures(sf.language, sf.tree.root_node, _CALL_QUERY).get("callee", []):
        name = node_text(callee)
        if is_hook_name(name):
            out.append((callee.parent, name))  # call_expression node
    return out


def _finding(rule: Rule, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule.id, severity=rule.severity, title=rule.title,
                   file=sf.rel, line=line_of(node), snippet=node_text(node)[:120],
                   detail=detail, language=sf.language, engine="auditor")


class HookInConditional(Rule):
    id = "R001"
    severity = Severity.RED
    title = "React hook called conditionally (if/loop/ternary/try)"
    frameworks = ("react",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            boundary = fns[0] if fns else None
            cur = call.parent
            while cur is not None and cur is not boundary:
                if cur.type in _CONTROL_TYPES:
                    out.append(_finding(self, sf, call,
                                        f"{name} is called inside a {cur.type.replace('_', ' ')}; "
                                        "hooks must run unconditionally at the top level."))
                    break
                cur = cur.parent
        return out


class HookInNestedCallback(Rule):
    id = "R002"
    severity = Severity.RED
    title = "React hook called inside a callback argument of another hook"
    frameworks = ("react",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            if not fns:
                continue
            inner = fns[0]
            args = inner.parent  # arrow passed directly as an argument?
            if args is not None and args.type == "arguments":
                outer_call = args.parent
                callee = outer_call.child_by_field_name("function")
                if callee is not None and callee.type == "identifier" \
                        and is_hook_name(node_text(callee)):
                    out.append(_finding(self, sf, call,
                                        f"{name} runs inside the callback of "
                                        f"{node_text(callee)}; move it to component top level."))
        return out


class HookOutsideComponent(Rule):
    id = "R003"
    severity = Severity.YELLOW
    title = "Hook call in a non-component, non-hook function"
    frameworks = ("react",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            if not fns:
                continue
            named = next((function_name(fn) for fn in fns if function_name(fn)), "")
            if named and not (named[0].isupper() or is_hook_name(named)):
                out.append(_finding(self, sf, call,
                                    f"{name} is called from '{named}', which is neither a "
                                    "component (Capitalized) nor a custom hook (use*)."))
        return out


# --------------------------------------------------------------------------
# Task 13: R004/R005 EffectDeps (verbatim)
# --------------------------------------------------------------------------

_EFFECT_NAMES = frozenset({"useEffect", "useLayoutEffect"})
_IDENT_QUERY = "(identifier) @id"
_GLOBALS = frozenset({
    "console", "window", "document", "Math", "JSON", "Object", "Array",
    "Promise", "fetch", "localStorage", "setTimeout", "setInterval",
    "clearTimeout", "clearInterval", "undefined", "NaN", "Infinity",
})


def _component_reactive_names(fn_node, lang: str) -> set[str]:
    """useState firsts + destructured props of the function."""
    names: set[str] = set()
    params = fn_node.child_by_field_name("parameters")
    if params is not None:
        for pat in captures(lang, params, "(shorthand_property_identifier_pattern) @p").get("p", []):
            names.add(node_text(pat))
    for decl in captures(lang, fn_node, "(variable_declarator) @d").get("d", []):
        value = decl.child_by_field_name("value")
        name = decl.child_by_field_name("name")
        if value is None or name is None or value.type != "call_expression":
            continue
        callee = value.child_by_field_name("function")
        if callee is not None and node_text(callee) == "useState" and name.type == "array_pattern":
            idents = [c for c in name.named_children if c.type == "identifier"]
            if idents:
                names.add(node_text(idents[0]))
    return names


class EffectDeps(Rule):
    id = "R004"  # emits R004 and R005
    severity = Severity.YELLOW
    title = "useEffect dependency-array problems"
    frameworks = ("react",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            if name not in _EFFECT_NAMES:
                continue
            args = call.child_by_field_name("arguments")
            arg_nodes = [] if args is None else args.named_children
            if not arg_nodes:
                continue
            callback = arg_nodes[0]
            if len(arg_nodes) < 2:
                f = _finding(self, sf, call,
                             f"{name} has no dependency array; it re-runs after every render.")
                out.append(Finding(**{**f.__dict__, "rule_id": "R004",
                                      "title": "useEffect without dependency array"}))
                continue
            deps_node = arg_nodes[1]
            if deps_node.type != "array":
                continue
            deps = {node_text(c) for c in deps_node.named_children if c.type == "identifier"}
            fns = enclosing_functions(call)
            component = fns[-1] if fns else None
            if component is None:
                continue
            reactive = _component_reactive_names(component, sf.language)
            used = {node_text(n) for n in
                    captures(sf.language, callback, _IDENT_QUERY).get("id", [])}
            missing = sorted((used & reactive) - deps - _GLOBALS)
            if missing:
                f = _finding(self, sf, call,
                             f"{name} reads {', '.join(missing)} but its dependency array "
                             f"only lists [{', '.join(sorted(deps))}].")
                out.append(Finding(**{**f.__dict__, "rule_id": "R005",
                                      "title": "useEffect with obviously missing dependencies"}))
        return out


# --------------------------------------------------------------------------
# Task 14 (module-graph demo only): has_use_client + N003 (verbatim)
# --------------------------------------------------------------------------

_KNOWN_HOOKS = frozenset({
    "useState", "useEffect", "useLayoutEffect", "useReducer", "useRef",
    "useCallback", "useMemo", "useContext", "useTransition", "useDeferredValue",
    "useOptimistic", "useSyncExternalStore", "useImperativeHandle",
    "useInsertionEffect",
})


def has_use_client(sf: SourceFile) -> bool:
    for child in sf.tree.root_node.named_children[:3]:
        if child.type == "expression_statement" and child.named_children \
                and child.named_children[0].type == "string":
            if node_text(child.named_children[0]).strip("'\"") == "use client":
                return True
    return False


class ClientApiInServerComponent(Rule):
    id = "N003"
    severity = Severity.RED
    title = "Client-only API used in a Server Component (missing \"use client\")"
    frameworks = ("next",)

    _EVENT_ATTR = re.compile(r"^on[A-Z]")

    def check(self, sf: SourceFile) -> list[Finding]:
        parts = sf.rel.split("/")
        if "app" not in parts[:2] or has_use_client(sf):
            return []
        out = []
        for call, name in hook_calls(sf):
            if name in _KNOWN_HOOKS:
                out.append(_finding(self, sf, call,
                                    f"{name} requires a Client Component; add \"use client\" "
                                    "or move this logic into a client child."))
        for attr in captures(sf.language, sf.tree.root_node,
                             "(jsx_attribute (property_identifier) @n)").get("n", []):
            if self._EVENT_ATTR.match(node_text(attr)):
                out.append(_finding(self, sf, attr.parent,
                                    f"{node_text(attr)} event handlers only work in Client "
                                    "Components; this file has no \"use client\" directive."))
        return out


# --------------------------------------------------------------------------
# Runner [A3]
# --------------------------------------------------------------------------

REACT_RULES: list[Rule] = [HookInConditional(), HookInNestedCallback(),
                           HookOutsideComponent(), EffectDeps()]


def scan(root: Path, rules: list[Rule]) -> dict:
    results: dict[str, dict] = {}
    for p in sorted(root.rglob("*.tsx")):
        rel = p.relative_to(root).as_posix()
        sf = SourceFile(path=p, rel=rel, language="tsx", text=p.read_bytes())
        parse_source(sf)
        findings = []
        for rule in rules:
            for f in rule.check(sf):
                findings.append({"rule_id": f.rule_id, "line": f.line,
                                 "snippet": f.snippet, "detail": f.detail})
        findings.sort(key=lambda d: (d["line"], d["rule_id"]))
        results[rel] = {"parse_error": sf.tree.root_node.has_error, "findings": findings}
    return results


def main() -> None:
    import tree_sitter, tree_sitter_typescript
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "corpus"
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).parent / "prototype-results.json"
    with_n003 = "--with-n003" in sys.argv
    rules = REACT_RULES + ([ClientApiInServerComponent()] if with_n003 else [])
    results = scan(root, rules)
    payload = {
        "versions": {
            "python": sys.version.split()[0],
            "tree_sitter": getattr(tree_sitter, "__version__", "unknown"),
            "tree_sitter_typescript": getattr(tree_sitter_typescript, "__version__", "unknown"),
        },
        "rules": [r.id for r in rules],
        "adaptation_log": ADAPTATION_LOG,
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

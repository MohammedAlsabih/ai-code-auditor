from __future__ import annotations

import re

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

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
_LOGICAL_OPS = frozenset({"&&", "||", "??"})
_CALL_QUERY = "(call_expression function: (identifier) @callee)"


def _is_conditional_ancestor(node) -> bool:
    """Control-flow node, including short-circuit logic (`cond && useX()`),
    which the TSX grammar represents as binary_expression."""
    if node.type in _CONTROL_TYPES:
        return True
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        return op is not None and node_text(op) in _LOGICAL_OPS
    return False


def _has_earlier_return(call, boundary) -> bool:
    """Heuristic (corpus-proven FN otherwise): does any statement BEFORE the
    hook call, at any block level inside the enclosing function, contain a
    return? Catches `if (x) return null; ... useState()`. The walk NEVER
    descends into nested functions — a `return` inside a prior callback
    (`if (x) { run(() => { return 1; }) }`) must not be falsely flagged."""
    cur = call
    while cur is not None and cur is not boundary:
        parent = cur.parent
        if parent is not None and parent.type == "statement_block":
            for sibling in parent.named_children:
                if sibling == cur:
                    break
                if sibling.type == "return_statement":
                    return True
                if sibling.type == "if_statement" and any(
                        n.type == "return_statement"
                        for n in _walk_no_functions(sibling)):
                    return True
        cur = parent
    return False


def _walk_no_functions(node):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(c for c in cur.named_children if c.type not in _FUNC_TYPES)


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
                   detail=detail, language=sf.language, engine="auditor",
                   precision=rule.precision)


class HookInConditional(Rule):
    id = "R001"
    severity = Severity.RED
    title = "React hook called conditionally (if/loop/ternary/logical/try, or after early return)"
    frameworks = ("react",)
    precision = "heuristic"   # the early-return part is sibling-scan, not CFG
    # Intentional divergence, documented: hooks inside try/catch ARE flagged here.
    # eslint-plugin-react-hooks 7.1.1 stays silent on try/catch (corpus-verified),
    # but react.dev/reference/rules/rules-of-hooks explicitly forbids it.

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            boundary = fns[0] if fns else None
            cur = call.parent
            flagged = False
            while cur is not None and cur is not boundary:
                if _is_conditional_ancestor(cur):
                    out.append(_finding(self, sf, call,
                                        f"{name} is called inside a {cur.type.replace('_', ' ')}; "
                                        "hooks must run unconditionally at the top level."))
                    flagged = True
                    break
                cur = cur.parent
            if not flagged and boundary is not None and _has_earlier_return(call, boundary):
                out.append(_finding(self, sf, call,
                                    f"{name} is called after a possible early return; hooks "
                                    "must run on every render (heuristic sibling-scan)."))
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
    # Judge the INNERMOST enclosing function (corpus FN class: hooks inside
    # event-handler arrows, .map callbacks, promise callbacks were invisible when
    # we skipped anonymous functions and accepted the outer Capitalized component).

    # Empirically verified: an arrow passed to memo/forwardRef IS the component
    # body — without this exemption the rule false-flags every
    # `const Btn = memo(() => ...)`.
    _COMPONENT_WRAPPERS = frozenset({"memo", "forwardRef", "React.memo", "React.forwardRef"})

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            if not fns:
                continue
            inner = fns[0]
            inner_name = function_name(inner)
            if inner_name and (inner_name[0].isupper() or is_hook_name(inner_name)):
                continue  # component body or custom hook — legal
            wrapper = self._wrapping_callee(inner)
            if wrapper is not None and is_hook_name(wrapper):
                continue  # `useEffect(() => useX())` — R002 owns that case
            if wrapper in self._COMPONENT_WRAPPERS:
                continue  # memo/forwardRef-wrapped component body — legal
            where = f"'{inner_name}'" if inner_name else "an anonymous callback"
            out.append(_finding(self, sf, call,
                                f"{name} is called from {where}, which is neither a "
                                "component (Capitalized) nor a custom hook (use*); hooks "
                                "cannot run inside event handlers or nested callbacks."))
        return out

    @staticmethod
    def _wrapping_callee(fn_node) -> str | None:
        """Callee name of the call this function is a DIRECT argument of."""
        args = fn_node.parent
        if args is None or args.type != "arguments":
            return None
        callee = args.parent.child_by_field_name("function")
        return node_text(callee) if callee is not None else None


REACT_RULES: list[Rule] = [HookInConditional(), HookInNestedCallback(), HookOutsideComponent()]

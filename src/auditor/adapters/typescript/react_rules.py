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
# both a bare `useState(...)` and a member `React.useState(...)` / `hooks.useX(...)`
# — CP-8.4: member-expression hook callees were previously invisible
_CALL_QUERY = """
[
  (call_expression function: (identifier) @callee)
  (call_expression function: (member_expression property: (property_identifier) @callee))
]
"""


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


def is_hook_callee(callee) -> bool:
    """THE shared hook predicate (react_rules + N006), matching
    eslint-plugin-react-hooks 7.1.1 LITERALLY: a bare `useX` identifier, or a
    member `<Obj>.useX` whose object is a plain IDENTIFIER that is either
    `React` or PascalCase. This rejects `api.useState` (lowercase object),
    `r.useState` (lowercase alias — ESLint diverges here too), AND
    `api.Hooks.useState` (object is a member_expression, not an Identifier)."""
    if not is_hook_name(node_text(callee)):
        return False
    parent = callee.parent
    if parent is not None and parent.type == "member_expression":
        obj = parent.child_by_field_name("object")
        if obj is None or obj.type != "identifier":
            return False   # nested member (api.Hooks.useState) => object not an Identifier
        name = node_text(obj)
        return name == "React" or name[:1].isupper()
    return True   # bare identifier callee


def hook_calls(sf: SourceFile) -> list[tuple]:
    """(call_expression node, hook name) pairs. Bare `useX(...)` and member
    `React.useX(...)`/`Hooks.useX(...)` count; `api.useX(...)`,
    `api.Hooks.useX(...)`, and lowercase-alias `r.useX(...)` do not — literal
    ESLint 7.1.1 semantics. Walk up to the enclosing call_expression."""
    out = []
    for callee in captures(sf.language, sf.tree.root_node, _CALL_QUERY).get("callee", []):
        if not is_hook_callee(callee):
            continue
        name = node_text(callee)
        call = callee
        while call is not None and call.type != "call_expression":
            call = call.parent
        if call is not None:
            out.append((call, name))
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


_EFFECT_NAMES = frozenset({"useEffect", "useLayoutEffect"})
_IDENT_QUERY = "(identifier) @id"
_JSX_ATTR_QUERY = "(jsx_attribute (property_identifier) @name)"
_GLOBALS = frozenset({
    "console", "window", "document", "Math", "JSON", "Object", "Array",
    "Promise", "fetch", "localStorage", "setTimeout", "setInterval",
    "clearTimeout", "clearInterval", "undefined", "NaN", "Infinity",
})


def _component_reactive_names(fn_node, lang: str, exclude=None) -> set[str]:
    """useState firsts + destructured props of the component function.
    `exclude`: subtree to ignore (the effect callback itself) — corpus-proven FP:
    a useState declared INSIDE the callback is not a missing dependency."""
    def _inside_exclude(node) -> bool:
        return exclude is not None and \
            node.start_byte >= exclude.start_byte and node.end_byte <= exclude.end_byte

    names: set[str] = set()
    params = fn_node.child_by_field_name("parameters")
    if params is not None:
        for pat in captures(lang, params, "(shorthand_property_identifier_pattern) @p").get("p", []):
            names.add(node_text(pat))
    for decl in captures(lang, fn_node, "(variable_declarator) @d").get("d", []):
        if _inside_exclude(decl):
            continue
        value = decl.child_by_field_name("value")
        name = decl.child_by_field_name("name")
        if value is None or name is None or value.type != "call_expression":
            continue
        callee = value.child_by_field_name("function")
        if callee is not None and node_text(callee).split(".")[-1] == "useState" \
                and name.type == "array_pattern":
            idents = [c for c in name.named_children if c.type == "identifier"]
            if idents:
                names.add(node_text(idents[0]))
    return names


class EffectDeps(Rule):
    id = "R004"  # emits R004 and R005
    severity = Severity.YELLOW
    title = "useEffect dependency-array problems"
    frameworks = ("react",)
    precision = "heuristic"
    # R004 intentionally diverges from exhaustive-deps (which ignores a missing
    # deps argument BY DESIGN): the project spec explicitly requires flagging
    # useEffect without a dependency array. Yellow, never red.

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
            reactive = _component_reactive_names(component, sf.language, exclude=callback)
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


class IndexAsKey(Rule):
    id = "R006"
    severity = Severity.YELLOW
    title = "List key uses array index"
    frameworks = ("react",)

    def check(self, sf: SourceFile) -> list[Finding]:
        if sf.language != "tsx":
            return []   # jsx_attribute exists only in the tsx grammar
        out = []
        for attr_name in captures(sf.language, sf.tree.root_node, _JSX_ATTR_QUERY).get("name", []):
            if node_text(attr_name) != "key":
                continue
            attr = attr_name.parent
            expr = next((c for c in attr.named_children if c.type == "jsx_expression"), None)
            if expr is None or not expr.named_children:
                continue
            value = expr.named_children[0]
            if value.type != "identifier":
                continue
            key_name = node_text(value)
            map_param = self._second_map_param(attr)
            if key_name == map_param or (map_param is None and key_name in ("index", "i", "idx")):
                out.append(_finding(self, sf, attr,
                                    f"key={{{key_name}}} is the .map() index; reordering or "
                                    "deleting items will confuse React reconciliation."))
        return out

    @staticmethod
    def _second_map_param(node) -> str | None:
        cur = node.parent
        while cur is not None:
            if cur.type in ("arrow_function", "function_expression"):
                call = cur.parent
                if call is not None and call.type == "arguments":
                    call = call.parent
                if call is not None and call.type == "call_expression":
                    callee = call.child_by_field_name("function")
                    if callee is not None and callee.type == "member_expression":
                        prop = callee.child_by_field_name("property")
                        if prop is not None and node_text(prop) == "map":
                            params = cur.child_by_field_name("parameters")
                            if params is not None:
                                idents = [c for c in params.named_children
                                          if c.type in ("identifier", "required_parameter")]
                                names = []
                                for p in idents:
                                    names.append(node_text(p.child_by_field_name("pattern"))
                                                 if p.type == "required_parameter" else node_text(p))
                                if len(names) >= 2:
                                    return names[1]
            cur = cur.parent
        return None


class DangerousInnerHtml(Rule):
    id = "R007"
    severity = Severity.RED
    title = "dangerouslySetInnerHTML with a non-literal value"
    frameworks = ("react",)
    precision = "heuristic"   # CP-8.5: syntactic only — no taint/sanitizer analysis

    _LITERAL_TYPES = frozenset({"string", "template_string", "number"})

    def check(self, sf: SourceFile) -> list[Finding]:
        if sf.language != "tsx":
            return []   # jsx_attribute exists only in the tsx grammar
        out = []
        for attr_name in captures(sf.language, sf.tree.root_node, _JSX_ATTR_QUERY).get("name", []):
            if node_text(attr_name) != "dangerouslySetInnerHTML":
                continue
            attr = attr_name.parent
            # CP-8.5: flag UNLESS the value is PROVABLY { __html: <string/number
            # literal without interpolation> }. So `={expr}` (an identifier),
            # `={{__html: x}}` (non-literal), and `={{...spread}}` (spread —
            # contents unknown) are all flagged; only the proven literal is clean.
            if not self._is_provably_literal(sf, attr):
                out.append(_finding(self, sf, attr,
                                    "__html is not a proven string literal; any user-influenced "
                                    "content here is an XSS vector (heuristic — no taint analysis)."))
        return out

    def _is_provably_literal(self, sf: SourceFile, attr) -> bool:
        expr = next((c for c in attr.named_children if c.type == "jsx_expression"), None)
        if expr is None:
            return False
        obj = next((c for c in expr.named_children), None)   # the {__html: ...} object
        if obj is None or obj.type != "object":
            return False   # `={identifier}`, ternary, call, etc. — not provable
        members = [c for c in obj.named_children]
        if not members or any(m.type == "spread_element" for m in members):
            return False   # a spread hides whether __html is a literal
        html_seen = False
        for pair in members:
            if pair.type != "pair":
                return False
            key = pair.child_by_field_name("key")
            if key is None or node_text(key).strip("'\"") != "__html":
                return False   # only a lone __html key is provable
            val = pair.child_by_field_name("value")
            if val is None or val.type not in self._LITERAL_TYPES:
                return False
            if captures(sf.language, val, "(template_substitution) @s").get("s"):
                return False   # `${...}` interpolation is dynamic
            html_seen = True
        return html_seen


REACT_RULES: list[Rule] = [HookInConditional(), HookInNestedCallback(),
                           HookOutsideComponent(), EffectDeps(), IndexAsKey(),
                           DangerousInnerHtml()]

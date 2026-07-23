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


# B2.8C1 (closing): the two proven R003 false-positive classes, both proven
# from the AST — never a file-level regex boolean. `renderHook` must resolve
# to a REAL @testing-library import binding (respecting alias + shadowing);
# a Storybook `render` must be a real Story render (an exported story object's
# property), not any property named render.
def _import_bindings(sf) -> dict:
    """local binding name -> (imported_name, source) from this file's import
    declarations. `import { renderHook }` -> renderHook maps to
    ('renderHook', spec); `import { x as y }` -> y maps to ('x', spec);
    default/namespace imports map to ('default'/'*', spec). Keeping the
    ORIGINAL imported name lets callers require the real export, so
    `import { somethingElse as renderHook }` is NOT accepted as renderHook."""
    out: dict[str, tuple[str, str]] = {}
    root = sf.tree.root_node
    for imp in captures(sf.language, root, "(import_statement) @i").get("i", []):
        src = imp.child_by_field_name("source")
        spec = node_text(src).strip("'\"`") if src is not None else ""
        if not spec:
            continue
        for named in captures(sf.language, imp, "(import_specifier) @s").get("s", []):
            name = named.child_by_field_name("name")
            alias = named.child_by_field_name("alias")
            imported = node_text(name) if name is not None else ""
            local = node_text(alias) if alias is not None else imported
            if local and imported:
                out[local] = (imported, spec)
        for clause in captures(sf.language, imp,
                               "(import_clause (identifier) @d)").get("d", []):
            out[node_text(clause)] = ("default", spec)
        for ns in captures(sf.language, imp,
                           "(namespace_import (identifier) @n)").get("n", []):
            out[node_text(ns)] = ("*", spec)
    return out


def _direct_scope_decls(fn_node, lang: str) -> set:
    """Names declared DIRECTLY in this function's own lexical scope — its
    parameters and the top-level statements of its body. Deliberately does NOT
    descend into nested functions or the bodies of nested blocks/other
    functions, so a `const renderHook` inside a sibling/nested function does
    not shadow this scope. A same-scope declaration counts even if it appears
    textually after the use (block scoping is lexical, not positional)."""
    names: set[str] = set()
    params = fn_node.child_by_field_name("parameters")
    if params is not None:
        for p in captures(lang, params, "(identifier) @p").get("p", []):
            names.add(node_text(p))
    body = fn_node.child_by_field_name("body")
    if body is not None and body.type == "statement_block":
        for stmt in body.named_children:
            if stmt.type in ("lexical_declaration", "variable_declaration"):
                for d in stmt.named_children:
                    if d.type == "variable_declarator":
                        n = d.child_by_field_name("name")
                        if n is not None and n.type == "identifier":
                            names.add(node_text(n))
            elif stmt.type == "function_declaration":
                n = stmt.child_by_field_name("name")
                if n is not None:
                    names.add(node_text(n))
    return names


def _is_shadowed(name: str, at_node, lang: str) -> bool:
    """True when `name` is re-declared in a function scope enclosing the use —
    lexically, i.e. in that scope's own params/top-level declarations (never
    inside a nested/sibling function). Module scope keeps the import."""
    cur = at_node.parent
    while cur is not None:
        if cur.type in _FUNC_TYPES and name in _direct_scope_decls(cur, lang):
            return True
        cur = cur.parent
    return False


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

    _TESTING_LIB_RE = re.compile(r"^@testing-library/")
    _STORYBOOK_RE = re.compile(r"^@storybook/")

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        imports = _import_bindings(sf)
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
            # B2.8C1 (closing): a renderHook(() => useX()) callback is a hook
            # test context ONLY when the callee resolves to a real
            # @testing-library import binding AND is not shadowed by a local of
            # the same name in an enclosing scope.
            if wrapper is not None and inner.parent is not None \
                    and self._is_testing_lib_renderhook(inner, wrapper, imports, sf):
                continue
            # B2.8C1 (closing): a Storybook `render` is a component context only
            # when it is the render property of an EXPORTED story object — mere
            # presence of a @storybook import never exempts a local helper.
            if inner_name == "render" \
                    and self._is_exported_story_render(inner, imports, sf):
                continue
            where = f"'{inner_name}'" if inner_name else "an anonymous callback"
            out.append(_finding(self, sf, call,
                                f"{name} is called from {where}, which is neither a "
                                "component (Capitalized) nor a custom hook (use*); hooks "
                                "cannot run inside event handlers or nested callbacks."))
        return out

    _STORY_TYPE_RE = re.compile(r"\b(?:Story|StoryObj|Meta|StoryFn)\b")

    def _is_testing_lib_renderhook(self, fn_node, wrapper, imports, sf) -> bool:
        binding = imports.get(wrapper)
        if binding is None:
            return False
        imported_name, spec = binding
        # the EXPORT must actually be `renderHook` (reject
        # `import { somethingElse as renderHook }`) from a @testing-library pkg
        if imported_name != "renderHook" or not self._TESTING_LIB_RE.match(spec):
            return False
        call = fn_node.parent.parent if fn_node.parent is not None else None
        if call is None or call.type != "call_expression":
            return False
        return not _is_shadowed(wrapper, call, sf.language)

    def _is_exported_story_render(self, fn_node, imports, sf) -> bool:
        parent = fn_node.parent
        if parent is None or parent.type != "pair":
            return False   # not an object property at all
        has_sb = any(self._STORYBOOK_RE.match(spec)
                     for _imported, spec in imports.values()) \
            or ".stories." in sf.rel
        if not has_sb:
            return False
        obj = parent.parent
        if obj is None or obj.type != "object":
            return False
        # A Storybook import + an export is NOT enough. Require ACTUAL story
        # evidence: (a) a Story/StoryObj/Meta type annotation or a
        # `satisfies StoryObj/Story` on the declaration, OR (b) the module has
        # a `export default` meta (a proven CSF module) AND this object is an
        # exported named binding (a story). A bare `export const helper = {
        # render }` with no annotation and no meta stays R003.
        exported = self._exported_declarator(obj)
        if exported is not None:
            if self._has_story_type_evidence(exported):
                return True
            if self._module_has_default_export(sf):
                return True    # CSF module: named exports are stories
        return False

    @staticmethod
    def _exported_declarator(obj):
        """The variable_declarator whose value is `obj`, IF that declaration is
        exported — else None."""
        cur = obj.parent
        hops = 0
        while cur is not None and hops < 6:
            hops += 1
            if cur.type == "variable_declarator":
                decl = cur.parent
                if decl is not None and decl.parent is not None \
                        and decl.parent.type == "export_statement":
                    return cur
                return None
            if cur.type in ("object", "pair", "parenthesized_expression",
                            "satisfies_expression", "as_expression"):
                cur = cur.parent
                continue
            return None
        return None

    def _has_story_type_evidence(self, declarator) -> bool:
        # a `: Story`/`: StoryObj`/`: Meta` type annotation on the declarator
        type_node = declarator.child_by_field_name("type")
        if type_node is not None and self._STORY_TYPE_RE.search(node_text(type_node)):
            return True
        # or `= { ... } satisfies StoryObj`
        value = declarator.child_by_field_name("value")
        if value is not None and value.type == "satisfies_expression" \
                and self._STORY_TYPE_RE.search(node_text(value)):
            return True
        return False

    @staticmethod
    def _module_has_default_export(sf) -> bool:
        for exp in captures(sf.language, sf.tree.root_node,
                            "(export_statement) @e").get("e", []):
            txt = node_text(exp)
            if txt.startswith("export default") or "export default" in txt[:40]:
                return True
        return False

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


def _member_path(node) -> str | None:
    """A normalized member path for a dependency-array entry, or None when the
    entry is not a plain identifier/member chain (a call, computed `[...]`
    access, spread, etc. — which cannot be reasoned about). `client?.costModel`
    and `client.costModel` both normalize to 'client.costModel'."""
    t = node.type
    if t == "identifier":
        return node_text(node)
    if t in ("member_expression",):
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if prop is None or prop.type != "property_identifier":
            return None                 # computed member: obj[expr]
        base = _member_path(obj)
        return f"{base}.{node_text(prop)}" if base is not None else None
    if t in ("parenthesized_expression", "non_null_expression"):
        inner = next(iter(node.named_children), None)
        return _member_path(inner) if inner is not None else None
    return None


def _path_covers(dep: str, read: str) -> bool:
    """A dependency path covers a read path when it is the read or a prefix of
    it: [client] covers client.costModel; [client.costModel] covers
    client.costModel; [client.other] does not."""
    return dep == read or read.startswith(dep + ".")


def _read_paths(callback, lang: str, bases: set[str]) -> dict[str, set[str]]:
    """For every reactive `base` name read inside the callback, the set of
    member paths actually read. A bare use of `base`, or a use whose full path
    cannot be resolved (it is an argument to a call, a computed access, etc.),
    contributes the base path itself — so it needs whole-object coverage."""
    out: dict[str, set[str]] = {}
    for ident in captures(lang, callback, _IDENT_QUERY).get("id", []):
        base = node_text(ident)
        if base not in bases:
            continue
        # climb member_expression parents while THIS node is the .object side
        # (compare by byte-range: tree-sitter re-wraps nodes, so `is` fails)
        path = base
        cur = ident
        parent = cur.parent
        while parent is not None and parent.type == "member_expression":
            obj = parent.child_by_field_name("object")
            if obj is None or (obj.start_byte, obj.end_byte) != \
                    (cur.start_byte, cur.end_byte):
                break                   # cur is the .property side, not .object
            prop = parent.child_by_field_name("property")
            if prop is None or prop.type != "property_identifier":
                break                   # computed access — stop at the base path
            path = f"{path}.{node_text(prop)}"
            cur = parent
            parent = cur.parent
        out.setdefault(base, set()).add(path)
    return out


class EffectDeps(Rule):
    id = "R004"  # emits R004 and R005
    output_ids = ("R004", "R005")
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
            # B2.8C1: dependencies and reads are compared as MEMBER PATHS, not
            # base identifiers. `[client.costModel]` / `[client?.costModel]`
            # cover a read of client.costModel; `[client]` covers it too
            # (broader); `[client.other]` does not. A read whose path cannot be
            # resolved (computed access / call result) is treated conservatively
            # as reading the base object — it is only covered by a whole-object
            # dependency, never silenced without evidence.
            dep_paths = {p for c in deps_node.named_children
                         if (p := _member_path(c)) is not None}
            fns = enclosing_functions(call)
            component = fns[-1] if fns else None
            if component is None:
                continue
            reactive = _component_reactive_names(component, sf.language, exclude=callback)
            read_paths = _read_paths(callback, sf.language, reactive)
            missing_bases: set[str] = set()
            for base, paths in read_paths.items():
                if base in _GLOBALS:
                    continue
                for rp in paths:
                    if not any(_path_covers(dp, rp) for dp in dep_paths):
                        missing_bases.add(base)
                        break
            missing = sorted(missing_bases)
            if missing:
                shown = sorted(p for p in dep_paths if p) or ["(none)"]
                f = _finding(self, sf, call,
                             f"{name} reads {', '.join(missing)} but its dependency array "
                             f"only lists [{', '.join(shown)}].")
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


# B2.8C-B (closing round): the safety index travels ON each SourceFile
# (`sf._r007_safety`, attached by TypeScriptAdapter.prepare via
# dom_safety.attach_index) — no mutable module global, so interleaved
# projects can never leak proofs into each other. Proofs are file-scoped
# inside the index itself: a name is safe in THIS file only if proven here
# or imported from the file that proved it.
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
            # literal without interpolation> }. B2.8C-B adds two structural
            # proofs: DOMPurify-sanitized values (real import + direct-return
            # wrapper, incl. through useMemo), and hex-gated CSS builders when
            # the element is <style> (a CSS context, judged separately from
            # HTML). A sanitize-ish NAME alone never counts.
            if self._is_provably_literal(sf, attr):
                continue
            if self._is_proven_sanitized(sf, attr):
                continue
            if self._is_style_element(attr) and self._is_css_safe_value(sf, attr):
                continue
            out.append(_finding(self, sf, attr,
                                "__html is not a proven string literal; any user-influenced "
                                "content here is an XSS vector (heuristic — no taint analysis)."))
        return out

    # ---- B2.8C-B helpers -----------------------------------------------------
    @staticmethod
    def _html_value(attr):
        expr = next((c for c in attr.named_children if c.type == "jsx_expression"), None)
        if expr is None or not expr.named_children:
            return None
        obj = expr.named_children[0]
        if obj.type != "object":
            return None
        for pair in obj.named_children:
            if pair.type == "pair":
                key = pair.child_by_field_name("key")
                if key is not None and node_text(key).strip("'\"") == "__html":
                    return pair.child_by_field_name("value")
        return None

    @staticmethod
    def _is_style_element(attr) -> bool:
        opening = attr.parent
        if opening is None or opening.type != "jsx_opening_element":
            # self-closing: jsx_self_closing_element carries attributes directly
            if opening is None or opening.type != "jsx_self_closing_element":
                return False
        name = opening.child_by_field_name("name")
        return name is not None and node_text(name) == "style"

    def _resolve_call_or_ident(self, sf: SourceFile, val):
        """The __html value as evidence tokens: called function NAMES, the
        marker "<direct>" for a real `DOMPurify.sanitize(...)` member call,
        or "" for any unresolvable part (which poisons the proof). One
        identifier hop through its declaration; useMemo unwrapped."""
        from auditor.adapters.typescript.dom_safety import is_direct_sanitize_call
        names: list[str] = []
        nodes = [val]
        hops = 0
        while nodes and hops < 6:
            hops += 1
            cur = nodes.pop()
            if cur is None:
                continue
            if cur.type == "call_expression":
                fn = cur.child_by_field_name("function")
                ftext = node_text(fn) if fn is not None else ""
                if ftext in ("useMemo", "React.useMemo"):
                    args = cur.child_by_field_name("arguments")
                    cb = args.named_children[0] if args is not None and args.named_children else None
                    if cb is not None and cb.type in ("arrow_function", "function_expression"):
                        nodes.append(cb.child_by_field_name("body"))
                    continue
                if is_direct_sanitize_call(cur, sf):
                    names.append("<direct>")
                    continue
                if fn is not None and fn.type == "identifier":
                    names.append(ftext)
                continue
            if cur.type == "identifier":
                decl_value = self._declaration_value(sf, node_text(cur))
                if decl_value is not None:
                    nodes.append(decl_value)
                continue
            if cur.type in ("binary_expression", "parenthesized_expression",
                            "ternary_expression"):
                for k in cur.named_children:
                    if k.type in ("string",):
                        continue
                    nodes.append(k)
                continue
            if cur.type == "statement_block":
                for r in captures(sf.language, cur, "(return_statement) @r").get("r", []):
                    if r.named_children:
                        nodes.append(r.named_children[0])
                continue
            if cur.type == "string":
                continue
            names.append("")   # unresolvable part — poisons the proof
        return names

    @staticmethod
    def _declaration_value(sf: SourceFile, name: str):
        for d in captures(sf.language, sf.tree.root_node,
                          "(variable_declarator) @d").get("d", []):
            n = d.child_by_field_name("name")
            if n is not None and node_text(n) == name:
                return d.child_by_field_name("value")
        return None

    def _is_proven_sanitized(self, sf: SourceFile, attr) -> bool:
        idx = getattr(sf, "_r007_safety", None)
        val = self._html_value(attr)
        if val is None:
            return False
        names = self._resolve_call_or_ident(sf, val)
        if not names:
            return False
        for n in names:
            if n == "<direct>":
                continue                      # proven DOMPurify.sanitize call
            if idx is None or not idx.is_dompurify_safe(sf.rel, n):
                return False
        return True

    def _is_css_safe_value(self, sf: SourceFile, attr) -> bool:
        idx = getattr(sf, "_r007_safety", None)
        if idx is None:
            return False
        val = self._html_value(attr)
        if val is None:
            return False
        names = self._resolve_call_or_ident(sf, val)
        return bool(names) and all(
            n != "" and n != "<direct>" and idx.is_css_safe(sf.rel, n)
            for n in names)

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


# ── Rule Capability Catalog (owned HERE; the R004 check emits R004 AND R005 —
#    each id is described separately) ───────────────────────────────────────
from auditor.core.catalog import RuleDescriptor as _RD  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

from typing import Any as _Any  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

_R: "dict[str, _Any]" = dict(category="react", engine="pattern-engine", scope="file",
          source="builtin", languages=("typescript", "tsx"),
          frameworks=("react",))
DESCRIPTORS = [
    _RD("R001", "Conditional hook call",
        "A React hook is called inside if/loop/ternary/&&/try or after an early return.",
        default_level="error", default_precision="heuristic", **_R),
    _RD("R002", "Hook inside a hook callback",
        "A hook is called inside a callback passed to another hook.",
        default_level="error", default_precision="heuristic", **_R),
    _RD("R003", "Hook outside component or custom hook",
        "A hook is called from a function that is neither a component nor a use* hook (memo/forwardRef exempt).",
        default_level="warning", default_precision="heuristic", **_R),
    _RD("R004", "useEffect without dependency array",
        "An effect omits its dependency array and re-runs on every render.",
        default_level="warning", default_precision="heuristic", **_R),
    _RD("R005", "Obviously missing effect dependencies",
        "Identifiers used inside the effect are absent from its dependency array.",
        default_level="warning", default_precision="heuristic", **_R),
    _RD("R006", "List key uses array index",
        "key={index} defeats React reconciliation for reorderable lists.",
        default_level="warning", default_precision="exact", **_R),
    _RD("R007", "Non-literal dangerouslySetInnerHTML",
        "dangerouslySetInnerHTML receives a non-literal __html value (XSS vector pattern).",
        default_level="error", default_precision="heuristic", **_R),
]

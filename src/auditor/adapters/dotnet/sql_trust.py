"""C# SQL-provenance analysis (W2-B2.8C-A).

Answers ONE question about an expression that builds SQL text: is every part
of it PROVABLY compile-time-constant or derived from a trusted, non-user
source inside this file? Trusted sources are deliberately narrow:

- string literals (regular / verbatim / raw), and concatenation of trusted
  parts;
- interpolated strings whose EVERY hole is trusted;
- `const` fields/locals and `nameof(...)`;
- EF Core MODEL METADATA (table/schema/column names come from the compiled
  model, not from input): expressions mentioning `.Model` /
  `GetEntityTypes()` / `GetTableName()` / `GetSchema()` / `GetColumnName()` /
  `FindProperty()`;
- locals whose initializer is trusted (recursively), including foreach
  variables over a trusted collection (e.g. tuples deconstructed from an EF
  metadata query or from an array of trusted tuples);
- invocations of a LOCAL helper (defined in the same file) where EVERY call
  site in the file passes only literal arguments AND the helper's own return
  expressions are trusted when its parameters are assumed trusted (the
  `Scoped("\"Code\"")` pattern).

Anything else — parameters, method arguments, external calls, member reads —
is UNTRUSTED, so `$"...{userInput}..."` and `"SELECT..." + variable` keep
firing. This is a per-file analysis with a hard node/depth budget: when the
budget is exceeded the answer is False (fail open to DETECTION, never to
silence).
"""
from __future__ import annotations

from typing import Any

from auditor.core.treesitter import captures, node_text

_LITERAL_TYPES = frozenset({
    "string_literal", "verbatim_string_literal", "raw_string_literal",
    "integer_literal", "real_literal", "character_literal",
    "boolean_literal", "null_literal",
})
# EF model metadata: table/schema/column names from the compiled model.
# Proven on the ACCESS SPINE only (the chain of receivers/members actually
# invoked) — metadata appearing merely as an ARGUMENT to some other call
# (`Build(user, db.Model)`) never launders that call's result.
_EF_METHODS = frozenset({"GetEntityTypes", "GetTableName", "GetSchema",
                         "GetColumnName", "FindProperty", "GetDefaultSchema"})
_EF_PROPERTIES = frozenset({"Model"})
_MAX_STEPS = 4000
_MAX_DEPTH = 48


class _FileIndex:
    """Per-file maps built once: local declarations, const names, local
    functions, foreach bindings."""

    def __init__(self, sf) -> None:
        root = sf.tree.root_node
        self.decls: dict[str, Any] = {}
        self.const_names: set[str] = set()
        self.local_funcs: dict[str, Any] = {}
        self.foreach_of: dict[str, Any] = {}
        for decl in captures("csharp", root, "(variable_declarator) @d").get("d", []):
            name_node = decl.child_by_field_name("name") or next(
                (c for c in decl.named_children if c.type == "identifier"), None)
            init = next((c for c in decl.named_children
                         if c is not name_node and c.type != "identifier"), None)
            if name_node is None:
                continue
            name = node_text(name_node)
            if init is not None and name not in self.decls:
                self.decls[name] = init
            parent = decl.parent
            hops = 0
            while parent is not None and hops < 4:
                if "const" in [c.type for c in parent.children] or \
                        any(node_text(c) == "const" for c in parent.children
                            if c.type == "modifier"):
                    self.const_names.add(name)
                    break
                parent = parent.parent
                hops += 1
        for fn in captures("csharp", root,
                           "(local_function_statement) @f").get("f", []) + \
                captures("csharp", root, "(method_declaration) @f").get("f", []):
            n = fn.child_by_field_name("name")
            if n is not None:
                self.local_funcs.setdefault(node_text(n), fn)
        for fe in captures("csharp", root, "(foreach_statement) @f").get("f", []):
            right = fe.child_by_field_name("right")
            left = fe.child_by_field_name("left")
            if right is None:
                continue
            names: list[str] = []
            if left is not None:
                if left.type == "identifier":
                    names.append(node_text(left))
                else:
                    for ident in captures("csharp", left, "(identifier) @i").get("i", []):
                        names.append(node_text(ident))
            else:
                # older grammar shape: identifiers between 'var' and 'in'
                for ident in captures("csharp", fe, "(identifier) @i").get("i", []):
                    if ident.end_byte < right.start_byte:
                        names.append(node_text(ident))
            for name in names:
                self.foreach_of.setdefault(name, right)


def _index(sf) -> _FileIndex:
    idx = getattr(sf, "_sql_trust_index", None)
    if idx is None:
        idx = _FileIndex(sf)
        sf._sql_trust_index = idx
    return idx


def trusted_sql_expr(node, sf) -> bool:
    """True iff `node` is provably constant/trusted per the module contract."""
    state = {"steps": 0}
    return _trusted(node, sf, _index(sf), frozenset(), 0, state)


def _budget(state) -> bool:
    state["steps"] += 1
    return state["steps"] <= _MAX_STEPS


def _trusted(node, sf, idx: _FileIndex, assumed: frozenset,
             depth: int, state) -> bool:
    if node is None or depth > _MAX_DEPTH or not _budget(state):
        return False
    t = node.type
    if t in _LITERAL_TYPES:
        return True
    if t in ("interpolated_string_expression",):
        for child in node.named_children:
            if child.type == "interpolation":
                if not _trusted(_interp_expr(child), sf, idx, assumed,
                                depth + 1, state):
                    return False
        return True
    if t == "interpolation":
        return _trusted(_interp_expr(node), sf, idx, assumed, depth + 1, state)
    if t == "binary_expression":
        kids = node.named_children
        return len(kids) == 2 and all(
            _trusted(k, sf, idx, assumed, depth + 1, state) for k in kids)
    if t in ("parenthesized_expression", "cast_expression", "checked_expression"):
        inner = node.named_children[-1] if node.named_children else None
        return _trusted(inner, sf, idx, assumed, depth + 1, state)
    if t == "conditional_expression":
        # only the RESULT branches flow into the string; the condition does not
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        return _trusted(cons, sf, idx, assumed, depth + 1, state) and \
            _trusted(alt, sf, idx, assumed, depth + 1, state)
    if t in ("tuple_expression", "array_creation_expression",
             "implicit_array_creation_expression", "initializer_expression",
             "collection_expression"):
        return all(_trusted(k, sf, idx, assumed, depth + 1, state)
                   for k in node.named_children)
    if t == "identifier":
        name = node_text(node)
        if name in assumed or name in idx.const_names:
            return True
        if name in idx.decls:
            return _trusted(idx.decls[name], sf, idx, assumed, depth + 1, state)
        if name in idx.foreach_of:
            coll = idx.foreach_of[name]
            if _trusted(coll, sf, idx, assumed, depth + 1, state):
                return True
            return _spine_has_ef(coll)
        return False
    if t in ("invocation_expression",):
        if node_text(node).startswith("nameof("):
            return True
        if _spine_has_ef(node):
            return True
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "identifier":
            return _trusted_local_helper_call(node, node_text(fn), sf, idx,
                                              depth, state)
        return False
    if t in ("member_access_expression", "conditional_access_expression"):
        return _spine_has_ef(node)
    return False


def _interp_expr(interp):
    """The EXPRESSION inside an interpolation hole — skipping the brace and
    format/alignment clause nodes that the grammar also exposes as named."""
    return next((c for c in interp.named_children
                 if c.type not in ("interpolation_brace",
                                   "interpolation_alignment_clause",
                                   "interpolation_format_clause")), None)


def _spine_has_ef(node) -> bool:
    """AST proof: walk the ACCESS SPINE (function of an invocation, receiver
    of a member access) looking for an EF metadata method/property. Argument
    subtrees are deliberately never entered — `Build(user, db.Model)` has no
    EF member on its spine and stays untrusted."""
    cur = node
    hops = 0
    while cur is not None and hops < 64:
        hops += 1
        t = cur.type
        if t == "invocation_expression":
            cur = cur.child_by_field_name("function")
            continue
        if t in ("member_access_expression", "member_binding_expression"):
            name = cur.child_by_field_name("name")
            if name is not None:
                txt = node_text(name)
                if txt in _EF_METHODS or txt in _EF_PROPERTIES:
                    return True
            cur = cur.child_by_field_name("expression")
            continue
        if t == "conditional_access_expression":
            return any(_spine_has_ef(k) for k in cur.named_children)
        if t == "parenthesized_expression":
            cur = next(iter(cur.named_children), None)
            continue
        return False
    return False


def local_initializer(node, sf):
    """The initializer expression of a local/field identifier, or None when
    the name has no visible declaration in this file (parameter, out-var,
    external)."""
    if node is None or node.type != "identifier":
        return None
    return _index(sf).decls.get(node_text(node))


def _literal_only_args(call) -> bool:
    args = call.child_by_field_name("arguments")
    if args is None:
        return True
    for arg in args.named_children:
        inner = next(iter(arg.named_children), arg)
        if inner.type not in _LITERAL_TYPES:
            return False
    return True


def _trusted_local_helper_call(call, name: str, sf, idx: _FileIndex,
                               depth: int, state) -> bool:
    """The Scoped(...) pattern: a helper DEFINED IN THIS FILE, where EVERY
    call site in the file passes literal-only arguments, and whose return
    expressions are trusted when its parameters are assumed trusted."""
    fn = idx.local_funcs.get(name)
    if fn is None:
        return False
    for other in captures("csharp", sf.tree.root_node,
                          "(invocation_expression) @i").get("i", []):
        f = other.child_by_field_name("function")
        if f is not None and f.type == "identifier" and node_text(f) == name:
            if not _literal_only_args(other):
                return False
    params: set[str] = set()
    plist = fn.child_by_field_name("parameters")
    if plist is not None:
        for p in plist.named_children:
            pn = p.child_by_field_name("name")
            if pn is not None:
                params.add(node_text(pn))
    assumed = frozenset(params)
    body = fn.child_by_field_name("body")
    returns = []
    if body is not None:
        if body.type == "arrow_expression_clause":
            returns = list(body.named_children)
        else:
            returns = [r.named_children[0]
                       for r in captures("csharp", body, "(return_statement) @r").get("r", [])
                       if r.named_children]
    elif (arrow := next((c for c in fn.children
                         if c.type == "arrow_expression_clause"), None)) is not None:
        returns = list(arrow.named_children)
    if not returns:
        return False
    return all(_trusted(r, sf, idx, assumed, depth + 1, state) for r in returns)

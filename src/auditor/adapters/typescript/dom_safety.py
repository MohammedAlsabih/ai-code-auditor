"""Project-level sanitizer/CSS-safety index for R007 (W2-B2.8C-B, hardened in
the closing round).

Proofs are SCOPED, never name-global: a proof belongs to the FILE that
establishes it, and another file may use it only through a real import whose
module specifier resolves to that file. `clean()` proven safe in lib/safe.tsx
never clears a different `clean()` defined in app/evil.tsx.

1. DOMPurify-safe functions: the DEFINING file imports DOMPurify from
   `dompurify` / `isomorphic-dompurify`, and the function's every return is a
   plain string literal or a direct `DOMPurify.sanitize(...)` call on that
   import.

2. CSS-safe builders (for `<style>` elements only): the defining file binds
   an ANCHORED hex-only regex to a name (`const HEX = /^#[0-9a-fA-F]{6}$/`),
   and every value interpolated into the builder's CSS output is a literal, a
   literal-branch ternary, or a value routed through a REAL hex gate — a
   ternary whose condition tests THAT regex (`HEX.test(x)`), whose kept
   branch is the tested value (or a literal), and whose fallback is inert.
   A `.test()` on some other regex, or a gate that returns its input on both
   branches, proves nothing. Assignments are last-write-wins.

The index is attached per-SourceFile by TypeScriptAdapter.prepare — there is
no mutable module-global, so interleaved projects cannot leak proofs into
each other. Analysis failure fails toward DETECTION.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from auditor.core.treesitter import captures, node_text, parse_source

_DOMPURIFY_MODULES = ("dompurify", "isomorphic-dompurify")
# an anchored, hex-only character-class regex literal
_ANCHORED_HEX_RE = re.compile(r"^/\^#\[0-9a-fA-F\]\{?[0-9,{}]*\}?\$/[a-z]*$")
_IMPORT_NAMED_RE = re.compile(
    r"import\s+(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s+from\s+['\"]([^'\"]+)['\"]")
_IMPORT_DEFAULT_RE = re.compile(
    r"import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s+['\"]([^'\"]+)['\"]")
_MAX_DEPTH = 24


@dataclass
class FileSafety:
    dompurify_safe: set[str] = field(default_factory=set)
    css_safe: set[str] = field(default_factory=set)
    imports: dict[str, str] = field(default_factory=dict)   # binding -> specifier


@dataclass
class SafetyIndex:
    files: dict[str, FileSafety] = field(default_factory=dict)  # keyed by sf.rel

    def _resolve(self, rel: str, name: str, kind: str) -> bool:
        fs = self.files.get(rel)
        if fs is None:
            return False
        local = fs.dompurify_safe if kind == "dompurify" else fs.css_safe
        if name in local:
            return True
        spec = fs.imports.get(name)
        if not spec:
            return False
        for other_rel, other in self.files.items():
            if other_rel == rel or not _module_matches(other_rel, spec):
                continue
            pool = other.dompurify_safe if kind == "dompurify" else other.css_safe
            if name in pool:
                return True
        return False

    def is_dompurify_safe(self, rel: str, name: str) -> bool:
        return self._resolve(rel, name, "dompurify")

    def is_css_safe(self, rel: str, name: str) -> bool:
        return self._resolve(rel, name, "css")


EMPTY_INDEX = SafetyIndex()


def _module_matches(rel: str, spec: str) -> bool:
    """Does file `rel` (project-relative) provide module specifier `spec`?
    Alias/relative prefixes are dropped; the remaining path tail must match
    the file path (extension-less). Conservative: no match = no proof."""
    parts = [p for p in spec.split("/")
             if p not in (".", "..", "", "@") and not p.startswith("@")]
    if spec.startswith("@") and "/" in spec and not spec.startswith("@/"):
        return False        # a scoped npm package is never a project file
    if not parts:
        return False
    stem = rel.rsplit(".", 1)[0]
    tail = "/".join(parts)
    return stem == tail or stem.endswith("/" + tail)


def build_safety_index(files) -> SafetyIndex:
    idx = SafetyIndex()
    for sf in files:
        if sf.language not in ("typescript", "tsx"):
            continue
        try:
            parse_source(sf)
            idx.files[sf.rel] = _index_file(sf)
        except Exception:  # noqa: BLE001 — an unparsable file adds no proofs
            continue
    return idx


def attach_index(files, idx: SafetyIndex) -> None:
    """Per-SourceFile context (no mutable global): each file carries the
    project's index; proofs stay scoped by the index's own file keys."""
    for sf in files:
        sf._r007_safety = idx


def _index_file(sf) -> FileSafety:
    out = FileSafety()
    text = sf.text.decode("utf-8", errors="replace")
    for m in _IMPORT_NAMED_RE.finditer(text):
        spec = m.group(2)
        for piece in m.group(1).split(","):
            piece = piece.strip()
            if not piece:
                continue
            binding = piece.split(" as ")[-1].strip()
            if binding:
                out.imports[binding] = spec
    for m in _IMPORT_DEFAULT_RE.finditer(text):
        out.imports.setdefault(m.group(1), m.group(2))
    fns = _named_functions(sf)
    has_dompurify = dompurify_import_name(text) is not None
    hex_names = _hex_regex_names(sf)
    gate_fns = _hex_gate_functions(sf, fns, hex_names) if hex_names else set()
    for name, (_params, body) in fns.items():
        if has_dompurify and _returns_only_sanitize_or_literal(sf, body, text):
            out.dompurify_safe.add(name)
        if hex_names and _css_safe_function(sf, body, gate_fns, hex_names):
            out.css_safe.add(name)
    return out


def dompurify_import_name(text: str) -> str | None:
    for mod in _DOMPURIFY_MODULES:
        m = re.search(rf"import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+"
                      rf"['\"]{mod}['\"]", text)
        if m:
            return m.group(1)
    return None


def _named_functions(sf) -> dict[str, tuple[object, object]]:
    """name -> (parameters, body) for function declarations + const arrows."""
    out: dict[str, tuple[object, object]] = {}
    root = sf.tree.root_node
    for fn in captures(sf.language, root, "(function_declaration) @f").get("f", []):
        name = fn.child_by_field_name("name")
        body = fn.child_by_field_name("body")
        if name is not None and body is not None:
            out[node_text(name)] = (fn.child_by_field_name("parameters"), body)
    for decl in captures(sf.language, root,
                         "(variable_declarator) @d").get("d", []):
        name = decl.child_by_field_name("name")
        value = decl.child_by_field_name("value")
        if name is not None and value is not None and \
                value.type in ("arrow_function", "function_expression"):
            body = value.child_by_field_name("body")
            if body is not None:
                out[node_text(name)] = (value.child_by_field_name("parameters"),
                                        body)
    return out


# ---- proof 1: DOMPurify wrappers ------------------------------------------------

def is_direct_sanitize_call(node, sf) -> bool:
    """`<DOMPurifyImport>.sanitize(...)` where the receiver is the file's REAL
    dompurify import binding."""
    if node is None or node.type != "call_expression":
        return False
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "member_expression":
        return False
    obj = fn.child_by_field_name("object")
    prop = fn.child_by_field_name("property")
    imp = dompurify_import_name(sf.text.decode("utf-8", errors="replace"))
    return (imp is not None and obj is not None and prop is not None
            and node_text(obj) == imp and node_text(prop) == "sanitize")


def _returns_only_sanitize_or_literal(sf, body, text: str) -> bool:
    if body.type != "statement_block":       # expression-bodied arrow
        return is_direct_sanitize_call(body, sf) or body.type == "string"
    rets = captures(sf.language, body, "(return_statement) @r").get("r", [])
    if not rets:
        return False
    for r in rets:
        val = next(iter(r.named_children), None)
        if val is None:
            return False
        if val.type == "string" or is_direct_sanitize_call(val, sf):
            continue
        return False
    return True


# ---- proof 2: hex-gated CSS builders ---------------------------------------------

def _hex_regex_names(sf) -> set[str]:
    """Names bound to an ANCHORED hex-only regex literal in this file."""
    out: set[str] = set()
    for d in captures(sf.language, sf.tree.root_node,
                      "(variable_declarator) @d").get("d", []):
        n = d.child_by_field_name("name")
        v = d.child_by_field_name("value")
        if n is not None and v is not None and v.type == "regex" \
                and _ANCHORED_HEX_RE.match(node_text(v)):
            out.add(node_text(n))
    return out


def _gate_test_re(hex_names: set[str]) -> re.Pattern:
    alt = "|".join(re.escape(n) for n in sorted(hex_names))
    return re.compile(rf"\b(?:{alt})\s*\.\s*test\s*\(")


def _gated_ternary_ok(sf, tern, hex_names: set[str], params_text: str) -> bool:
    """`HEX.test(x…) ? <tested value or literal> : <inert fallback>` — THE
    anchored regex, the SAME value, and a constant fallback. Anything else
    (another regex, both branches returning the input) is not a gate."""
    kids = tern.named_children
    if len(kids) != 3:
        return False
    cond, cons, alt = kids
    if not _gate_test_re(hex_names).search(node_text(cond)):
        return False
    cons_txt = node_text(cons).strip()
    cons_ok = cons.type == "string" or (cons_txt and cons_txt in node_text(cond))
    if not cons_ok:
        return False
    if alt.type in ("string", "null", "undefined"):
        return True
    if alt.type == "identifier":
        # a parameter with a string-literal default (safeHex's `fallback`)
        return bool(re.search(rf"\b{re.escape(node_text(alt))}\s*(?::[^=]+)?="
                              rf"\s*['\"]", params_text))
    return False


def _hex_gate_functions(sf, fns, hex_names: set[str]) -> set[str]:
    """In-file gates (safeHex-style): the RETURN VALUE is a gated ternary on
    the file's anchored hex regex."""
    out: set[str] = set()
    for name, (params, body) in fns.items():
        params_text = node_text(params) if params is not None else ""
        exprs = []
        if body.type != "statement_block":
            exprs.append(body)
        else:
            for r in captures(sf.language, body, "(return_statement) @r").get("r", []):
                if r.named_children:
                    exprs.append(r.named_children[0])
        ok = bool(exprs)
        for e in exprs:
            while e is not None and e.type in ("parenthesized_expression",):
                e = next(iter(e.named_children), None)
            if e is None or e.type != "ternary_expression" \
                    or not _gated_ternary_ok(sf, e, hex_names, params_text):
                ok = False
                break
        if ok:
            out.add(name)
    return out


def _css_safe_function(sf, body, gate_fns: set[str], hex_names: set[str]) -> bool:
    bindings: dict[str, tuple[int, object]] = {}
    array_locals: set[str] = set()
    if body.type == "statement_block":
        for d in captures(sf.language, body, "(variable_declarator) @d").get("d", []):
            n = d.child_by_field_name("name")
            v = d.child_by_field_name("value")
            if n is not None and v is not None:
                key = node_text(n)
                if key not in bindings or d.start_byte > bindings[key][0]:
                    bindings[key] = (d.start_byte, v)
                if v.type == "array":
                    array_locals.add(key)
        for a in captures(sf.language, body, "(assignment_expression) @a").get("a", []):
            left = a.child_by_field_name("left")
            right = a.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                key = node_text(left)
                if key not in bindings or a.start_byte > bindings[key][0]:
                    bindings[key] = (a.start_byte, right)

    def safe(node, depth=0) -> bool:
        if node is None or depth > _MAX_DEPTH:
            return False
        t = node.type
        if t in ("string", "number", "null", "undefined"):
            return True
        if t == "template_string":
            return all(safe(next(iter(s.named_children), None), depth + 1)
                       for s in captures(sf.language, node,
                                         "(template_substitution) @s").get("s", []))
        if t == "binary_expression":
            return all(safe(k, depth + 1) for k in node.named_children)
        if t == "parenthesized_expression":
            return safe(next(iter(node.named_children), None), depth + 1)
        if t == "ternary_expression":
            if _gated_ternary_ok(sf, node, hex_names, ""):
                return True    # the anchored hex regex accepted the kept value
            kids = node.named_children
            return len(kids) == 3 and safe(kids[1], depth + 1) \
                and safe(kids[2], depth + 1)
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is None:
                return False
            if fn.type == "identifier" and node_text(fn) in gate_fns:
                return True                       # value passed a REAL hex gate
            if fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                obj = fn.child_by_field_name("object")
                if prop is not None and node_text(prop) == "join" \
                        and obj is not None and obj.type == "identifier" \
                        and node_text(obj) in array_locals:
                    return True   # parts were judged at their .push sites
            return False
        if t == "identifier":
            bound = bindings.get(node_text(node))
            return bound is not None and safe(bound[1], depth + 1)
        return False

    outputs: list = []
    if body.type == "statement_block":
        for r in captures(sf.language, body, "(return_statement) @r").get("r", []):
            v = next(iter(r.named_children), None)
            if v is not None:
                outputs.append(v)
        for call in captures(sf.language, body, "(call_expression) @c").get("c", []):
            fn = call.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                obj = fn.child_by_field_name("object")
                if prop is not None and node_text(prop) == "push" \
                        and obj is not None and node_text(obj) in array_locals:
                    args = call.child_by_field_name("arguments")
                    outputs.extend(args.named_children if args is not None else [])
    else:
        outputs.append(body)
    if not outputs:
        return False
    return all(safe(o) for o in outputs)

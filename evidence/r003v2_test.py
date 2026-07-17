"""Second-round review: test v2 R003 (innermost fn) + early-return heuristic
against the wrapper/nesting cases flagged in review, BEFORE freezing the design.

Self-contained rerun (any clean checkout):
    python -m venv venv && venv/Scripts/pip install "tree-sitter>=0.26,<0.27" "tree-sitter-typescript>=0.23.2,<0.24"
    venv/Scripts/python r003v2_test.py
Reference versions at original measurement (2026-07-17): tree-sitter 0.26.0,
tree-sitter-typescript 0.23.2, CPython 3.12.4, Windows 11."""
import re

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_typescript as tsts

LANG = Language(tsts.language_tsx())
PARSER = Parser(LANG)
HOOK_RE = re.compile(r"^use[A-Z]")
FUNC_TYPES = {"function_declaration", "function_expression", "arrow_function",
              "method_definition", "generator_function", "generator_function_declaration"}
WRAPPERS = {"memo", "forwardRef", "React.memo", "React.forwardRef"}

def text(n): return n.text.decode()

def hook_calls(root):
    caps = QueryCursor(Query(LANG, "(call_expression function: (identifier) @c)")).captures(root)
    return [(c.parent, text(c)) for c in caps.get("c", []) if HOOK_RE.match(text(c))]

def enclosing(node):
    out, cur = [], node.parent
    while cur is not None:
        if cur.type in FUNC_TYPES: out.append(cur)
        cur = cur.parent
    return out

def fn_name(fn):
    n = fn.child_by_field_name("name")
    if n is not None: return text(n)
    p = fn.parent
    if p is not None and p.type == "variable_declarator":
        i = p.child_by_field_name("name")
        if i is not None: return text(i)
    if p is not None and p.type == "pair":
        k = p.child_by_field_name("key")
        if k is not None: return text(k)
    return ""

def call_wrapping(fn):
    """Name of the call this fn is a direct argument of, else None."""
    args = fn.parent
    if args is None or args.type != "arguments": return None
    callee = args.parent.child_by_field_name("function")
    return text(callee) if callee is not None else None

def r003_v2(src, with_wrapper_exemption):
    tree = PARSER.parse(src.encode())
    out = []
    for call, name in hook_calls(tree.root_node):
        fns = enclosing(call)
        if not fns: continue
        inner = fns[0]
        nm = fn_name(inner)
        if nm and (nm[0].isupper() or HOOK_RE.match(nm)): continue
        wrap = call_wrapping(inner)
        if wrap and HOOK_RE.match(wrap): continue          # hook-arg -> R002's case
        if with_wrapper_exemption and wrap in WRAPPERS: continue
        out.append(name)
    return out

CASES = [
    ("memo_wrapped", "const Btn = memo(() => { const [v] = useState(0); return <b>{v}</b>; });", []),
    ("forwardref_wrapped", "const In = forwardRef((props, ref) => { const [v] = useState(0); return <input ref={ref}/>; });", []),
    ("react_memo_member", "const B = React.memo(() => { const [v] = useState(0); return null; });", []),
    ("named_arrow_component", "const Card = () => { const [v] = useState(0); return null; };", []),
    ("event_handler", "function B(){ return <button onClick={() => { const [v] = useState(0); }}/>; }", ["useState"]),
    ("map_callback", "function L({xs}){ return xs.map(() => useMemo(() => 1, [])); }", ["useMemo"]),
    ("custom_hook_arrow", "const useThing = () => { const [v] = useState(0); return v; };", []),
]

print("== R003 v2: WITHOUT wrapper exemption ==")
for name, src, expected in CASES:
    got = r003_v2(src, False)
    print(f"{name:24} got={got} expected={expected} {'OK' if got == expected else '** MISMATCH **'}")
print("== R003 v2: WITH wrapper exemption ==")
for name, src, expected in CASES:
    got = r003_v2(src, True)
    print(f"{name:24} got={got} expected={expected} {'OK' if got == expected else '** MISMATCH **'}")

# ---- early-return heuristic: nested-callback false positive check ----
def walk_no_fn(node):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(c for c in cur.named_children if c.type not in FUNC_TYPES)

def has_earlier_return(call, boundary, skip_fns):
    cur = call
    while cur is not None and cur is not boundary:
        p = cur.parent
        if p is not None and p.type == "statement_block":
            for sib in p.named_children:
                if sib.id == cur.id: break
                if sib.type == "return_statement": return True
                walker = walk_no_fn(sib) if skip_fns else _walk_all(sib)
                if any(n.type == "return_statement" for n in walker): return True
        cur = p
    return False

def _walk_all(node):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(cur.named_children)

ER_CASES = [
    ("true_early_return", "function C({x}){ if (x) return null; const [v] = useState(0); return <p/>; }", True),
    ("return_in_prior_callback", "function C(){ const f = items.filter(i => { return i > 1; }); const [v] = useState(0); return null; }", False),
    ("if_with_callback_return_only", "function C({x}){ if (x) { run(() => { return 1; }); } const [v] = useState(0); return null; }", False),
    ("nested_if_return", "function C({x,y}){ if (x) { if (y) return null; } const [v] = useState(0); return null; }", True),
]
for label, mode in (("naive _walk (v2 as written)", False), ("fn-boundary-aware _walk", True)):
    print(f"== early-return: {label} ==")
    for name, src, expected in ER_CASES:
        tree = PARSER.parse(src.encode())
        calls = hook_calls(tree.root_node)
        call = next(c for c, n in calls if n == "useState")
        boundary = enclosing(call)[0]
        got = has_earlier_return(call, boundary, skip_fns=mode)
        print(f"{name:28} got={got} expected={expected} {'OK' if got == expected else '** MISMATCH **'}")

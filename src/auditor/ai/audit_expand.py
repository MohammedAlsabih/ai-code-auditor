"""W3-E4A closing: deterministic, repository-confined cross-file expansion of
an audit unit's context, computed BEFORE the pack is finalized (so the whole
payload is decided at Preview and the privacy contract stays exact).

From each seed candidate we resolve, ONLY within RepositoryAuditIndex:
- local imports / path aliases -> the imported symbol's definition window;
- for a web route under the authorization query -> the project's middleware;
- a route/proxy path literal -> the backend endpoint that registers it, even
  in another project.

No free filesystem, no symlinks, no network. Depth, file count, and bytes are
bounded by explicit constants. Every added piece records provenance
(import / framework_middleware / route_target). A reference that cannot be
resolved inside the index becomes a STRUCTURED FACT in the context — the model
is never handed an arbitrary file to guess with.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from auditor.ai.audit_index import IndexedFile, RepositoryAuditIndex
from auditor.ai.audit_queries import AuditQuery

# explicit bounds
MAX_EXPAND_FILES = 4                # extra files added by expansion, at most
EXPAND_WINDOW = 25                  # lines of context around a resolved symbol
MAX_UNRESOLVED = 6                  # structured unresolved facts, at most

_TS_IMPORT = re.compile(
    r"""import\s+(?:(?P<names>[\w{}\*,\s]+?)\s+from\s+)?['"](?P<spec>[^'"]+)['"]""")
_PY_FROM = re.compile(r"""^\s*from\s+(?P<mod>[.\w]+)\s+import\s+(?P<names>[^\n#]+)""",
                      re.MULTILINE)
_CS_USING = re.compile(r"""^\s*using\s+(?P<ns>[\w.]+)\s*;""", re.MULTILINE)
# a quoted path STRING literal that looks like an HTTP route ('/api/...'): an
# EXACT route path.
_ROUTE_LIT = re.compile(r"""['"](/[A-Za-z0-9_./:-]{1,120})['"]""")
# a TEMPLATE literal whose static prefix is a path (`/api/auth/mfa/${seg}`): a
# route FAMILY. We keep the leading literal up to the first interpolation.
_ROUTE_TEMPLATE = re.compile(r"""`(/[A-Za-z0-9_./:-]{1,120}?)\$\{""")
_WEB_ROUTE_MARK = re.compile(
    r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b"
    r"|app\.(?:get|post|put|patch|delete)\s*\(")
# backend route REGISTRATIONS (Minimal API map + MVC attribute), capturing the
# registered route string so the match is a real registration — never mere
# co-occurrence of the path text somewhere in the file.
_BACKEND_MAP = re.compile(
    r"""(?:MapGet|MapPost|MapPut|MapDelete|MapPatch)\s*\(\s*(['"])(?P<r>[^'"]+)\1""")
_BACKEND_ATTR = re.compile(
    r"""\[\s*(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route)\s*\(\s*(['"])(?P<r>[^'"]*)\1""")


def _strip_cs_comments(text: str) -> str:
    """Remove C# // line and /* */ block comments, STRING-AWARE so a `//` or
    `/*` inside a string/char/verbatim literal is preserved (and so a
    registration commented out with `//` is never seen as real code). Newlines
    are kept so line numbers do not shift. Deterministic, no parser needed."""
    out: list[str] = []
    i, n = 0, len(text)
    state = "code"                       # code|line|block|str|verbatim|char
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line"
                i += 2
            elif ch == "/" and nxt == "*":
                state = "block"
                i += 2
            elif ch == "@" and nxt == '"':
                state = "verbatim"
                out.append('@"')
                i += 2
            else:
                if ch == '"':
                    state = "str"
                elif ch == "'":
                    state = "char"
                out.append(ch)
                i += 1
        elif state == "line":
            if ch == "\n":
                state = "code"
                out.append(ch)
            i += 1
        elif state == "block":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                if ch == "\n":
                    out.append("\n")
                i += 1
        elif state == "str":
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
            else:
                if ch == '"':
                    state = "code"
                i += 1
        elif state == "verbatim":
            out.append(ch)
            if ch == '"' and nxt == '"':      # "" is an escaped quote in @"..."
                out.append(nxt)
                i += 2
            else:
                if ch == '"':
                    state = "code"
                i += 1
        else:                            # char
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
            else:
                if ch == "'":
                    state = "code"
                i += 1
    return "".join(out)


def _endpoint_routes(text: str) -> set[str]:
    """The route strings a backend file actually REGISTERS (leading slash
    normalized). Comments are stripped first, so a registration commented out
    with `//` is NOT a registration; and only MapGet/[Http...] literals count,
    never a path that merely appears as free text elsewhere."""
    code = _strip_cs_comments(text)
    routes: set[str] = set()
    for rx in (_BACKEND_MAP, _BACKEND_ATTR):
        for m in rx.finditer(code):
            r = m.group("r")
            if r:
                routes.add(r if r.startswith("/") else "/" + r)
    return routes


def _route_prefix(raw: str) -> str | None:
    """The static, segment-aligned prefix of a template-literal route family.
    Trimmed to the last '/' so matching happens on a whole-segment boundary
    (`/api/auth/mfa/` never matches `/api/auth/mfargh`), and required to carry
    at least two path segments so a bare `/api/` can never link broadly."""
    if not raw.startswith("/"):
        return None
    p = raw if raw.endswith("/") else raw[:raw.rfind("/") + 1]
    return p if len([s for s in p.split("/") if s]) >= 2 else None


@dataclass(frozen=True)
class ExtraPiece:
    file: str
    spans: tuple[tuple[int, int], ...]
    provenance: str                 # import | framework_middleware | route_target


@dataclass(frozen=True)
class Unresolved:
    relation: str                   # import | route
    reference: str
    reason: str


def _sym_names(raw: str) -> list[str]:
    """Extract imported identifier names from an import clause."""
    out: list[str] = []
    for tok in re.split(r"[\s{},*]+", raw or ""):
        tok = tok.strip()
        if tok and tok not in ("import", "from", "as", "type", "default") \
                and re.fullmatch(r"[A-Za-z_]\w*", tok):
            out.append(tok)
    return out


def _windows_for(target: IndexedFile, names: list[str]) -> tuple[
        tuple[int, int], ...]:
    """Line windows around the definitions of `names` in the target (or the
    whole file if small / nothing matched)."""
    lines = target.text.splitlines()
    n = len(lines)
    if n == 0:
        return ((1, 1),)
    hits: list[int] = []
    lowered = [ln.casefold() for ln in lines]
    for i, ln in enumerate(lowered, start=1):
        if any(nm.casefold() in ln for nm in names):
            hits.append(i)
        if len(hits) >= 8:
            break
    if not hits or n <= EXPAND_WINDOW:
        return ((1, n),)
    spans: list[tuple[int, int]] = []
    for h in hits:
        lo, hi = max(1, h - EXPAND_WINDOW // 2), min(n, h + EXPAND_WINDOW // 2)
        if spans and lo <= spans[-1][1] + 1:
            spans[-1] = (spans[-1][0], max(spans[-1][1], hi))
        else:
            spans.append((lo, hi))
    return tuple(spans)


def _resolve_import(spec: str, seed_rel: str, project: str,
                    by_rel: dict[str, IndexedFile]) -> IndexedFile | None:
    """Resolve a LOCAL import spec to an indexed file. External packages
    (bare specifiers) return None (not unresolved — they are declared deps)."""
    proj = project.strip("/")
    seed_dir = seed_rel.rsplit("/", 1)[0] if "/" in seed_rel else ""
    bases: list[str] = []
    if spec.startswith("@/"):                       # Next '@/x' -> <project>/x
        bases.append(f"{proj}/{spec[2:]}" if proj not in ("", ".")
                     else spec[2:])
    elif spec.startswith("."):                      # relative
        parts = (seed_dir + "/" + spec).split("/")
        stack: list[str] = []
        for p in parts:
            if p in ("", "."):
                continue
            if p == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(p)
        bases.append("/".join(stack))
    else:
        return None                                 # external/bare specifier
    exts = ["", ".ts", ".tsx", ".js", ".jsx", ".py", ".cs",
            "/index.ts", "/index.tsx"]
    for base in bases:
        for ext in exts:
            cand = base + ext
            if cand in by_rel and cand != seed_rel:
                return by_rel[cand]
    return None


def _find_middleware(project: str,
                     by_rel: dict[str, IndexedFile]) -> IndexedFile | None:
    proj = project.strip("/")
    prefixes = [f"{proj}/" if proj not in ("", ".") else ""]
    for pre in prefixes:
        for name in ("middleware.ts", "middleware.tsx", "middleware.js",
                     "src/middleware.ts", "app/middleware.ts"):
            if pre + name in by_rel:
                return by_rel[pre + name]
    return None


def _find_route_target(needle: str, is_prefix: bool,
                       by_rel: dict[str, IndexedFile],
                       exclude: set[str]) -> IndexedFile | None:
    """A backend file (any project) that REGISTERS a route matching `needle` —
    exactly (string literal) or by static prefix (template-literal family).
    Matching is against the registered route strings only (via
    _endpoint_routes); a file that merely mentions the path in a comment while
    registering a DIFFERENT route is never matched."""
    for rel in sorted(by_rel):
        if rel in exclude:
            continue
        f = by_rel[rel]
        if f.language != "csharp":
            continue
        for route in _endpoint_routes(f.text):
            if route.startswith(needle) if is_prefix else route == needle:
                return f
    return None


def _is_web_route(seed: IndexedFile) -> bool:
    return seed.language == "typescript" and (
        "/route.ts" in seed.rel or seed.rel.endswith("route.ts")
        or bool(_WEB_ROUTE_MARK.search(seed.text)))


def expand(index: RepositoryAuditIndex, project: str, query: AuditQuery,
           seeds: list[IndexedFile]) -> tuple[list[ExtraPiece],
                                              list[Unresolved]]:
    """Return (extra pieces with provenance, unresolved structured facts).
    Deterministic: inputs are ordered, outputs are ordered by (provenance,
    file)."""
    by_rel = {f.rel: f for f in index.files}
    seed_rels = {s.rel for s in seeds}
    picked: dict[str, ExtraPiece] = {}
    unresolved: list[Unresolved] = []

    def add(target: IndexedFile, names: list[str], prov: str) -> None:
        if target.rel in seed_rels or target.rel in picked:
            return
        if len(picked) >= MAX_EXPAND_FILES:
            return
        picked[target.rel] = ExtraPiece(
            target.rel, _windows_for(target, names), prov)

    for seed in seeds:
        # 1) local imports -> imported symbol definitions
        imports: list[tuple[str, list[str]]] = []
        if seed.language in ("typescript",):
            for m in _TS_IMPORT.finditer(seed.text):
                imports.append((m.group("spec"),
                                _sym_names(m.group("names") or "")))
        elif seed.language == "python":
            for m in _PY_FROM.finditer(seed.text):
                imports.append((m.group("mod").replace(".", "/"),
                                _sym_names(m.group("names"))))
        for spec, names in imports:
            target = _resolve_import(spec, seed.rel, project, by_rel)
            if target is not None:
                add(target, names, "import")
            elif spec.startswith(("@/", ".")):      # local but missing
                if len(unresolved) < MAX_UNRESOLVED:
                    unresolved.append(Unresolved(
                        "import", spec, "local import not found in the "
                        "repository index"))
        # 2) route references -> backend endpoint (any project). Two forms,
        #    both deterministic: an EXACT string-literal path, and a
        #    TEMPLATE-literal family reduced to its static segment-aligned
        #    prefix. Unresolved authorization routes become structured facts.
        needles: list[tuple[str, bool]] = []
        for m in _ROUTE_LIT.finditer(seed.text):
            path = m.group(1)
            if path.startswith("/api") or path.count("/") >= 2:
                needles.append((path, False))
        for m in _ROUTE_TEMPLATE.finditer(seed.text):
            pref = _route_prefix(m.group(1))
            if pref is not None and (pref.startswith("/api")
                                     or pref.count("/") >= 3):
                needles.append((pref, True))
        seen_needles: set[str] = set()
        for needle, is_prefix in needles:
            if needle in seen_needles:
                continue
            seen_needles.add(needle)
            target = _find_route_target(needle, is_prefix, by_rel,
                                        seed_rels | set(picked))
            if target is not None:
                add(target, [needle], "route_target")
            elif query.category == "authorization":
                if len(unresolved) < MAX_UNRESOLVED:
                    unresolved.append(Unresolved(
                        "route", needle, "no backend endpoint for this route "
                        "was found in the repository index"))
        # 3) authorization query + web route -> project middleware
        if query.category == "authorization" and _is_web_route(seed):
            mw = _find_middleware(project, by_rel)
            if mw is not None:
                add(mw, ["middleware", "auth"], "framework_middleware")

    ordered = sorted(picked.values(), key=lambda e: (e.provenance, e.file))
    return ordered, unresolved

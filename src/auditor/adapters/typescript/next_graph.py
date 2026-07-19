from __future__ import annotations

from pathlib import Path
from posixpath import dirname, join, normpath

from auditor.adapters.typescript.next_rules import (_KNOWN_HOOKS,
                                                    _SAFE_CLIENT_ENVS,
                                                    _SERVER_ONLY_IMPORTS,
                                                    _env_reads, has_use_client)
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

# Official app-router module conventions (nextjs.org/docs/app/api-reference/
# file-conventions, Next 15/16). SUPPORTED render/segment entries (each a graph
# root): page, layout, template, error, global-error, global-not-found, loading,
# not-found, forbidden, unauthorized, default (parallel routes), route (handlers).
# EXCLUDED (documented in report limitations — they are not part of the render
# module graph): middleware/proxy, instrumentation (edge/runtime hooks) and the
# metadata file conventions (sitemap/opengraph-image/icon/robots/manifest).
_ENTRY_STEMS = frozenset({"page", "layout", "template", "error", "global-error",
                          "global-not-found", "loading", "not-found", "forbidden",
                          "unauthorized", "default", "route"})
_EXTS = (".tsx", ".ts", ".jsx", ".js")


def _under_app(rel: str) -> bool:
    """Next allows both app/ and src/app/ (documented dual layout)."""
    parts = rel.split("/")
    return parts[0] == "app" or (len(parts) > 1 and parts[0] == "src" and parts[1] == "app")


def _is_entry(rel: str) -> bool:
    return _under_app(rel) and Path(rel).stem in _ENTRY_STEMS and Path(rel).suffix in _EXTS


_EDGE_QUERY = """
(import_statement source: (string) @src)
(export_statement source: (string) @src)
(call_expression function: (import) arguments: (arguments (string) @src))
(call_expression function: (identifier) @fn arguments: (arguments (string) @req))
"""
_BROWSER_GLOBALS = frozenset({"window", "document", "localStorage", "navigator"})


def _is_type_only(stmt) -> bool:
    # `import type {X} from` / `export type {X} from` — erased at runtime,
    # never a client/server boundary edge
    return any(c.type == "type" for c in stmt.children)


def _edges(sf: SourceFile) -> list[str]:
    caps = captures(sf.language, sf.tree.root_node, _EDGE_QUERY)
    out: list[str] = []
    for node in caps.get("src", []):
        stmt = node.parent
        while stmt is not None and stmt.type not in ("import_statement",
                                                     "export_statement",
                                                     "call_expression"):
            stmt = stmt.parent
        if stmt is not None and stmt.type in ("import_statement", "export_statement") \
                and _is_type_only(stmt):
            continue
        out.append(node_text(node).strip("'\"`"))
    for node in caps.get("req", []):
        fn = node.parent.parent.child_by_field_name("function")
        if fn is not None and fn.type == "identifier" and node_text(fn) == "require":
            out.append(node_text(node).strip("'\"`"))
    return out


def _resolve(spec: str, from_rel: str, files_by_rel: dict,
             alias_map: tuple[tuple[str, str], ...]) -> str | None:
    base: str | None
    if spec.startswith("."):
        base = normpath(join(dirname(from_rel), spec))
    else:
        base = None
        # longest matching alias prefix wins; rebase onto its TARGET, not just
        # strip the prefix — "@/*":["./src/*"] maps @/components/x to
        # src/components/x
        for prefix, target_base in sorted(alias_map, key=lambda t: -len(t[0])):
            if spec == prefix or spec.startswith(prefix + "/"):
                rest = spec[len(prefix):].lstrip("/")
                base = f"{target_base}/{rest}".strip("/") if target_base else rest
                break
    if base is None:
        return None              # external package — hallucination engine's job
    if base.split("/")[0] == "..":
        return None              # escapes the project root
    for cand in [base] + [base + e for e in _EXTS] \
            + [join(base, "index" + e) for e in _EXTS]:
        if cand in files_by_rel:
            return cand
    return None                  # unresolved — reported via notes, never guessed


def _n(rule_id: str, sev: Severity, title: str, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule_id, severity=sev, title=title, file=sf.rel,
                   line=line_of(node), snippet=node_text(node)[:120], detail=detail,
                   language=sf.language, engine="auditor", precision="heuristic")


def _server_violations(sf: SourceFile) -> list[Finding]:
    out = []
    # ONE shared hook predicate with react_rules (CP-8b.7): bare useX or a member
    # call on a React namespace only — api.useState/client.useState do NOT count.
    from auditor.adapters.typescript.react_rules import hook_calls
    for call, name in hook_calls(sf):
        if name in _KNOWN_HOOKS:
            out.append(_n("N006", Severity.RED,
                          "Client-only API in a module reachable from a Server Component",
                          sf, call,
                          f"{name} runs in a SERVER import path (module-graph); "
                          "add \"use client\" at the boundary that should own this file."))
    if sf.language == "tsx":   # jsx_attribute exists only in the tsx grammar
        for attr in captures(sf.language, sf.tree.root_node,
                             "(jsx_attribute (property_identifier) @n)").get("n", []):
            name = node_text(attr)
            if len(name) > 2 and name.startswith("on") and name[2].isupper():
                out.append(_n("N006", Severity.RED,
                              "Client-only API in a module reachable from a Server Component",
                              sf, attr.parent,
                              f"{name} event handler in a SERVER import path (module-graph)."))
    for ident in captures(sf.language, sf.tree.root_node, "(identifier) @i").get("i", []):
        if node_text(ident) in _BROWSER_GLOBALS and _is_global_use(ident):
            out.append(_n("N006", Severity.RED,
                          "Client-only API in a module reachable from a Server Component",
                          sf, ident, f"browser global '{node_text(ident)}' in a SERVER path."))
    return out


def _is_global_use(ident) -> bool:
    """A browser global is a real usage as the OBJECT of a member access
    (window.location, document.cookie) or standalone — but NOT a local binding."""
    parent = ident.parent
    if parent is None:
        return True
    if parent.type == "member_expression":
        obj = parent.child_by_field_name("object")
        return obj is not None and obj.start_byte == ident.start_byte \
            and obj.end_byte == ident.end_byte      # object side, not the property
    # exclude declarations/params/import bindings named like a global
    return parent.type not in ("variable_declarator", "required_parameter",
                               "formal_parameters", "import_specifier",
                               "shorthand_property_identifier_pattern")


def _client_context_findings(sf: SourceFile) -> list[Finding]:
    """N002/N004/N005 for files that INHERIT client context (no directive of
    their own) — the per-file rules gate on has_use_client and cannot see them."""
    out = []
    for node, var in _env_reads(sf):
        if not var.startswith("NEXT_PUBLIC_") and var not in _SAFE_CLIENT_ENVS:
            out.append(_n("N002", Severity.YELLOW,
                          "Non-NEXT_PUBLIC env read in inherited client context",
                          sf, node,
                          f"process.env.{var} is undefined in the client bundle; this file "
                          "inherits client context through its importer (module-graph)."))
    for src in captures(sf.language, sf.tree.root_node,
                        "(import_statement source: (string) @s)").get("s", []):
        spec = node_text(src).strip("'\"`")
        if spec in _SERVER_ONLY_IMPORTS:
            out.append(_n("N004", Severity.RED,
                          "Server-only import in inherited client context", sf, src.parent,
                          f"'{spec}' cannot run in the browser; this file is pulled into the "
                          "client bundle through its importer."))
    for fn in captures(sf.language, sf.tree.root_node,
                       "(function_declaration) @f").get("f", []):
        name = fn.child_by_field_name("name")
        if name is not None and node_text(name)[:1].isupper() \
                and any(c.type == "async" for c in fn.children):
            out.append(_n("N005", Severity.YELLOW,
                          "async component in inherited client context", sf, fn,
                          f"{node_text(name)} is async in a client-context import path."))
    return out


def analyze(files: list[SourceFile],
            alias_map: tuple[tuple[str, str], ...]) -> tuple[list[Finding], list[str]]:
    """Dual-state BFS over the import graph. BOTH (file, server) and
    (file, client) contexts are explored and reported — a server-path violation
    stands even when a client path also reaches the same file.

    Coverage guarantee: EVERY app/ file is analyzed, so the global removal of
    per-file N003 loses nothing. Files reached from an entry inherit their
    path's context; app/ files NOT reached from any entry (orphans) are
    analyzed as standalone SERVER roots — a Next app/ module renders as a
    Server Component by default unless it declares "use client"."""
    files_by_rel = {sf.rel: sf for sf in files}
    entries = sorted(sf.rel for sf in files if _is_entry(sf.rel))
    notes: list[str] = []
    findings: list[Finding] = []
    visited: set[tuple[str, str]] = set()
    unresolved: list[str] = []

    def _bfs(roots):
        stack = [(r, "server") for r in roots]
        while stack:
            rel, state = stack.pop()
            if (rel, state) in visited:
                continue          # cycle/diamond termination
            visited.add((rel, state))
            sf = files_by_rel[rel]
            out_state = "client" if (state == "client" or has_use_client(sf)) else "server"
            if out_state == "server":
                findings.extend(_server_violations(sf))
            elif not has_use_client(sf):
                findings.extend(_client_context_findings(sf))
            # (files WITH the directive keep their per-file N002/N004/N005 rules)
            for spec in _edges(sf):
                target = _resolve(spec, rel, files_by_rel, alias_map)
                if target is not None:
                    stack.append((target, out_state))
                elif spec.startswith("."):
                    unresolved.append(f"{rel} -> {spec}")

    _bfs(entries)
    reached = {r for r, _ in visited}
    orphans = sorted(sf.rel for sf in files
                     if _under_app(sf.rel) and sf.rel not in reached)
    if orphans:
        _bfs(orphans)            # analyze standalone (server default) — NOT excluded
        notes.append(f"next-graph: {len(orphans)} orphan app/ file(s) not reachable from "
                     f"an entry (first: {orphans[0]}) — analyzed standalone as server default")
    if unresolved:
        notes.append(f"next-graph: {len(unresolved)} unresolved relative edge(s) "
                     f"(first: {unresolved[0]}) — not guessed")
    return findings, notes


# ── Rule Capability Catalog (owned HERE) ────────────────────────────────────
from auditor.core.catalog import RuleDescriptor as _RD  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

DESCRIPTORS = [
    _RD("N006", "Client API on a server module-graph path",
        "Dual-state BFS over the app/ module graph proves a client-only API is reachable in a server context (orphans analyzed as server default).",
        category="next", default_level="error", default_precision="exact",
        engine="next-graph", scope="module_graph", source="builtin",
        languages=("typescript", "tsx"), frameworks=("next",)),
]

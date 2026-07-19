from __future__ import annotations

import re
from pathlib import Path

from auditor.adapters.typescript.react_rules import _finding, hook_calls
from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, node_text

_SENSITIVE = re.compile(r"(SECRET|PRIVATE|PASSWORD|TOKEN|SERVICE_ROLE|ACCESS_KEY|API_?KEY)",
                        re.I)
_SAFE = re.compile(r"(PUBLIC_KEY|PUBLISHABLE)", re.I)
_ENV_MEMBER_QUERY = "(member_expression) @m"
_KNOWN_HOOKS = frozenset({
    "useState", "useEffect", "useLayoutEffect", "useReducer", "useRef",
    "useCallback", "useMemo", "useContext", "useTransition", "useDeferredValue",
    "useOptimistic", "useSyncExternalStore", "useImperativeHandle",
    "useInsertionEffect",
})
_SERVER_ONLY_IMPORTS = frozenset({
    "fs", "node:fs", "fs/promises", "child_process", "node:child_process",
    "net", "node:net", "server-only", "next/headers",
})
_SAFE_CLIENT_ENVS = frozenset({"NODE_ENV", "NEXT_RUNTIME"})


def has_use_client(sf: SourceFile) -> bool:
    """A real directive prologue (CP-8.4): scan from the first statement and stop
    at the FIRST non-string-literal statement — no arbitrary 3-node window.
    Leading comments are skipped; another directive string ('use strict') keeps
    the prologue open; an import or any real statement ends it."""
    for child in sf.tree.root_node.named_children:
        if child.type in ("comment", "hash_bang_line"):
            continue
        if child.type == "expression_statement" and child.named_children \
                and child.named_children[0].type == "string":
            if node_text(child.named_children[0]).strip("'\"") == "use client":
                return True
            continue   # a different directive — the prologue continues
        return False   # first non-string statement ends the prologue
    return False


def _env_reads(sf: SourceFile) -> list[tuple]:
    out = []
    for m in captures(sf.language, sf.tree.root_node, _ENV_MEMBER_QUERY).get("m", []):
        text = node_text(m)
        if text.startswith("process.env.") and text.count(".") == 2:
            out.append((m, text.rsplit(".", 1)[1]))
    return out


class PublicEnvSecret(Rule):
    id = "N001"
    severity = Severity.RED
    title = "NEXT_PUBLIC_ variable with secret-like name (exposed to client bundle)"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for node, var in _env_reads(sf):
            if var.startswith("NEXT_PUBLIC_") and _SENSITIVE.search(var) and not _SAFE.search(var):
                out.append(_finding(self, sf, node,
                                    f"{var} is inlined into the public client bundle at build "
                                    "time; a secret here is exposed to every visitor."))
        return out


def scan_env_files(root: Path) -> list[Finding]:
    from auditor.core.walk import read_text_capped
    rule = PublicEnvSecret()
    out: list[Finding] = []
    for env in sorted(root.glob(".env*")):
        if not env.is_file():
            continue
        for i, line in enumerate(read_text_capped(env).splitlines(), 1):
            name = line.split("=", 1)[0].strip()
            # the VALUE is never echoed into the report — only the name
            if "=" in line and name.startswith("NEXT_PUBLIC_") \
                    and _SENSITIVE.search(name) and not _SAFE.search(name):
                out.append(Finding(rule_id="N001", severity=Severity.RED, title=rule.title,
                                   file=env.name, line=i, snippet=name + "=***",
                                   detail=f"{name} in {env.name} ships to the client bundle.",
                                   language="typescript", engine="auditor"))
    return out


class PrivateEnvInClient(Rule):
    id = "N002"
    severity = Severity.YELLOW
    title = "Non-NEXT_PUBLIC env read in a Client Component (empty at runtime)"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        if not has_use_client(sf):
            return []
        out = []
        for node, var in _env_reads(sf):
            if not var.startswith("NEXT_PUBLIC_") and var not in _SAFE_CLIENT_ENVS:
                out.append(_finding(self, sf, node,
                                    f"process.env.{var} is not NEXT_PUBLIC_*; in client code it "
                                    "is replaced by undefined at build time (silent failure)."))
        return out


class ClientApiInServerComponent(Rule):
    id = "N003"
    severity = Severity.RED
    title = "Client-only API used in a Server Component (missing \"use client\")"
    frameworks = ("next",)
    precision = "heuristic"   # per-file fallback; superseded by the N006 graph pass

    _EVENT_ATTR = re.compile(r"^on[A-Z]")

    def check(self, sf: SourceFile) -> list[Finding]:
        # per-file fallback ONLY when the graph pass is inactive; app/ or src/app/
        parts = sf.rel.split("/")
        under_app = parts[0] == "app" or (len(parts) > 1 and parts[0] == "src"
                                          and parts[1] == "app")
        if not under_app or has_use_client(sf):
            return []
        out = []
        for call, name in hook_calls(sf):
            if name in _KNOWN_HOOKS:
                out.append(_finding(self, sf, call,
                                    f"{name} requires a Client Component; add \"use client\" "
                                    "or move this logic into a client child."))
        if sf.language == "tsx":   # jsx_attribute exists only in the tsx grammar
            for attr in captures(sf.language, sf.tree.root_node,
                                 "(jsx_attribute (property_identifier) @n)").get("n", []):
                if self._EVENT_ATTR.match(node_text(attr)):
                    out.append(_finding(self, sf, attr.parent,
                                        f"{node_text(attr)} event handlers only work in Client "
                                        "Components; this file has no \"use client\" directive."))
        return out


class ServerImportInClient(Rule):
    id = "N004"
    severity = Severity.RED
    title = "Server-only import inside a Client Component"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        if not has_use_client(sf):
            return []
        out = []
        for src in captures(sf.language, sf.tree.root_node,
                            "(import_statement source: (string) @s)").get("s", []):
            spec = node_text(src).strip("'\"")
            if spec in _SERVER_ONLY_IMPORTS:
                out.append(_finding(self, sf, src.parent,
                                    f"'{spec}' cannot run in the browser; importing it in a "
                                    "\"use client\" file breaks the build or leaks server code."))
        return out


class AsyncClientComponent(Rule):
    id = "N005"
    severity = Severity.YELLOW
    title = "async Client Component"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        if not has_use_client(sf):
            return []
        out = []
        for fn in captures(sf.language, sf.tree.root_node, "(function_declaration) @f").get("f", []):
            name_node = fn.child_by_field_name("name")
            is_async = any(c.type == "async" for c in fn.children)
            if is_async and name_node is not None and node_text(name_node)[:1].isupper():
                out.append(_finding(self, sf, fn,
                                    f"{node_text(name_node)} is an async Client Component — "
                                    "not supported by React; fetch in a Server Component instead."))
        return out


NEXT_RULES: list[Rule] = [PublicEnvSecret(), PrivateEnvInClient(),
                          ClientApiInServerComponent(), ServerImportInClient(),
                          AsyncClientComponent()]


# ── Rule Capability Catalog (owned HERE) ────────────────────────────────────
from auditor.core.catalog import RuleDescriptor as _RD  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

from typing import Any as _Any  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

_N: "dict[str, _Any]" = dict(category="next", engine="pattern-engine", scope="file",
          source="builtin", languages=("typescript", "tsx"),
          frameworks=("next",))
DESCRIPTORS = [
    _RD("N001", "Secret exposed via NEXT_PUBLIC_*",
        "A secret-named NEXT_PUBLIC_ variable is defined in code or .env* (value never echoed).",
        default_level="error", default_precision="exact", **_N),
    _RD("N002", "Private env read in client code",
        "A non-public environment variable is read from a client component.",
        default_level="warning", default_precision="exact", **_N),
    _RD("N003", "Client API in a server component (per-file)",
        "Browser/client-only APIs are used in a file treated as a server component by the per-file fallback.",
        default_level="error", default_precision="heuristic", **_N),
    _RD("N004", "server-only import in client code",
        "A module marked server-only is imported from a client component.",
        default_level="error", default_precision="exact", **_N),
    _RD("N005", "Async client component",
        "A client component is declared async, which React does not support.",
        default_level="warning", default_precision="exact", **_N),
]

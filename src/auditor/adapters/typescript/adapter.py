from __future__ import annotations

import json
import re
from pathlib import Path

from auditor.adapters.typescript.builtins import NODE_BUILTINS
from auditor.core.interfaces import LanguageAdapter, SyntaxProfile
from auditor.core.models import DeclaredDep, ImportRef, SourceFile

_SKIP_SPEC = ("workspace:", "file:", "link:", "portal:", "git+", "git:", "github:",
              "http://", "https://")
_DEP_GROUPS = ("dependencies", "devDependencies", "peerDependencies",
               "optionalDependencies")
_IMPORT_QUERY = """
(import_statement source: (string) @src)
(export_statement source: (string) @src)
(call_expression function: (identifier) @fn arguments: (arguments (string) @arg))
(call_expression function: (import) arguments: (arguments (string) @dynarg))
"""


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


class TypeScriptAdapter(LanguageAdapter):
    # npm import specifiers ARE registry identifiers (a bare 'lodash' import can
    # only resolve to the lodash package), so mapping_precision stays "exact".
    name = "typescript"
    ecosystem = "npm"
    source_globs = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

    def __init__(self) -> None:
        self._self_name = ""
        self._alias_prefixes: tuple[str, ...] = ()
        # (import-prefix, project-relative target base) — graph resolution needs
        # the TARGET, not just the prefix: "@/*":["./src/*"] maps @/x to src/x
        self._alias_map: tuple[tuple[str, str], ...] = ()
        self._graph_findings: list = []
        self._graph_active = False

    def file_language(self, path: Path) -> str:
        return "tsx" if path.suffix.lower() in (".tsx", ".jsx") else "typescript"

    def detect(self, root: Path) -> bool:
        return (root / "package.json").is_file()

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        self._scan_root = root.resolve()   # enables the central symlink guard
        pkg = root / "package.json"
        data = self._load_pkg(pkg)
        out: list[DeclaredDep] = []
        seen: set[str] = set()
        for group in _DEP_GROUPS:
            table = data.get(group)
            if table is None:
                continue
            if not isinstance(table, dict):
                self._schema_note(pkg, group)
                continue
            for name, spec in table.items():
                if name in seen:
                    continue
                seen.add(name)
                out.append(self._dep(group, name, spec))
        self._last_declared = out
        return out

    def _load_pkg(self, pkg: Path) -> dict:
        try:
            data = json.loads(self._read(pkg) or "{}")
        except json.JSONDecodeError as e:
            self._manifest_error(pkg, e)
            return {}
        if not isinstance(data, dict):
            self._schema_note(pkg, "top-level document")
            return {}
        return data

    @staticmethod
    def _dep(group: str, name: str, spec) -> DeclaredDep:
        skip = isinstance(spec, str) and spec.startswith(_SKIP_SPEC)
        registry_name = ""
        if isinstance(spec, str) and spec.startswith("npm:"):
            # alias: "foo": "npm:bar@^1" => import name foo, registry package bar
            target = spec[4:]
            cut = target.rfind("@")
            registry_name = target[:cut] if cut > 0 else target
        return DeclaredDep(name=name, ecosystem="npm", source_file="package.json",
                           raw=f"{group}: {name}@{spec}", skip_registry=skip,
                           registry_name=registry_name)

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        self.ensure_grammars()
        self._scan_root = root.resolve()
        self._self_name = str(self._load_pkg(root / "package.json").get("name") or "")
        self._load_tsconfig_aliases(root)
        # N006 module-graph pass: built here because prepare has files + cached
        # declared deps; per-file N003 is superseded when the graph is active
        self._graph_notes: list[str] = []
        self._graph_findings, self._graph_active = [], False
        names = {d.name for d in getattr(self, "_last_declared", []) or []}
        if "next" in names and ((root / "app").is_dir() or (root / "src" / "app").is_dir()):
            from auditor.adapters.typescript.next_graph import analyze
            from auditor.core.treesitter import parse_source
            for sf in files:
                parse_source(sf)
            self._graph_findings, self._graph_notes = analyze(files, self._alias_map)
            self._graph_active = True
            if self._diag is not None:
                for n in self._graph_notes:
                    self._note(n)

    def _load_tsconfig_aliases(self, root: Path) -> None:
        paths: dict = {}
        cfg = root / "tsconfig.json"
        for _ in range(2):  # follow local `extends` one level only (documented limit)
            if not cfg.is_file():
                break
            try:
                data = json.loads(_strip_jsonc(self._read(cfg)))
            except json.JSONDecodeError:
                break
            if not isinstance(data, dict):
                break
            opts = data.get("compilerOptions")
            opts = opts if isinstance(opts, dict) else {}
            cfg_paths = opts.get("paths")
            if isinstance(cfg_paths, dict):
                paths = {**cfg_paths, **paths}   # child config wins
            if isinstance(opts.get("baseUrl"), str) and "__baseUrl__" not in paths:
                paths["__baseUrl__"] = opts["baseUrl"]
            ext = data.get("extends")
            if isinstance(ext, str) and ext.startswith("."):
                cfg = (cfg.parent / ext).with_suffix(".json") \
                    if not ext.endswith(".json") else cfg.parent / ext
            else:
                break
        base_url = paths.pop("__baseUrl__", ".")
        self._alias_prefixes = tuple(
            p for p in (key.removesuffix("*").rstrip("/") for key in paths) if p)
        amap: list[tuple[str, str]] = []
        for key, targets in paths.items():
            prefix = key.removesuffix("*").rstrip("/")
            if not prefix or not targets:
                continue
            target = targets[0] if isinstance(targets, list) else targets
            if not isinstance(target, str):
                continue
            target_base = target.removesuffix("*").lstrip("./").rstrip("/")
            if base_url not in (".", "", None):
                target_base = f"{base_url.strip('./').rstrip('/')}/{target_base}".strip("/")
            amap.append((prefix, target_base))
        self._alias_map = tuple(amap)

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, node_text, parse_source
        self.ensure_grammars()
        out: list[ImportRef | None] = []
        for sf in files:
            parse_source(sf)
            caps = captures(sf.language, sf.tree.root_node, _IMPORT_QUERY)
            for key in ("src", "dynarg"):
                for node in caps.get(key, []):
                    out.append(self._ref(node, sf.rel))
            for node in caps.get("arg", []):
                # string -> arguments -> call_expression; keep only require(...)
                # (re-read the function field; never compare Node objects by id)
                call = node.parent.parent
                fn = call.child_by_field_name("function")
                if fn is not None and fn.type == "identifier" and node_text(fn) == "require":
                    out.append(self._ref(node, sf.rel))
        return [r for r in out if r is not None]

    def _ref(self, string_node, rel: str) -> ImportRef | None:
        from auditor.core.treesitter import line_of, node_text
        spec = node_text(string_node).strip("'\"`")
        if not spec or spec.startswith((".", "/", "#")):
            return None  # relative, absolute, or package-private "#x" subpath import
        if any(spec == p or spec.startswith(p + "/") for p in self._alias_prefixes):
            return None  # tsconfig path alias: a local path in disguise
        parts = spec.split("/")
        top = "/".join(parts[:2]) if spec.startswith("@") and len(parts) >= 2 else parts[0]
        return ImportRef(module=spec, file=rel, line=line_of(string_node), top_level=top)

    def is_internal(self, imp: ImportRef) -> bool:
        top = imp.top_level
        if top.startswith("node:") or top in NODE_BUILTINS:
            return True
        if self._self_name and top == self._self_name:
            return True   # package self-reference (imports its own name)
        return any(imp.module == p or imp.module.startswith(p + "/") or top == p
                   for p in self._alias_prefixes)

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        return next((d for d in declared if d.name == imp.top_level), None)

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        return [imp.top_level]

    def unresolvable_hint(self, identifier: str) -> str | None:
        # kept OUT of core (CP-3): npm-specific semantics live here
        if identifier.startswith("@"):
            return "scoped npm package (private scopes return 404 without auth)"
        return None

    def language_rules(self):
        from auditor.adapters.typescript.next_rules import NEXT_RULES
        from auditor.adapters.typescript.react_rules import REACT_RULES
        rules = [*REACT_RULES, *NEXT_RULES]
        if getattr(self, "_graph_active", False):
            rules = [r for r in rules if r.id != "N003"]   # graph classification supersedes
        return rules

    def project_rules(self, root: Path, frameworks: list[str]) -> list:
        out = list(getattr(self, "_graph_findings", []))
        if "next" in frameworks:
            from auditor.adapters.typescript.next_rules import scan_env_files
            out += scan_env_files(root)
        return out

    def frameworks(self, root: Path, declared: list[DeclaredDep]) -> list[str]:
        names = {d.name for d in declared}
        fws: list[str] = []
        if "react" in names:
            fws.append("react")
        router_dirs = (root / "app", root / "pages",
                       root / "src" / "app", root / "src" / "pages")
        if "next" in names and any(d.is_dir() for d in router_dirs):
            fws.append("next")
        return fws

    def grammars(self) -> dict[str, object]:
        import tree_sitter_typescript
        return {"typescript": tree_sitter_typescript.language_typescript(),
                "tsx": tree_sitter_typescript.language_tsx()}

    def syntax(self):
        return SyntaxProfile(
            catch_query="(catch_clause) @c",
            sql_concat_query="(binary_expression) @n",
            sql_interp_query="(template_string) @n",
            sql_dynamic_types=("template_substitution",),
        )

    def private_registry_reason(self, root: Path) -> str | None:
        # a repo-level .npmrc above the project dir also configures the registry
        for d in self._config_search_dirs(root):
            npmrc = d / ".npmrc"
            if not npmrc.is_file():
                continue
            for line in self._read(npmrc).splitlines():
                stripped = line.strip()
                if stripped.startswith("registry=") or \
                        (stripped.startswith("@") and ":registry=" in stripped):
                    where = ".npmrc" if d == root.resolve() else f"{npmrc.as_posix()}"
                    return f"custom registry configured in {where}"
        return None

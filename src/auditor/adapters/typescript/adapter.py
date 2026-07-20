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

    # runtime environments whose imports are NOT npm packages: k6 load-test
    # scripts import `k6` / `k6/*` from the k6 runtime itself (field-verified
    # false H002s). Extended per-repo via config runtime_builtins.npm.
    _RUNTIME_BUILTINS = frozenset({"k6"})

    def __init__(self) -> None:
        self._self_name = ""
        self._runtime_builtins: frozenset[str] = self._RUNTIME_BUILTINS
        self._npm_roots: tuple[str, ...] = ()   # config-authorized manifestless roots
        self._alias_prefixes: tuple[str, ...] = ()
        # (import-prefix, project-relative target base) — graph resolution needs
        # the TARGET, not just the prefix: "@/*":["./src/*"] maps @/x to src/x
        self._alias_map: tuple[tuple[str, str], ...] = ()
        self._graph_findings: list = []
        self._graph_active = False

    def file_language(self, path: Path) -> str:
        return "tsx" if path.suffix.lower() in (".tsx", ".jsx") else "typescript"

    def detect(self, root: Path) -> bool:
        if (root / "package.json").is_file():
            return True
        # a config-authorized npm root IS a package root: it becomes a real
        # project in discovery, so nearest-root ownership and the dependency
        # audit apply to it exactly like a manifest-bearing package
        return self._is_configured_npm_root(root)

    def _is_configured_npm_root(self, root: Path) -> bool:
        if not self._npm_roots:
            return False
        repo = self._confinement_root()
        if repo is None:
            return False
        try:
            rel = root.resolve().relative_to(repo).as_posix()
        except (ValueError, OSError):
            return False
        return rel in self._npm_roots or (rel == "." and "." in self._npm_roots)

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
        # B2-B execution facts, consumed by project_rules:
        self._graph_applicable = False   # Next app graph applies to this project
        self._graph_failed = False       # build/analyze raised (fallback stays)
        self._graph_partial = False      # a graph input carried syntax errors
        names = {d.name for d in getattr(self, "_last_declared", []) or []}
        if "next" in names and ((root / "app").is_dir() or (root / "src" / "app").is_dir()):
            self._graph_applicable = True
            from auditor.adapters.typescript.next_graph import analyze
            from auditor.core.treesitter import parse_source
            try:
                for sf in files:
                    parse_source(sf)
                self._graph_findings, self._graph_notes, in_graph = \
                    analyze(files, self._alias_map)
                # partial is evidence about the GRAPH'S inputs: only a file the
                # BFS actually visited counts — a broken file outside the graph
                # (unreachable, not an app/ orphan) is not a graph fact
                self._graph_partial = any(
                    sf.rel in in_graph and sf.tree.root_node.has_error
                    for sf in files)
                self._graph_active = True
            except Exception as e:  # noqa: BLE001 — graph failure must not sink the
                # project; per-file N003 stays available (graph inactive)
                self._graph_failed = True
                self._graph_active = False
                if self._diag is not None:
                    self._note(f"next-graph: build failed ({e.__class__.__name__})")
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

    def apply_config(self, config) -> None:
        super().apply_config(config)
        extra = config.runtime_builtins.get("npm", ())
        if extra:
            self._runtime_builtins = self._RUNTIME_BUILTINS | set(extra)
        self._npm_roots = config.npm_roots

    def dependency_audit_reason(self, root: Path) -> str | None:
        """npm dependency auditing requires a LEGAL package root: a
        `package.json` at the project root, or an explicit config npm_roots
        entry. A `.js/.ts` suffix alone (Phoenix asset pipelines, k6 scripts,
        loose tooling) never proves the file is npm-owned — such projects get
        code rules only, and no import is sent to the npm registry."""
        if (root / "package.json").is_file():
            return None
        if self._is_configured_npm_root(root):
            return None
        return ("no npm package root owns these files (no package.json and no "
                "configured npm root) — code rules ran; npm dependency audit "
                "disabled")

    def is_internal(self, imp: ImportRef) -> bool:
        top = imp.top_level
        if top.startswith("node:") or top in NODE_BUILTINS:
            return True
        if top in self._runtime_builtins:
            return True   # runtime-provided (k6/...), not an npm package
        if self._config_internal_match(imp.module) or self._config_internal_match(top):
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

    _GRAPH_GROUP = ("N002", "N004", "N005", "N006")
    _ENV_GROUP = ("N001",)

    def project_rules(self, root: Path, frameworks: list[str],
                      ledger=None, diag=None) -> list:
        """Two project passes, each recording its OWN execution evidence (B2-B):
        the Next module graph (built in prepare) and per-file .env scanning."""
        from auditor.adapters.typescript.next_rules import (
            list_env_files,
            scan_one_env_file,
        )
        from auditor.core.execution import record_project_pass
        out: list = []

        # ── Next module-graph pass ──────────────────────────────────────────
        if getattr(self, "_graph_applicable", False):
            if getattr(self, "_graph_failed", False):
                # one failure for the whole group; N003 fallback stays active
                if ledger is not None:
                    ledger.eligible(self._GRAPH_GROUP)
                if diag is not None:
                    diag.rule_attempted += 1
                    diag.rule_failures += 1
                if ledger is not None:
                    ledger.attempted_failed(self._GRAPH_GROUP)
            else:
                out += record_project_pass(
                    ledger, diag, self._GRAPH_GROUP,
                    list(getattr(self, "_graph_findings", [])),
                    partial=getattr(self, "_graph_partial", False))
                # a SUCCESSFUL graph supersedes the per-file N003 fallback
                if ledger is not None:
                    ledger.not_applicable(
                        ("N003",), "superseded by the N006 module-graph pass")
        # (graph not applicable => we never claim it ran)

        # ── .env pass (per file) ────────────────────────────────────────────
        if "next" in frameworks:
            env_files = list_env_files(root)
            for env in env_files:
                try:
                    efindings = scan_one_env_file(env)
                except Exception as e:  # noqa: BLE001 — next env file still runs
                    if diag is not None and hasattr(diag, "rule_errors"):
                        diag.rule_errors.append(
                            f"N001 env {env.name}: {e.__class__.__name__}")
                    record_project_pass(ledger, diag, self._ENV_GROUP, [], failed=True)
                    continue
                out += record_project_pass(ledger, diag, self._ENV_GROUP, efindings)
            if not env_files and ledger is not None:
                ledger.not_applicable(self._ENV_GROUP, "no .env* files in this project")
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


# ── Rule Capability Catalog hook (owners: react_rules / next_rules /
#    next_graph — this only AGGREGATES its own package's descriptors) ────────
from auditor.adapters.typescript import next_graph as _ng  # noqa: E402  (deliberate late import: catalog block lives next to its rules)
from auditor.adapters.typescript import next_rules as _nr  # noqa: E402  (deliberate late import: catalog block lives next to its rules)
from auditor.adapters.typescript import react_rules as _rr  # noqa: E402  (deliberate late import: catalog block lives next to its rules)


def _ts_rule_descriptors(self):
    return list(_rr.DESCRIPTORS) + list(_nr.DESCRIPTORS) + list(_ng.DESCRIPTORS)


TypeScriptAdapter.rule_descriptors = _ts_rule_descriptors  # type: ignore[method-assign]

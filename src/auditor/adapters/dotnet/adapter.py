from __future__ import annotations

from pathlib import Path

import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException

from auditor.core.interfaces import LanguageAdapter, SyntaxProfile
from auditor.core.models import DeclaredDep, ImportRef, SourceFile

_BCL_PREFIXES = ("System.", "Microsoft.CSharp", "Microsoft.VisualBasic",
                 "Microsoft.Win32", "Windows.")
# Review-verified (learn.microsoft.com per-TFM matrix): these ship as NuGet
# packages on EVERY modern TFM despite the System.* name — never BCL-filter them.
_PACKAGE_DELIVERED_SYSTEM = ("System.CommandLine", "System.Data.SqlClient",
                             "System.Drawing", "System.Management", "System.Data.Entity")
# Additionally package-delivered when targeting .NET Framework / netstandard:
_OLD_TFM_PACKAGE_SYSTEM = ("System.Text.Json", "System.Collections.Immutable",
                           "System.Text.Encodings.Web", "System.Threading.Channels")
# Known using->package-id fixups where the naive heuristic resolves to the WRONG
# package (NUnit.Framework would hit the relic `nunit.framework 2.63.0`).
_NUGET_ALIASES = {"nunit.framework": "NUnit"}
_USING_QUERY = "(using_directive) @u"
_NS_QUERY = "[(namespace_declaration) (file_scoped_namespace_declaration)] @ns"


def _is_old_tfm(tfm: str) -> bool:
    t = tfm.strip().lower()
    return t.startswith(("net4", "netstandard", "net3", "net2")) and not t.startswith("net10")


class DotnetAdapter(LanguageAdapter):
    name = "dotnet"
    ecosystem = "nuget"
    source_globs = (".cs",)
    mapping_precision = "heuristic"   # namespace->package-id guessing => mapping findings are heuristic

    def __init__(self) -> None:
        self._own_namespaces: tuple[str, ...] = ()
        self._old_tfm = False   # any TargetFramework < netcore3 / netstandard?

    def detect(self, root: Path) -> bool:
        if (root / "packages.config").is_file() or (root / "Directory.Packages.props").is_file():
            return True
        return any(root.glob("*.csproj"))

    def _read_target_frameworks(self, root: Path) -> list[str]:
        tfms: list[str] = []
        for proj in root.glob("*.csproj"):
            try:
                doc = ET.fromstring(self._read(proj))
            except (ET.ParseError, DefusedXmlException) as e:
                self._manifest_error(proj, e)
                continue
            plural = singular = None
            for el in doc.iter():
                tag = el.tag.rsplit("}", 1)[-1]
                if tag == "TargetFrameworks":
                    plural = el.text or ""
                elif tag == "TargetFramework":
                    singular = el.text or ""
            # msbuild-props docs: TargetFrameworks (plural) overrides singular
            if plural:
                tfms += [t for t in plural.split(";") if t.strip()]
            elif singular:
                tfms.append(singular)
        return tfms

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        self._scan_root = root.resolve()   # central symlink guard for manifests
        out: list[DeclaredDep] = []
        for proj in sorted(root.glob("*.csproj")) + [root / "Directory.Packages.props"]:
            if proj.is_file():
                out += self._parse_msbuild(proj)
        pkgcfg = root / "packages.config"
        if pkgcfg.is_file():
            out += self._parse_packages_config(pkgcfg)
        seen: set[str] = set()
        deduped = []
        for d in out:
            if d.name.lower() not in seen:   # NuGet ids are case-insensitive
                seen.add(d.name.lower())
                deduped.append(d)
        return deduped

    def _parse_msbuild(self, path: Path) -> list[DeclaredDep]:
        try:
            root = ET.fromstring(self._read(path))   # defused + 2MB-capped
        except (ET.ParseError, DefusedXmlException) as e:
            self._manifest_error(path, e)
            return []
        out = []
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag in ("PackageReference", "PackageVersion"):
                name = el.get("Include") or el.get("Update")
                if name:
                    out.append(DeclaredDep(name=name, ecosystem="nuget",
                                           source_file=path.name, raw=name,
                                           skip_registry="$(" in name))
        return out

    def _parse_packages_config(self, path: Path) -> list[DeclaredDep]:
        try:
            root = ET.fromstring(self._read(path))
        except (ET.ParseError, DefusedXmlException) as e:
            self._manifest_error(path, e)
            return []
        out = []
        for el in root.iter():
            if el.tag.rsplit("}", 1)[-1] == "package":
                pkg_id = el.get("id")
                if pkg_id:
                    out.append(DeclaredDep(name=pkg_id, ecosystem="nuget",
                                           source_file=path.name, raw=pkg_id))
        return out

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        from auditor.core.treesitter import captures, node_text, parse_source
        self.ensure_grammars()
        self._old_tfm = any(_is_old_tfm(t) for t in self._read_target_frameworks(root))
        ns: set[str] = set()
        for sf in files:
            parse_source(sf)
            for node in captures("csharp", sf.tree.root_node, _NS_QUERY).get("ns", []):
                name = node.child_by_field_name("name")
                if name is not None:
                    ns.add(node_text(name))
        self._own_namespaces = tuple(sorted(ns))

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, line_of, node_text, parse_source
        self.ensure_grammars()
        out: list[ImportRef] = []
        for sf in files:
            parse_source(sf)
            for node in captures("csharp", sf.tree.root_node, _USING_QUERY).get("u", []):
                text = node_text(node).rstrip(";").strip()
                for kw in ("global ", "using ", "static "):
                    text = text.removeprefix(kw).strip() if text.startswith(kw) else text
                text = text.removeprefix("using").strip()
                text = text.removeprefix("static").strip()
                if "=" in text:                     # alias: using Foo = Bar.Baz
                    text = text.split("=", 1)[1].strip()
                if not text:
                    continue
                out.append(ImportRef(module=text, file=sf.rel, line=line_of(node),
                                     top_level=text))
        return out

    def is_internal(self, imp: ImportRef) -> bool:
        m = imp.module
        exceptions = _PACKAGE_DELIVERED_SYSTEM + (_OLD_TFM_PACKAGE_SYSTEM if self._old_tfm else ())
        if any(m == e or m.startswith(e + ".") for e in exceptions):
            return False   # System.*-named but NuGet-delivered => normal declared/registry path
        if m == "System" or m.startswith(_BCL_PREFIXES):
            return True
        return any(m == ns or m.startswith(ns + ".") or ns.startswith(m + ".")
                   for ns in self._own_namespaces)

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        best: tuple[int, DeclaredDep] | None = None
        for dep in declared:
            n = dep.name
            if imp.module == n or imp.module.startswith(n + "."):
                if best is None or len(n) > best[0]:
                    best = (len(n), dep)
        return best[1] if best else None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        parts = imp.module.split(".")
        cands = [imp.module]
        if len(parts) > 2:
            cands.append(".".join(parts[:2]))
        return [_NUGET_ALIASES.get(c.lower(), c) for c in cands]

    def language_rules(self):
        from auditor.adapters.dotnet.rules import (AsyncVoidMethod, BlockingTaskWait,
                                                   RawSqlInterpolation)
        return [AsyncVoidMethod(), BlockingTaskWait(), RawSqlInterpolation()]

    def grammars(self) -> dict[str, object]:
        import tree_sitter_c_sharp
        return {"csharp": tree_sitter_c_sharp.language()}

    def syntax(self):
        return SyntaxProfile(
            catch_query="(catch_clause) @c",
            catch_body_types=("block",),
            sql_concat_query="(binary_expression) @n",
            sql_interp_query="(interpolated_string_expression) @n",
            sql_dynamic_types=("interpolation",),
        )

    def private_registry_reason(self, root: Path) -> str | None:
        for cfg_name in ("nuget.config", "NuGet.Config", "NuGet.config"):
            cfg = root / cfg_name
            if not cfg.is_file():
                continue
            text = self._read(cfg)
            if "<packageSources>" in text and "nuget.org" not in text.split("<packageSources>")[-1]:
                return f"custom <packageSources> configured in {cfg_name}"
            if "<packageSources>" in text and "<add" in text and \
                    text.count("<add") > text.count("api.nuget.org"):
                return f"additional package sources configured in {cfg_name}"
        return None

    def file_language(self, path: Path) -> str:
        return "csharp"

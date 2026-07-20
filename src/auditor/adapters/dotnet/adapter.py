from __future__ import annotations

from dataclasses import replace
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
    """A TFM on which System.Text.Json etc. ship as NuGet packages, not in-box:
    .NET Framework (net4x / old MSBuild vXY / TargetFrameworkVersion), all
    netstandard, and netcoreapp1.x/2.x. netcoreapp3.0+ and net5+ ship them
    in-box. CP-8.3: netcoreapp1/2 were missed by the naive net2/net3 prefix."""
    t = tfm.strip().lower().lstrip("v")   # TargetFrameworkVersion is 'v4.7.2'
    if t.startswith(("netcoreapp1", "netcoreapp2")):
        return True
    if t.startswith("netcoreapp"):
        return False                      # 3.0+ ships System.Text.Json in-box
    if t[:2] in ("4.", "3.", "2."):       # bare .NET Framework version (from v4.7.2)
        return True
    return t.startswith(("net4", "netstandard", "net3", "net2")) and not t.startswith("net10")


class DotnetAdapter(LanguageAdapter):
    name = "dotnet"
    ecosystem = "nuget"
    source_globs = (".cs",)
    mapping_precision = "heuristic"   # namespace->package-id guessing => mapping findings are heuristic

    # Shared-framework providers (W2-B2.8A). SOURCE: the official
    # Microsoft.AspNetCore.App reference-pack / "ASP.NET Core shared framework"
    # asset list (learn.microsoft.com, aspnet/AspNetCore shared-framework
    # manifest): its assemblies live under EXACTLY these namespace roots.
    # Deliberately narrow — never a blanket "Microsoft.*" family guess.
    _FRAMEWORK_PROVIDES: dict[str, tuple[str, ...]] = {
        "microsoft.aspnetcore.app": (
            "Microsoft.AspNetCore", "Microsoft.Extensions",
            "Microsoft.Net.Http.Headers", "Microsoft.JSInterop"),
    }
    # SDKs that imply a FrameworkReference without writing one (official docs:
    # "Microsoft.NET.Sdk.Web implicitly references Microsoft.AspNetCore.App")
    _SDK_IMPLICIT_FRAMEWORKS: dict[str, str] = {
        "microsoft.net.sdk.web": "microsoft.aspnetcore.app",
    }

    def __init__(self) -> None:
        self._own_namespaces: tuple[str, ...] = ()
        self._old_tfm = False   # any TargetFramework < netcore3 / netstandard?
        self._fw_provides_definite: tuple[str, ...] = ()
        self._fw_provides_possible: tuple[str, ...] = ()

    def detect(self, root: Path) -> bool:
        if (root / "packages.config").is_file() or (root / "Directory.Packages.props").is_file():
            return True
        return any(root.glob("*.csproj"))

    def _read_target_frameworks(self, root: Path) -> list[str]:
        """All TFMs visible to the project (csproj + ancestor props), verbatim."""
        return (self._tfms_from(list(root.glob("*.csproj")))
                + self._tfms_from(self._props_files(root)))

    def _nearest_ancestor_file(self, root: Path, name: str) -> tuple[Path | None, bool]:
        """(nearest ancestor file with this name, does a FURTHER one exist).
        MSBuild auto-imports only the NEAREST Directory.Build.props walking up —
        outer ones apply only via a manual <Import>, which we do not execute
        (CP-8b round 4: never pool all ancestors as if applied together)."""
        found: list[Path] = []
        for d in self._config_search_dirs(root):
            f = d / name
            if f.is_file():
                found.append(f)
        return (found[0] if found else None), len(found) > 1

    def _props_files(self, root: Path) -> list[Path]:
        nearest, _ = self._nearest_ancestor_file(root, "Directory.Build.props")
        return [nearest] if nearest else []

    def _tfms_from(self, candidates: list[Path]) -> list[str]:
        """TFMs from the given MSBuild files. No MSBuild execution: dynamic
        values ($(Prop)) are kept verbatim so the caller can classify them as
        unresolvable."""
        tfms: list[str] = []
        for proj in candidates:
            try:
                doc = ET.fromstring(self._read(proj))
            except (ET.ParseError, DefusedXmlException) as e:
                self._manifest_error(proj, e)
                continue
            plural = singular = legacy = None
            for el in doc.iter():
                tag = el.tag.rsplit("}", 1)[-1]
                if tag == "TargetFrameworks":
                    plural = el.text or ""
                elif tag == "TargetFramework":
                    singular = el.text or ""
                elif tag == "TargetFrameworkVersion":   # old-style csproj (v4.7.2)
                    legacy = el.text or ""
            # msbuild-props docs: TargetFrameworks (plural) overrides singular
            if plural:
                tfms += [t for t in plural.split(";") if t.strip()]
            elif singular:
                tfms.append(singular)
            elif legacy:
                tfms.append(legacy)
        return tfms

    @staticmethod
    def _tfm_kind(tfms: list[str]) -> str | None:
        """Classify ONE source's TFM list: None (no TFMs), 'unknown' (any
        dynamic $(...)), 'old'/'modern', or 'unknown' when a single source
        mixes... no — a static multi-target list mixing old+modern IS old (the
        old target needs the package)."""
        if not tfms:
            return None
        if any("$(" in t for t in tfms):
            return "unknown"    # a dynamic member poisons the whole list
        return "old" if any(_is_old_tfm(t) for t in tfms) else "modern"

    def _classify_tfm(self, root: Path) -> str:
        """'old' | 'modern' | 'unknown' (CP-8b round 3/4). Sources classified
        SEPARATELY — the csproj vs the NEAREST ancestor Directory.Build.props —
        never pooled into one any(old). A conflict between them, or any dynamic
        $(...), is 'unknown': MSBuild override order is not assumed without
        executing MSBuild. packages.config (the classic framework format) => old."""
        if (root / "packages.config").is_file():
            return "old"
        cs = self._tfm_kind(self._tfms_from(list(root.glob("*.csproj"))))
        pr = self._tfm_kind(self._tfms_from(self._props_files(root)))
        if "unknown" in (cs, pr):
            return "unknown"
        if cs and pr and cs != pr:
            return "unknown"    # conflicting sources — priority not provable
        return cs or pr or "unknown"

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        self._scan_root = root.resolve()   # central symlink guard for manifests
        manifests = sorted(root.glob("*.csproj")) + [root / "Directory.Packages.props"]
        # MSBuild auto-imports the NEAREST ancestor Directory.Build.props AND
        # Directory.Packages.props (central package management) — read their
        # PackageReference/PackageVersion too (CP-8b round 4)
        for name in ("Directory.Build.props", "Directory.Packages.props"):
            anc, _ = self._nearest_ancestor_file(root, name)
            if anc is not None and anc not in manifests:
                manifests.append(anc)
        # MSBuild EVALUATION ORDER per PROJECT (CP-8b round 7): every csproj is
        # evaluated INDEPENDENTLY on top of the inherited props baseline — a
        # Remove in project B must not delete project A's dependency. The
        # directory's declarations are the UNION of the projects' final states
        # (definite wins over possible on collision).
        props = [m for m in manifests if m.name.endswith(".props") and m.is_file()]
        csprojs = [m for m in manifests if m.name.endswith(".csproj") and m.is_file()]
        baseline: dict[str, tuple[DeclaredDep, str]] = {}
        fw_baseline: dict[str, str] = {}
        for pr in props:
            self._apply_msbuild_events(pr, baseline, fw_baseline)
        # each csproj is evaluated INDEPENDENTLY on the props baseline; with no
        # csproj the baseline itself is the state. FrameworkReference follows
        # the SAME evaluation order (W2-B2.8A) — csproj isolation included.
        per_project: list[dict] = []
        per_project_fw: list[dict] = []
        for cs in csprojs:
            state = dict(baseline)
            fw = dict(fw_baseline)
            self._apply_msbuild_events(cs, state, fw)
            per_project.append(state)
            per_project_fw.append(fw)
        if not per_project:
            per_project = [dict(baseline)]
            per_project_fw = [dict(fw_baseline)]
        merged: dict[str, tuple[DeclaredDep, str]] = {}
        for state in per_project:
            for key, (dep, kind) in state.items():
                if key not in merged or kind == "definite":
                    merged[key] = (dep, kind)
        fw_merged: dict[str, str] = {}
        for fw in per_project_fw:
            for key, kind in fw.items():
                if key not in fw_merged or kind == "definite":
                    fw_merged[key] = kind
        # FrameworkReference flows TRANSITIVELY through ProjectReference
        # (dotnet/sdk FrameworkReferenceResolution.targets; NU1510): walk the
        # static project graph — repo-confined, cycle-safe, no MSBuild run.
        for cs in csprojs:
            for name, kind in self._transitive_framework_refs(cs).items():
                if fw_merged.get(name) != "definite":
                    fw_merged[name] = kind
        self._finish_framework_refs(fw_merged, csprojs)
        # carry the definite/possible KIND onto the DeclaredDep so the engine can
        # gate H001 on it (CP-8b round 8: dropping kind here lost 'possible')
        declared = {k: replace(dep, presence=kind) for k, (dep, kind) in merged.items()}
        pkgcfg = root / "packages.config"
        if pkgcfg.is_file():
            for d in self._parse_packages_config(pkgcfg):
                declared.setdefault(d.name.lower(), d)
        return list(declared.values())

    @staticmethod
    def _const_false_condition(el) -> bool:
        c = (el.get("Condition") or "").strip().lower()
        # a literal always-false condition (Condition="false", "'a'!='a'")
        return c in ("false", "'false'") or c in ("'a'!='a'", "'x'!='x'")

    def _apply_msbuild_events(self, path: Path, state: dict,
                              fw_state: dict | None = None) -> None:
        """Fold this file's PackageReference Include/Remove into `state`
        (name -> (DeclaredDep, "definite"|"possible")). Only Include DECLARES;
        Update alone declares nothing; statically-false conditions (element OR
        enclosing ItemGroup) are skipped. An UNRESOLVED condition never mutates
        the definite state as if it were a fact (CP-8b round 7):
        - conditional Include  => the package is POSSIBLE (kept in declarations
          so no false H002, but flagged incomplete + a visible note — never a
          silent exact claim);
        - conditional Remove of a definite package => the package downgrades to
          POSSIBLE (never silently absent, which produced false H002)."""
        try:
            root = ET.fromstring(self._read(path))   # defused + 2MB-capped
        except (ET.ParseError, DefusedXmlException) as e:
            self._manifest_error(path, e)
            return
        if fw_state is None:
            fw_state = {}
        # <Project Sdk="Microsoft.NET.Sdk.Web"> IMPLIES Microsoft.AspNetCore.App
        # (official SDK contract) — an implicit definite FrameworkReference
        sdk = (root.get("Sdk") or "").strip().lower()
        implied = self._SDK_IMPLICIT_FRAMEWORKS.get(sdk)
        if implied:
            fw_state[implied] = "definite"
        possible_names: list[str] = []
        self._walk_msbuild(root, False, path, state, possible_names, fw_state)
        if possible_names:
            self._mark_incomplete(path)
            self._note(f"{path.name}: conditional PackageReference "
                       f"({', '.join(sorted(set(possible_names)))}) — presence not "
                       "statically provable; treated as POSSIBLE, not exact")

    def _walk_msbuild(self, el, dynamic: bool, path: Path, state: dict,
                      possible_names: list, fw_state: dict | None = None) -> None:
        """Recursive MSBuild walk carrying CONDITIONAL context from ancestors
        (CP-8b round 8): a PackageReference under an unresolved Condition — on the
        element, an ItemGroup, OR a Choose/When/Otherwise ancestor — is POSSIBLE,
        never definite. A statically-false condition prunes the whole subtree. No
        MSBuild interpreter: this is a conservative classification only."""
        tag = el.tag.rsplit("}", 1)[-1]
        if self._const_false_condition(el):
            return                                    # dead subtree
        # a When/Otherwise branch, or any non-constant Condition, makes the
        # subtree conditional
        here_dynamic = dynamic or bool((el.get("Condition") or "").strip()) \
            or tag in ("When", "Otherwise")
        if tag == "PackageReference":
            self._pkgref_event(el, here_dynamic, path, state, possible_names)
            return
        if tag == "FrameworkReference" and fw_state is not None:
            self._fwref_event(el, here_dynamic, fw_state)
            return
        for child in el:
            self._walk_msbuild(child, here_dynamic, path, state, possible_names,
                               fw_state)

    def _pkgref_event(self, el, dynamic: bool, path: Path, state: dict,
                      possible_names: list) -> None:
        inc, rem = el.get("Include"), el.get("Remove")
        if rem:
            key = rem.lower()
            if not dynamic:
                state.pop(key, None)                  # unconditional Remove cancels
            elif key in state:
                dep, _ = state[key]
                state[key] = (dep, "possible")        # unproven removal
                possible_names.append(rem)
        elif inc:
            dep = DeclaredDep(name=inc, ecosystem="nuget", source_file=path.name,
                              raw=inc, skip_registry="$(" in inc)
            if dynamic:
                if state.get(inc.lower(), (None, ""))[1] != "definite":
                    state[inc.lower()] = (dep, "possible")
                possible_names.append(inc)
            else:
                state[inc.lower()] = (dep, "definite")
        # Update="X" alone modifies an existing reference — declares nothing

    _PROJREF_DEPTH_CAP = 32

    def _fw_and_projrefs(self, path: Path) -> tuple[dict, list]:
        """STATIC read of one MSBuild file: (framework refs incl. the Sdk
        implicit one, ProjectReference edges as (raw_include, kind)). The
        conditional context of ItemGroup/Choose ancestors is inherited; a
        statically-false subtree is pruned; ReferenceOutputAssembly="false"
        (static) carries no compile-time framework, a DYNAMIC one degrades
        the edge to possible. No MSBuild, restore, or project code runs."""
        try:
            root = ET.fromstring(self._read(path))
        except (ET.ParseError, DefusedXmlException):
            return {}, []
        fw: dict[str, str] = {}
        sdk = (root.get("Sdk") or "").strip().lower()
        implied = self._SDK_IMPLICIT_FRAMEWORKS.get(sdk)
        if implied:
            fw[implied] = "definite"
        refs: list[tuple[str, str]] = []

        def walk(el, dynamic: bool) -> None:
            tag = el.tag.rsplit("}", 1)[-1]
            if self._const_false_condition(el):
                return
            here = dynamic or bool((el.get("Condition") or "").strip())                 or tag in ("When", "Otherwise")
            if tag == "FrameworkReference":
                self._fwref_event(el, here, fw)
                return
            if tag == "ProjectReference":
                inc = el.get("Include")
                if inc:
                    # ReferenceOutputAssembly is legal as an ATTRIBUTE and as
                    # CHILD METADATA (<ReferenceOutputAssembly>false</...>) —
                    # msbuild#1916; both forms must stop compile-time flow
                    roa = (el.get("ReferenceOutputAssembly") or "").strip()
                    for child in el:
                        ctag = child.tag.rsplit("}", 1)[-1]
                        if ctag == "ReferenceOutputAssembly":
                            roa = (child.text or "").strip()
                            if (child.get("Condition") or "").strip():
                                roa += "$("      # conditional metadata: dynamic
                    if roa.lower() == "false":
                        return          # static: no compile-time reference flows
                    dynamic_edge = here or "$(" in roa                         or (bool(roa) and roa.lower() != "true")
                    refs.append((inc, "possible" if dynamic_edge else "definite"))
                return
            for child in el:
                walk(child, here)

        walk(root, False)
        return fw, refs

    def _transitive_framework_refs(self, csproj: Path,
                                   visited: frozenset | None = None,
                                   depth: int = 0) -> dict:
        """Framework references REACHABLE from this csproj through its
        ProjectReference graph (its own file + its nearest ancestor
        Directory.Build.props, then each referenced csproj recursively).
        Repo-confined (the central _read symlink guard + an explicit escape
        check), cycle-safe via a resolved-path visited set, depth-capped.
        definite stays definite only through an all-definite chain; any
        conditional edge or conditional child ref degrades to possible. A
        DYNAMIC $(...) reference path cannot be followed statically: nothing
        is claimed, but the manifest is marked incomplete with a note that
        names the FILE NAME only (never a machine path)."""
        if visited is None:
            visited = frozenset()
        out: dict[str, str] = {}
        if depth > self._PROJREF_DEPTH_CAP:
            return out
        try:
            key = csproj.resolve().as_posix().lower()
        except OSError:
            return out
        if key in visited:
            return out                # CYCLE on the current recursion path only
        # recursion STACK, not a global visited: a diamond (A->B->D, A->C->D)
        # must evaluate D on BOTH paths so one definite chain wins — a global
        # set silently downgraded definite to possible (closing-round bug)
        visited = visited | {key}
        sources: list[tuple[dict, list]] = [self._fw_and_projrefs(csproj)]
        props, _ = self._nearest_ancestor_file(csproj.parent, "Directory.Build.props")
        if props is not None:
            sources.append(self._fw_and_projrefs(props))
        repo = self._confinement_root()
        for fw, refs in sources:
            for name, kind in fw.items():
                if out.get(name) != "definite":
                    out[name] = kind
            for raw, edge_kind in refs:
                if "$(" in raw:
                    self._note(f"{csproj.name}: dynamic ProjectReference path "
                               "($(...)) — transitive framework references "
                               "cannot be proven statically")
                    self._mark_incomplete(csproj)
                    continue
                target = (csproj.parent / raw.replace("\\", "/")).resolve()
                if target.suffix.lower() != ".csproj" or not target.is_file():
                    continue
                if repo is not None and target != repo                         and repo not in target.parents:
                    self._note(f"{csproj.name}: ProjectReference to "
                               f"{target.name} resolves outside the repository "
                               "— not followed")
                    continue
                child = self._transitive_framework_refs(target, visited, depth + 1)
                for name, ckind in child.items():
                    eff = "possible" if "possible" in (edge_kind, ckind)                         else "definite"
                    if out.get(name) != "definite":
                        out[name] = eff
        return out

    def _fwref_event(self, el, dynamic: bool, fw_state: dict) -> None:
        """FrameworkReference Include/Remove with the SAME conditional
        semantics as PackageReference: an unresolved condition yields
        POSSIBLE (never a silent definite fact), a statically-false subtree
        was already pruned by the walk. A FrameworkReference is a shared
        framework, NOT a NuGet package — it is never sent to any registry."""
        inc, rem = el.get("Include"), el.get("Remove")
        if rem:
            key = rem.strip().lower()
            if not dynamic:
                fw_state.pop(key, None)
            elif fw_state.get(key) == "definite":
                fw_state[key] = "possible"
        elif inc and "$(" not in inc:
            key = inc.strip().lower()
            if dynamic:
                if fw_state.get(key) != "definite":
                    fw_state[key] = "possible"
            else:
                fw_state[key] = "definite"

    def _finish_framework_refs(self, fw_merged: dict, csprojs: list) -> None:
        """Resolve the directory's framework references into provided-namespace
        prefixes. A POSSIBLE (conditional) reference suppresses definitive
        H002 for its namespaces but marks the manifest incomplete with a
        visible note — never a silent exact claim."""
        definite: list[str] = []
        possible: list[str] = []
        for key, kind in sorted(fw_merged.items()):
            prefixes = self._FRAMEWORK_PROVIDES.get(key)
            if prefixes is None:
                continue   # unmodeled framework: no namespace claims, no guess
            (definite if kind == "definite" else possible).extend(prefixes)
        self._fw_provides_definite = tuple(definite)
        self._fw_provides_possible = tuple(possible)
        if possible:
            proj = csprojs[0] if csprojs else None
            names = ", ".join(sorted(k for k, v in fw_merged.items()
                                     if v == "possible"))
            self._note(f"{proj.name if proj else 'project'}: conditional "
                       f"FrameworkReference ({names}) — presence not statically "
                       "provable; its namespaces are treated as POSSIBLY provided")
            if proj is not None:
                self._mark_incomplete(proj)

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
        # CP-8b.4: old / modern / UNKNOWN — unknown must not silently pass as
        # modern. When we cannot resolve the TFM, System.* stays external
        # (conservative: an unverifiable package-vs-BCL split), and the manifest
        # is marked incomplete so confidence drops and the verdict cannot PASS.
        self._tfm_class = self._classify_tfm(root)
        self._old_tfm = self._tfm_class in ("old", "unknown")
        if self._tfm_class == "unknown":
            self._diag_for_tfm(root)
        ns: set[str] = set()
        for sf in files:
            parse_source(sf)
            for node in captures("csharp", sf.tree.root_node, _NS_QUERY).get("ns", []):
                name = node.child_by_field_name("name")
                if name is not None:
                    ns.add(node_text(name))
        self._own_namespaces = tuple(sorted(ns))

    def _diag_for_tfm(self, root: Path) -> None:
        """Unknown TFM => a limitation the report must show + a manifest marked
        incomplete so confidence drops and the verdict cannot PASS."""
        proj = next(iter(root.glob("*.csproj")), None) or (root / "project")
        self._note(f"{proj.name}: TargetFramework could not be resolved "
                   "(missing or dynamic $(...)) — System.* BCL vs package split is "
                   "unverifiable; treated conservatively as package-delivered")
        self._mark_incomplete(proj)

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
        # shared-framework provided namespaces (FrameworkReference / Sdk.Web):
        # provided by the runtime, never a NuGet lookup. POSSIBLE references
        # also suppress definitive H002 (the manifest is already flagged
        # incomplete with a visible note at parse time).
        for prefix in self._fw_provides_definite + self._fw_provides_possible:
            if m == prefix or m.startswith(prefix + "."):
                return True
        if self._config_internal_match(m):
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

    def import_mapping_trust(self, imp: ImportRef) -> str:
        # CP-8.3: the .NET namespace -> package-id candidate is ALWAYS a generic
        # structural guess (there is no curated/authoritative map). So an absent
        # candidate degrades to H007, never a RED H008 — red requires a
        # documented mapping, which .NET does not have.
        return "guess"

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
        # a solution-level NuGet.config above the project also configures sources
        for d in self._config_search_dirs(root):
            for cfg_name in ("nuget.config", "NuGet.Config", "NuGet.config"):
                cfg = d / cfg_name
                if not cfg.is_file():
                    continue
                text = self._read(cfg)
                if "<packageSources>" in text and "nuget.org" not in text.split("<packageSources>")[-1]:
                    return f"custom <packageSources> configured in {cfg.as_posix()}"
                if "<packageSources>" in text and "<add" in text and \
                        text.count("<add") > text.count("api.nuget.org"):
                    return f"additional package sources configured in {cfg.as_posix()}"
        return None

    def file_language(self, path: Path) -> str:
        return "csharp"


# ── Rule Capability Catalog hook (owner: dotnet rules module) ───────────────
from auditor.adapters.dotnet import rules as _drules  # noqa: E402  (deliberate late import: catalog block lives next to its rules)


def _dotnet_rule_descriptors(self):
    return list(_drules.DESCRIPTORS)


DotnetAdapter.rule_descriptors = _dotnet_rule_descriptors  # type: ignore[method-assign]

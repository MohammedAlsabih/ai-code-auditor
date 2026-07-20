from __future__ import annotations

import ast as _ast
import re
import tomllib
from dataclasses import replace
from pathlib import Path

from auditor.adapters.python.aliases import IMPORT_TO_DIST
from auditor.core.interfaces import LanguageAdapter, SyntaxProfile
from auditor.core.models import DeclaredDep, Finding, ImportRef, Severity, SourceFile
from auditor.registries.pypi import canonical

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_VCS_SCHEMES = ("git+", "hg+", "svn+", "bzr+")
_URL_START = _VCS_SCHEMES + ("http://", "https://", "file://", "ftp://")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_INCLUDE_FLAGS = ("--requirement", "--constraint", "-r", "-c")
# Shared PyPI namespaces: the top-level import segment is NOT a distribution
# name (many dists contribute to google.*/azure.*/...), so an undeclared import
# under one cannot be mapped to a single registry id — we degrade to H007
# (unresolved) rather than guess a bogus package for a RED hallucination claim.
NAMESPACE_PREFIXES = frozenset({
    "google", "azure", "ruamel", "zope", "backports", "sphinxcontrib",
    "oslo", "paste", "repoze", "jaraco", "lazr", "odoo",
})


def _bound_versions(sset) -> list:
    """The NORMALIZED Version of every bound in the specifier set. Iterating the
    parsed Specifier objects (not regexing raw text) makes `3.13.0-rc1` and
    `3.13.0rc1` identical, exactly as PEP 440 defines them."""
    from packaging.version import InvalidVersion, Version
    out = []
    for spec in sset:
        text = spec.version
        if text.endswith(".*"):
            text = text[:-2]          # ==3.12.* — probe the prefix itself
        try:
            out.append(Version(text))
        except InvalidVersion:
            continue                  # e.g. ===arbitrary-string
    return out


def _reachable_minors(sset, max_minor: int) -> set[int]:
    """The set of 3.x minors admitted by the specifier: a synthetic patch sweep
    (0, a large sentinel, bound patch numbers ±1) plus each normalized bound
    version and its numeric neighbours (for prerelease-only ranges)."""
    from packaging.version import Version
    bounds = _bound_versions(sset)
    patches = {0, 10_000}
    for v in bounds:
        if len(v.release) >= 3 and v.release[0] == 3:
            p = v.release[2]
            patches.update({max(0, p - 1), p, p + 1})
    reachable: set[int] = set()
    for minor in range(0, max_minor + 1):
        if any(sset.contains(Version(f"3.{minor}.{c}"), prereleases=True) for c in patches):
            reachable.add(minor)
    literals: set[str] = set()
    for v in bounds:
        literals.update(_numeric_neighbours(str(v)))
    for lit in literals:
        try:
            v = Version(lit)
        except Exception:
            continue
        if sset.contains(v, prereleases=True) and len(v.release) >= 2 and v.release[0] == 3:
            reachable.add(v.release[1])
    return reachable


def _numeric_neighbours(lit: str) -> set[str]:
    """The literal plus variants with its LAST numeric group set to n-1/n/n+1 —
    turns a strict prerelease bound (3.13.0rc1) into a probe for the admitted
    value in between (3.13.0rc2). Gated later by SpecifierSet.contains, so
    over-generation on final versions is harmless."""
    runs = list(re.finditer(r"\d+", lit))
    if not runs:
        return {lit}
    last = runs[-1]
    n = int(last.group())
    out = {lit}
    for nn in (n - 1, n, n + 1):
        if nn >= 0:
            out.add(lit[:last.start()] + str(nn) + lit[last.end():])
    return out


def _const_bool(node) -> bool | None:
    """Statically resolve a literal `if True:` / `while False:` guard, else None
    (unknown). Handles a bare constant and a single `not` of one (CP-8b round 6)."""
    if isinstance(node, _ast.Constant):
        try:
            return bool(node.value)
        except Exception:
            return None
    if isinstance(node, _ast.UnaryOp) and isinstance(node.op, _ast.Not):
        inner = _const_bool(node.operand)
        return None if inner is None else (not inner)
    return None


class _SetupCtx:
    """Branch-aware binding state for the setup.py scanner (CP-8b round 5).
    `def_*` = bindings that hold on EVERY path so far; `poss_*` = bindings that
    hold on SOME path. A call resolvable via def_* is a real packaging call; via
    poss_* only is extracted but flags the manifest ambiguous."""

    def __init__(self, def_fn=None, def_mods=None, poss_fn=None, poss_mods=None):
        self.def_fn = set(def_fn or ())
        self.def_mods = set(def_mods or ())
        self.poss_fn = set(poss_fn or ())
        self.poss_mods = set(poss_mods or ())
        self.imported = False
        self.out: list = []
        self.found = False
        self.ambiguous = False

    def bind_fn(self, n):
        self.def_fn.add(n)
        self.poss_fn.add(n)

    def bind_mod(self, n):
        self.def_mods.add(n)
        self.poss_mods.add(n)

    def unbind(self, n):
        self.def_fn.discard(n)
        self.def_mods.discard(n)
        self.poss_fn.discard(n)
        self.poss_mods.discard(n)

    def clone(self) -> "_SetupCtx":
        c = _SetupCtx(self.def_fn, self.def_mods, self.poss_fn, self.poss_mods)
        c.imported = self.imported
        return c

    def merge(self, clones: list) -> None:
        """Fold path clones into this (parent) context. `clones` already includes
        a no-op clone (= parent unchanged) for a non-exhaustive construct, so the
        parent's pre-branch state participates AS a path — it is NOT OR-ed back in
        afterwards (that re-bound names a branch had unbound: CP-8b round 6).
        definite = INTERSECTION of clone def_*; possible = UNION of clone poss_*."""
        if not clones:
            return
        for b in clones:
            self.out += b.out
            self.found = self.found or b.found
            self.ambiguous = self.ambiguous or b.ambiguous
            self.imported = self.imported or b.imported
        self.def_fn = set.intersection(*(b.def_fn for b in clones))
        self.def_mods = set.intersection(*(b.def_mods for b in clones))
        self.poss_fn = set().union(*(b.poss_fn for b in clones))
        self.poss_mods = set().union(*(b.poss_mods for b in clones))


class PythonAdapter(LanguageAdapter):
    name = "python"
    ecosystem = "pypi"
    source_globs = (".py",)

    def __init__(self) -> None:
        self._internal_roots: set[str] = set()
        self._local_packages: set[str] = set()
        self._local_modules: set[str] = set()
        self._local_namespace: set[str] = set()

    def detect(self, root: Path) -> bool:
        if (root / "pyproject.toml").is_file() or (root / "setup.py").is_file() \
                or (root / "Pipfile").is_file():
            return True
        return any(root.glob("requirements*.txt"))

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        self._scan_root = root.resolve()   # confines -r/-c include following
        self._req_files_visited: list[Path] = []   # every req/constraint file read
        deps: list[DeclaredDep] = []
        seen_files: set[tuple[Path, bool]] = set()   # (resolved path, is_constraint)
        for req in sorted(root.glob("requirements*.txt")):
            deps += self._parse_requirements(req, seen_files)
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            deps += self._parse_pyproject(pyproject)
        pipfile = root / "Pipfile"
        if pipfile.is_file():
            deps += self._parse_pipfile(pipfile)
        setup = root / "setup.py"
        if setup.is_file():
            deps += self._parse_setup_py(setup)
        seen: set[str] = set()
        out = []
        for d in deps:
            if d.name not in seen:
                seen.add(d.name)
                out.append(d)
        self._last_declared = out   # cache: project_rules must NOT re-parse
        return out                  # (a bare re-call would reset self._diag)

    def _parse_requirements(self, path: Path, seen: set[tuple[Path, bool]],
                            depth: int = 0, constraint: bool = False) -> list[DeclaredDep]:
        rp = path.resolve()
        # the READ ROLE is part of the cycle key: the same file may legitimately
        # be read once as a constraint (-c, declares nothing) and once as a
        # requirement (-r, declares) — keying on path alone drops the second read
        key = (rp, constraint)
        if key in seen or depth > 10:
            return []
        seen.add(key)
        self._req_files_visited.append(rp)   # still scanned for --index-url later
        out: list[DeclaredDep] = []
        rel = self._provenance(rp)
        for i, raw in enumerate(self._read(path).splitlines(), 1):
            line = raw.split(" #", 1)[0].strip() if " #" in raw else raw.strip()
            if not line or line.startswith("#"):
                continue
            is_inc, fname, is_c = self._classify_include(line)
            if is_inc:
                out += self._follow_include(fname, is_c, path, rel, seen, depth, constraint)
                continue
            if constraint:
                continue     # a constraints file pins versions; it declares nothing
            if line.startswith(("-e", "--editable")):
                line = line.split(None, 1)[1].strip() if " " in line else ""
                if not line:
                    continue
            elif line.startswith("-"):
                continue                      # other pip options
            dep = self._req_dep(line, rel, i)
            if dep is not None:
                out.append(dep)
        return out

    def _provenance(self, path: Path) -> str:
        """Full scan-root-relative posix path so reqs/base.txt and a/base.txt vs
        b/base.txt never share a provenance label (point 4)."""
        try:
            return path.resolve().relative_to(self._scan_root).as_posix()
        except (ValueError, AttributeError):
            return path.name

    @staticmethod
    def _classify_include(line: str) -> tuple[bool, str | None, bool]:
        """(is_include_directive, filename_or_None, is_constraint). Handles both
        `-r file` and pip's attached `-rfile`, and the `--flag=file` form."""
        for flag, con in (("--requirement", False), ("--constraint", True),
                          ("-r", False), ("-c", True)):
            if line == flag:
                return True, None, con
            if line.startswith(flag):
                after = line[len(flag):]
                if flag.startswith("--") and after and after[0] not in " =":
                    continue                      # e.g. --requirements != --requirement
                return True, (after.lstrip(" =").strip().strip("'\"") or None), con
        return False, None, False

    def _follow_include(self, fname, is_c, path, rel, seen, depth, constraint):
        """Resolve + recurse into a -r/-c include. A missing file, or one
        escaping the REPOSITORY root, is an incompletely-read manifest — it
        lowers confidence and forbids PASS via _include_gap (CP-8.1/8.2). A
        shared file elsewhere in the same repo is followed normally."""
        role = "constraint" if is_c else "requirement"
        if not fname:
            self._include_gap(path, f"{rel}: empty {role} include directive")
            return []
        target = (path.parent / fname).resolve()
        if not target.is_file():
            self._include_gap(path, f"{rel}: {role} include not found: {fname}")
            return []
        root = self._confinement_root()
        if root is not None and not (target == root or root in target.parents):
            self._include_gap(path, f"{rel}: {role} include outside the repository, "
                                    f"NOT read: {fname}")
            return []
        return self._parse_requirements(target, seen, depth + 1,
                                        constraint=constraint or is_c)

    def _req_dep(self, line: str, rel: str, lineno: int) -> DeclaredDep | None:
        head = line.split(";", 1)[0].strip()   # drop environment marker
        # bare URL / VCS ref (checked FIRST so `https://...@host` is not mistaken
        # for a PEP 508 `name @ url`): never a PyPI name — use #egg or drop
        if head.startswith(_URL_START):
            egg = _EGG.search(line)
            if not egg:
                return None
            return DeclaredDep(name=canonical(egg.group(1)), ecosystem="pypi",
                               source_file=rel, line=lineno, raw=line, skip_registry=True)
        if "@" in head:                        # PEP 508 `name @ url`
            m = _REQ_NAME.match(head)
            if not m:
                return None
            return DeclaredDep(name=canonical(m.group(1)), ecosystem="pypi",
                               source_file=rel, line=lineno, raw=line, skip_registry=True)
        m = _REQ_NAME.match(head)
        if not m:
            return None
        return DeclaredDep(name=canonical(m.group(1)), ecosystem="pypi",
                           source_file=rel, line=lineno, raw=line, skip_registry=False)

    def _dep_string_list(self, value, path: Path, what: str) -> list[str]:
        """A list of PEP 508 strings, or [] + one diagnostic on a wrong type.
        Never str()->list-of-chars and never crash. Non-string list entries are
        dropped WITH a note (a bare 123 is not silently ignored)."""
        if value is None:
            return []
        if isinstance(value, list):
            strings = [s for s in value if isinstance(s, str)]
            if len(strings) != len(value):
                self._note(f"{path.name}: {len(value) - len(strings)} non-string "
                           f"entr(ies) in {what} ignored")
            return strings
        self._schema_note(path, what)
        return []

    def _parse_pyproject(self, path: Path) -> list[DeclaredDep]:
        try:
            data = tomllib.loads(self._read(path))
        except tomllib.TOMLDecodeError as e:
            self._manifest_error(path, e)
            return []
        if not isinstance(data, dict):
            self._schema_note(path, "top-level document")
            return []
        uv_local = self._uv_local_names(data, path)
        out: list[DeclaredDep] = []
        for spec in self._pep621_specs(data, path):
            dep = self._from_pep508(spec, path.name)
            if dep is None:
                continue
            if canonical(dep.name) in uv_local:
                dep = replace(dep, skip_registry=True)   # local/vcs/workspace uv source
            out.append(dep)
        out += self._poetry_deps(data, path)
        return out

    def _pep621_specs(self, data: dict, path: Path) -> list[str]:
        proj = data.get("project")
        if proj is not None and not isinstance(proj, dict):
            self._schema_note(path, "project")     # `project = "oops"` is NOT silent
            proj = {}
        proj = proj if isinstance(proj, dict) else {}
        specs = self._dep_string_list(proj.get("dependencies"), path, "project.dependencies")
        opt = proj.get("optional-dependencies")
        if isinstance(opt, dict):
            for name, group in opt.items():
                specs += self._dep_string_list(group, path,
                                               f"project.optional-dependencies.{name}")
        elif opt is not None:
            self._schema_note(path, "project.optional-dependencies")
        groups = data.get("dependency-groups")   # PEP 735
        if isinstance(groups, dict):
            for name, group in groups.items():
                specs += self._dep_string_list(group, path, f"dependency-groups.{name}")
        elif groups is not None:
            self._schema_note(path, "dependency-groups")
        return specs

    def _checked_table(self, data: dict, key: str, path: Path, label: str):
        """data[key] as a dict, or None — a wrong-typed section gets a schema
        note instead of a silent coercion."""
        value = data.get(key)
        if value is None or isinstance(value, dict):
            return value
        self._schema_note(path, label)
        return None

    def _poetry_deps(self, data: dict, path: Path) -> list[DeclaredDep]:
        tool = self._checked_table(data, "tool", path, "tool") or {}
        poetry = self._checked_table(tool, "poetry", path, "tool.poetry") or {}
        tables = []
        main = poetry.get("dependencies")
        if isinstance(main, dict):
            tables.append(main)
        elif main is not None:
            self._schema_note(path, "tool.poetry.dependencies")
        tables += self._poetry_group_tables(poetry, path)
        out = []
        for table in tables:
            for k, v in table.items():
                if k.lower() == "python":
                    continue
                skip = isinstance(v, dict) and any(
                    key in v for key in ("path", "git", "url", "file"))
                out.append(DeclaredDep(name=canonical(k), ecosystem="pypi",
                                       source_file=path.name, raw=f"{k} = {v!r}",
                                       skip_registry=skip))
        return out

    def _poetry_group_tables(self, poetry: dict, path: Path) -> list[dict]:
        groups = poetry.get("group")
        if groups is None:
            return []
        if not isinstance(groups, dict):
            self._schema_note(path, "tool.poetry.group")
            return []
        tables = []
        for gname, grp in groups.items():
            deps = grp.get("dependencies") if isinstance(grp, dict) else None
            if isinstance(deps, dict):
                tables.append(deps)
            elif not isinstance(grp, dict) or deps is not None:
                # a group that is not a table, or whose dependencies is a
                # list/string: declared deps would be silently DROPPED
                self._schema_note(path, f"tool.poetry.group.{gname}")
        return tables

    _UV_LOCAL_KEYS = ("path", "git", "url", "workspace")

    def _uv_local_names(self, data: dict, path: Path) -> set[str]:
        """Canonical names declared with a local/vcs/workspace [tool.uv.sources]
        entry — these resolve off-registry and must NOT be PyPI-checked (H001).
        uv also allows a LIST of conditional sources per name (marker-gated);
        conservative policy: if ANY alternative is local/vcs/workspace — even
        alongside an index entry — never claim H001 from a public lookup."""
        tool = data.get("tool")
        uv = tool.get("uv") if isinstance(tool, dict) else None
        sources = uv.get("sources") if isinstance(uv, dict) else None
        if sources is None:
            return set()
        if not isinstance(sources, dict):
            self._schema_note(path, "tool.uv.sources")
            return set()
        out: set[str] = set()
        for name, src in sources.items():
            entries = src if isinstance(src, list) else [src]
            tables = [e for e in entries if isinstance(e, dict)]
            if not tables:
                self._schema_note(path, f"tool.uv.sources.{name}")
                continue
            if any(k in e for e in tables for k in self._UV_LOCAL_KEYS):
                out.add(canonical(name))
        return out

    def _parse_pipfile(self, path: Path) -> list[DeclaredDep]:
        try:
            data = tomllib.loads(self._read(path))
        except tomllib.TOMLDecodeError as e:
            self._manifest_error(path, e)
            return []
        if not isinstance(data, dict):
            self._schema_note(path, "top-level document")
            return []
        out = []
        for section in ("packages", "dev-packages"):
            table = data.get(section)
            if table is None:
                continue
            if not isinstance(table, dict):
                self._schema_note(path, section)
                continue
            for name, spec in table.items():
                out.append(DeclaredDep(name=canonical(name), ecosystem="pypi",
                                       source_file=path.name, raw=f"{section}: {name} = {spec!r}",
                                       skip_registry=isinstance(spec, dict) and
                                       any(k in spec for k in ("path", "git", "file"))))
        return out

    def _from_pep508(self, spec: str, src: str) -> DeclaredDep | None:
        m = _REQ_NAME.match(spec.strip())
        if not m:
            return None
        return DeclaredDep(name=canonical(m.group(1)), ecosystem="pypi",
                           source_file=src, raw=spec, skip_registry="@" in spec)

    _SETUP_DEP_KWARGS = ("install_requires", "setup_requires", "tests_require")

    def _parse_setup_py(self, path: Path) -> list[DeclaredDep]:
        """AST-based, never executes the file: only literal lists inside the real
        setup(...) call count — a commented-out or string-embedded
        install_requires can no longer fabricate declared deps. Dynamic
        expressions surface as manifest_incomplete, not a silent []."""
        src = self._read(path)
        if not src:
            return []
        rel = self._provenance(path)
        try:
            tree = _ast.parse(src)
        except SyntaxError as e:
            self._manifest_error(path, e)
            return []
        out, found_call, imported = self._scan_setup_module(tree, rel, path)
        if not imported:
            # no setuptools/distutils import at all — a call named setup() here
            # is a local helper, not the packaging entry point (CP-8.10)
            return []
        if not found_call:
            # setuptools imported but NO statically-resolvable packaging call —
            # neither silently accept nor silently drop (CP-8b.2)
            self._dynamic_manifest(path, rel, "setup() call (none resolvable)")
        return out

    _FLOW_STMTS = (_ast.If, _ast.While, _ast.For, _ast.With, _ast.Try)
    # scopes whose body does NOT run at import time — a setup(...) inside one is
    # NOT a packaging call (CP-8b round 5)
    _DEFERRED = (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.Lambda,
                 _ast.ClassDef, _ast.GeneratorExp)

    def _scan_setup_module(self, tree, rel: str, path: Path):
        """MODULE-SCOPE name binding with BRANCH-AWARE flow (CP-8b round 5).
        Bindings are (definite, possible) sets: a branch (if/else, try/except)
        contributes to `possible`, and only the intersection across ALL branches
        stays `definite`. A setup call resolvable via `definite` is a real
        packaging call; one resolvable only via `possible` is extracted AND marks
        the manifest incomplete (ambiguous branch). Calls inside deferred scopes
        (lambda/def/genexpr) are never packaging calls. `result = setup(...)`
        stays detected (the RHS is scanned before the target is discarded)."""
        ctx = _SetupCtx()
        self._scan_setup_stmts(tree.body, ctx, rel, path)
        # any AMBIGUOUS (possible-only) resolution => incomplete
        if ctx.ambiguous:
            self._dynamic_manifest(path, rel, "conditional setup binding/call")
        return ctx.out, ctx.found, ctx.imported

    def _scan_setup_stmts(self, stmts, ctx: "_SetupCtx", rel: str, path: Path) -> None:
        for stmt in stmts:
            if isinstance(stmt, _ast.Import):
                for a in stmt.names:
                    if a.name.split(".")[0] in ("setuptools", "distutils"):
                        ctx.imported = True
                        ctx.bind_mod(a.asname or a.name.split(".")[0])
            elif isinstance(stmt, _ast.ImportFrom):
                if (stmt.module or "").split(".")[0] in ("setuptools", "distutils"):
                    ctx.imported = True
                    for a in stmt.names:
                        if a.name == "setup":
                            ctx.bind_fn(a.asname or "setup")
            elif isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
                ctx.unbind(stmt.name)              # module-level rebinding only —
            elif isinstance(stmt, (_ast.Assign, _ast.AnnAssign)):
                if stmt.value is not None:
                    self._scan_calls(stmt.value, ctx, rel, path)   # RHS first
                targets = stmt.targets if isinstance(stmt, _ast.Assign) else [stmt.target]
                for tgt in targets:
                    if isinstance(tgt, _ast.Name):
                        ctx.unbind(tgt.id)
            elif isinstance(stmt, self._FLOW_STMTS):
                self._scan_branches(stmt, ctx, rel, path)
            else:
                self._scan_calls(stmt, ctx, rel, path)

    def _scan_branches(self, stmt, ctx: "_SetupCtx", rel: str, path: Path) -> None:
        # each alternative runs on a CLONE; the parent keeps the INTERSECTION of
        # def_* as definite (only when the construct is EXHAUSTIVE — one branch
        # always runs) and the UNION of poss_* as possible (CP-8b round 5).
        if isinstance(stmt, _ast.Try):
            # try-body(+else) OR one handler always determines the outcome =>
            # exhaustive; finalbody ALWAYS runs => applied to the parent directly
            bodies = [list(stmt.body) + list(stmt.orelse or [])]
            bodies += [h.body for h in stmt.handlers]
            self._merge_branch_bodies(bodies, ctx, rel, path, exhaustive=True)
            if stmt.finalbody:
                self._scan_setup_stmts(stmt.finalbody, ctx, rel, path)
            return
        if isinstance(stmt, _ast.If):
            cond = _const_bool(stmt.test)             # evaluate `if True:` / `if False:`
            if cond is True:
                self._merge_branch_bodies([stmt.body], ctx, rel, path, exhaustive=True)
                return
            if cond is False:
                self._merge_branch_bodies([stmt.orelse or []], ctx, rel, path, exhaustive=True)
                return
            bodies = [stmt.body] + ([stmt.orelse] if stmt.orelse else [])
            exhaustive = bool(stmt.orelse)            # no `else` => body may be skipped
        elif isinstance(stmt, _ast.With):
            bodies, exhaustive = [stmt.body], True     # a with-body always runs
        elif isinstance(stmt, _ast.While):
            if _const_bool(stmt.test) is False:
                # `while False:` body is DEAD, but its ELSE always runs (python
                # while-else semantics: else runs when the loop exits normally —
                # including zero iterations). CP-8b round 7.
                if stmt.orelse:
                    self._merge_branch_bodies([stmt.orelse], ctx, rel, path,
                                              exhaustive=True)
                return
            bodies, exhaustive = [stmt.body], False    # may run 0 times otherwise
        else:                                          # For: body may run 0 times
            bodies = [stmt.body] + ([stmt.orelse] if getattr(stmt, "orelse", None) else [])
            exhaustive = False
        self._merge_branch_bodies(bodies, ctx, rel, path, exhaustive)

    def _merge_branch_bodies(self, bodies, ctx, rel, path, exhaustive):
        clones = []
        for body in bodies:
            sub = ctx.clone()
            self._scan_setup_stmts(body, sub, rel, path)
            clones.append(sub)
        if not exhaustive:
            clones.append(ctx.clone())                 # no-op path: the branch may not run
        ctx.merge(clones)

    def _scan_calls(self, node, ctx: "_SetupCtx", rel: str, path: Path) -> None:
        # walk the expression, treating any deferred scope (lambda/def/genexpr)
        # as a BARRIER — a setup(...) inside one is never run at import time
        stack = [node]
        while stack:
            cur = stack.pop()
            if isinstance(cur, self._DEFERRED):
                continue
            if isinstance(cur, _ast.Call):
                if self._is_setup_call(cur, ctx.def_fn, ctx.def_mods):
                    ctx.found = True
                    ctx.out += self._setup_call_deps(cur, rel, path)
                elif self._is_setup_call(cur, ctx.poss_fn, ctx.poss_mods):
                    # POSSIBLE-only (conditional binding): setup is bound on some
                    # path but not all. Do NOT add its deps to the CONFIRMED
                    # declarations (an unreachable/conditional dep must never
                    # silence H002/H007/H008) — just mark the manifest incomplete
                    # (CP-8b round 6).
                    ctx.found = True
                    ctx.ambiguous = True
            stack.extend(_ast.iter_child_nodes(cur))

    @staticmethod
    def _is_setup_call(call, fn_names: set, mod_aliases: set) -> bool:
        f = call.func
        if isinstance(f, _ast.Name):
            return f.id in fn_names
        # module-attribute form: st.setup(...) — ONLY on a bound module alias;
        # Helper().setup(...) has a Call object, not a bound Name => not packaging
        return (isinstance(f, _ast.Attribute) and f.attr == "setup"
                and isinstance(f.value, _ast.Name) and f.value.id in mod_aliases)

    def _setup_call_deps(self, call, rel: str, path: Path) -> list[DeclaredDep]:
        out: list[DeclaredDep] = []
        for kw in call.keywords:
            if kw.arg is None:
                # setup(**config): dependencies hidden in a dict we cannot
                # resolve statically — record the manifest as incomplete.
                self._dynamic_manifest(path, rel, "**kwargs")
            elif kw.arg in self._SETUP_DEP_KWARGS:
                out += self._static_spec_list(kw.value, kw.arg, rel, path)
            elif kw.arg == "extras_require":
                if isinstance(kw.value, _ast.Dict):
                    for v in kw.value.values:
                        out += self._static_spec_list(v, "extras_require", rel, path)
                else:
                    self._dynamic_manifest(path, rel, "extras_require")
        return out

    def _static_spec_list(self, node, arg: str, rel: str, path: Path) -> list[DeclaredDep]:
        """Literal list/tuple elements only. Per-element: a string constant keeps
        its own line; a non-literal element marks the manifest incomplete."""
        if not isinstance(node, (_ast.List, _ast.Tuple)):
            self._dynamic_manifest(path, rel, arg)
            return []
        out = []
        for elt in node.elts:
            if isinstance(elt, _ast.Constant) and isinstance(elt.value, str):
                d = self._from_pep508(elt.value, rel)
                if d is not None:
                    out.append(replace(d, line=elt.lineno))
            else:
                self._dynamic_manifest(path, rel, arg)
        return out

    def _dynamic_manifest(self, path: Path, rel: str, what: str) -> None:
        """A dependency expression we cannot resolve statically: note + mark the
        manifest partially extracted (drives analysis_confidence to 'partial')."""
        self._note(f"{rel}: dynamic/non-literal {what} in setup.py — "
                   "dependencies not fully extracted")
        self._mark_incomplete(path)

    _IMPORT_QUERY = "[(import_statement) (import_from_statement)] @imp"

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        self.ensure_grammars()
        self._last_files = files   # reused by project_rules (P008)
        # three distinct kinds of local names (a module FILE is not a package —
        # `import foo.x` fails at runtime when foo is foo.py, so it must NOT be
        # silenced as internal):
        packages: set[str] = set()     # dirs with __init__.py  -> claim subtree
        modules: set[str] = set()      # plain .py files        -> exact match only
        namespace: set[str] = set()    # PEP 420 dirs           -> exact match only
        for base in (root, root / "src", root / "lib"):
            if base.is_dir():
                self._scan_local(base, packages, modules, namespace)
        self._local_packages = packages
        self._local_modules = modules
        self._local_namespace = namespace
        self._internal_roots = {m.split(".")[0]
                                for m in (packages | modules | namespace)}

    @staticmethod
    def _scan_local(base: Path, packages: set[str], modules: set[str],
                    namespace: set[str], max_depth: int = 6) -> None:
        import os
        from auditor.core.walk import IGNORE_DIRS
        base_len = len(base.parts)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            rel = Path(dirpath).parts[base_len:]
            if len(rel) > max_depth:
                dirnames[:] = []
                continue
            if rel:   # a subdirectory of base
                dotted = ".".join(rel)
                (packages if "__init__.py" in filenames else namespace).add(dotted)
            for f in filenames:
                if f.endswith(".py") and f != "__init__.py":
                    stem = f[:-3]
                    modules.add(".".join(rel + (stem,)) if rel else stem)

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, parse_source
        self.ensure_grammars()   # contract: safe for standalone callers (no prepare)
        out: list[ImportRef] = []
        for sf in files:
            parse_source(sf)
            for node in captures("python", sf.tree.root_node, self._IMPORT_QUERY).get("imp", []):
                out += self._imports_from_node(node, sf.rel)
        return out

    def _imports_from_node(self, node, rel: str) -> list[ImportRef]:
        from auditor.core.treesitter import line_of, node_text
        refs: list[ImportRef] = []
        if node.type == "import_statement":
            for child in node.named_children:
                target = child.child_by_field_name("name") if child.type == "aliased_import" else child
                if target is not None and target.type == "dotted_name":
                    mod = node_text(target)
                    refs.append(ImportRef(module=mod, file=rel, line=line_of(node),
                                          top_level=mod.split(".")[0]))
        else:  # import_from_statement
            mod_node = node.child_by_field_name("module_name")
            if mod_node is None or mod_node.type == "relative_import":
                return []  # relative import => local by definition
            mod = node_text(mod_node)
            refs.append(ImportRef(module=mod, file=rel, line=line_of(node),
                                  top_level=mod.split(".")[0]))
        return refs

    # Removed-from-stdlib names (PEP 594 + PEP 632 + imp/lib2to3), keyed by the
    # version that removed them.
    REMOVED_STDLIB = {
        "distutils": (3, 12), "imp": (3, 12), "asynchat": (3, 12), "asyncore": (3, 12),
        "smtpd": (3, 12), "telnetlib": (3, 13), "cgi": (3, 13), "cgitb": (3, 13),
        "pipes": (3, 13), "crypt": (3, 13), "nis": (3, 13), "spwd": (3, 13),
        "ossaudiodev": (3, 13), "audioop": (3, 13), "aifc": (3, 13), "sunau": (3, 13),
        "chunk": (3, 13), "mailcap": (3, 13), "msilib": (3, 13), "nntplib": (3, 13),
        "sndhdr": (3, 13), "uu": (3, 13), "xdrlib": (3, 13), "imghdr": (3, 13),
        "lib2to3": (3, 13),
    }
    # Modules ADDED after old floors — introduced_in + the backport dist that
    # makes the import legitimate on older floors.
    ADDED_STDLIB = {"zoneinfo": ((3, 9), "backports-zoneinfo"),
                    "graphlib": ((3, 9), "graphlib-backport"),
                    "tomllib": ((3, 11), "tomli")}
    # Removed modules that a declared dist legitimately re-provides:
    REMOVED_BACKPORTS = {"distutils": "setuptools"}

    def apply_config(self, config) -> None:
        super().apply_config(config)
        # accept both spellings: the ecosystem key (pypi) and the runtime (python)
        self._extra_builtins = frozenset(
            (*config.runtime_builtins.get("pypi", ()),
             *config.runtime_builtins.get("python", ())))

    _extra_builtins: frozenset = frozenset()

    def is_internal(self, imp: ImportRef) -> bool:
        import sys
        top = imp.top_level
        if top in sys.stdlib_module_names or top == "__future__" \
                or top in self.REMOVED_STDLIB or top in self._extra_builtins:
            return True
        if self._config_internal_match(imp.module) or self._config_internal_match(top):
            return True
        mod = imp.module
        # module FILES and namespace dirs own only names that actually exist on
        # disk (every existing child is itself in one of the scanned sets);
        # ONLY a regular package (__init__.py) claims its whole dotted subtree.
        # So foo.py does NOT make `import foo.nonexistent` internal, and a local
        # `google/myapp` does NOT make `google.cloud.x` internal.
        if mod in self._local_modules or mod in self._local_namespace:
            return True
        return any(mod == p or mod.startswith(p + ".") for p in self._local_packages)

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        names = {canonical(imp.top_level)}
        alias = IMPORT_TO_DIST.get(imp.top_level)
        if alias:
            names.add(canonical(alias))
        mod = imp.module
        for dep in declared:
            cn = canonical(dep.name)
            if cn in names:
                return dep
            # dash->dot distribution heuristic: a declared google-cloud-storage
            # provides google.cloud.storage; requests provides requests.sessions.
            # This confirms the KNOWN declared package against a namespace import
            # before any H002/H008 is emitted (no false "undeclared").
            dotted = cn.replace("-", ".")
            if mod == dotted or mod.startswith(dotted + "."):
                return dep
        return None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        top = imp.top_level
        if top in NAMESPACE_PREFIXES:
            return []   # shared namespace => no reliable single registry id
        if top.startswith("win32") or top in ("pythoncom", "pywintypes"):
            return ["pywin32"]
        alias = IMPORT_TO_DIST.get(top)
        if alias:
            return [canonical(alias)]   # curated => reliable mapping
        # a multi-segment import with no curated mapping is NOT confidently a
        # single distribution (top-level could be an unknown namespace) — return
        # no candidate so the engine emits H007 (heuristic) instead of a RED H008.
        # Map breadth is therefore NOT the only guard against false hallucinations.
        if "." in imp.module:
            return []
        return [canonical(top)]   # single-segment: the import==dist convention

    def import_mapping_trust(self, imp: ImportRef) -> str:
        """TRUST POLICY (CP-3): import-name == PyPI-name is a packaging
        CONVENTION, not a guarantee — any distribution may provide any module
        (biopython->Bio, djangorestframework->rest_framework). So only the
        curated alias table is "exact"; the identity convention is "heuristic",
        which (in core) forbids a definitive RED H008 whenever an unmatched
        declared distribution could be the module's real provider."""
        top = imp.top_level
        if (top in IMPORT_TO_DIST or top.startswith("win32")
                or top in ("pythoncom", "pywintypes")):
            return "exact"
        return "heuristic"

    def grammars(self) -> dict[str, object]:
        import tree_sitter_python
        return {"python": tree_sitter_python.language()}

    def syntax(self):
        return SyntaxProfile(
            catch_query="(except_clause) @c",
            catch_body_types=("block",),
            is_swallow_stmt=lambda s: s.type == "pass_statement" or (
                s.type == "expression_statement" and s.named_children
                and s.named_children[0].type == "ellipsis"),
            sql_concat_query="(binary_operator) @n",
            sql_interp_query="(string) @n",
            sql_dynamic_types=("interpolation",),
        )

    def private_registry_reason(self, root: Path) -> str | None:
        markers = ("--index-url", "-i ", "--extra-index-url", "--no-index", "--find-links")
        # every requirement/constraint file actually read (incl. -r/-c includes),
        # not just a root glob that misses reqs/private.txt
        candidates = list(getattr(self, "_req_files_visited", [])) \
            or list(root.glob("requirements*.txt"))
        for req in candidates:
            if not Path(req).is_file():
                continue
            text = self._read(Path(req))
            if any(line.strip().startswith(markers) for line in text.splitlines()):
                return f"custom index configured in {Path(req).name}"
        # pyproject index config, project dir and repo ancestors (a repo-level
        # pip.conf / .pypirc equivalent lives above the project)
        for d in self._config_search_dirs(root):
            pyproject = d / "pyproject.toml"
            if not pyproject.is_file():
                continue
            try:
                data = tomllib.loads(self._read(pyproject))
            except tomllib.TOMLDecodeError:
                continue
            tool = data.get("tool") if isinstance(data, dict) else None
            tool = tool if isinstance(tool, dict) else {}
            uv = tool.get("uv")
            uv = uv if isinstance(uv, dict) else {}
            poetry = tool.get("poetry")
            poetry = poetry if isinstance(poetry, dict) else {}
            if uv.get("index") or poetry.get("source"):
                return f"custom index configured in {pyproject.as_posix()}"
        return None

    def _requires_python_state(self, root: Path):
        """(state, allowed_minors|None, unavailable_reason|None) where state is
        'absent' | 'unparseable' | 'out_of_model' | 'ok'. Reads pyproject ONCE;
        the parsed SpecifierSet feeds the minor computation directly. The states
        are precise: the KEY being absent is the only not-applicable case; a
        present-but-unusable value (non-string, empty, invalid specifier) is an
        INABILITY; a VALID spec admitting no modeled Python 3 minor (e.g. >=4)
        is out_of_model — never called 'invalid'."""
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        pyproject = root / "pyproject.toml"
        if not pyproject.is_file():
            return "absent", None, None
        try:
            data = tomllib.loads(self._read(pyproject))
        except tomllib.TOMLDecodeError:
            return ("unparseable", None,
                    "pyproject.toml is not parseable (requires-python unknown)")
        proj = data.get("project")
        if not isinstance(proj, dict) or "requires-python" not in proj:
            return "absent", None, None
        spec = proj["requires-python"]
        if not isinstance(spec, str) or not spec.strip():
            return ("unparseable", None,
                    "requires-python present but not analyzable "
                    f"(expected a non-empty string, got {type(spec).__name__})")
        try:
            sset = SpecifierSet(spec.strip())
        except InvalidSpecifier:
            return ("unparseable", None,
                    "requires-python present but not analyzable (invalid specifier)")
        allowed = self._minors_from_spec(sset)
        if allowed is None:
            return ("out_of_model", None,
                    "valid requires-python range is outside the modeled Python 3 minors")
        return "ok", allowed, None

    _P008_GROUP = ("P008",)

    def project_rules(self, root: Path, frameworks: list[str],
                      ledger=None, diag=None) -> list:
        """P008 (blue): stdlib drift relative to the project's OWN
        requires-python range. Records its OWN execution evidence (B2-B):
        eligible/attempted when requires-python is usable, not_applicable when
        absent, unavailable when present-but-unparseable — never a fabricated
        finding. Detection logic and results are unchanged."""
        from auditor.core.execution import record_project_pass
        state, allowed, reason = self._requires_python_state(root)
        if state == "absent":
            if ledger is not None:
                ledger.not_applicable(
                    self._P008_GROUP, "no requires-python declared in this project")
            return []
        if state != "ok":     # unparseable / out_of_model: an inability, with
            if ledger is not None:      # the PRECISE reason — never fabricated
                ledger.unavailable(self._P008_GROUP, reason)
            if diag is not None and hasattr(diag, "rule_errors"):
                note = f"P008: {reason}"
                if note not in diag.rule_errors:
                    diag.rule_errors.append(note)
            return []
        try:
            out = self._p008_findings(root, allowed)
        except Exception as e:  # noqa: BLE001 — a broken pass records + continues
            if diag is not None and hasattr(diag, "rule_errors"):
                diag.rule_errors.append(f"P008 on {root}: {e.__class__.__name__}")
            return record_project_pass(ledger, diag, self._P008_GROUP, [], failed=True)
        return record_project_pass(ledger, diag, self._P008_GROUP, out)

    def _p008_findings(self, root: Path, allowed) -> list:
        cached = getattr(self, "_last_declared", None)
        declared = {d.name for d in (cached if cached is not None
                                     else self.parse_dependencies(root))}
        out = []
        files = getattr(self, "_last_files", [])
        for imp in self.extract_imports(files):
            top = imp.top_level
            if top in self._internal_roots:
                continue   # a local module shadows the stdlib name => not stdlib
            removed_in = self.REMOVED_STDLIB.get(top)
            if removed_in and self.REMOVED_BACKPORTS.get(top) not in declared:
                msg = self._judge_removed(allowed, removed_in, top)
                if msg:
                    out.append(self._p008(imp, msg))
            added = self.ADDED_STDLIB.get(top)
            if added and added[1] not in declared:
                msg = self._judge_added(allowed, added[0], top, added[1])
                if msg:
                    out.append(self._p008(imp, msg))
        return out

    @staticmethod
    def _judge_removed(allowed, removed, top) -> str | None:
        if all(v < removed for v in allowed):
            return None                      # range ends before the removal
        if all(v >= removed for v in allowed):
            return (f"{top} was removed in Python {removed[0]}.{removed[1]} and every "
                    "version this project allows is at or above the removal.")
        return (f"{top} was removed in Python {removed[0]}.{removed[1]}; the allowed "
                "version range CROSSES the removal — ambiguous, breaks on the newer "
                "interpreters the project claims to support.")

    @staticmethod
    def _judge_added(allowed, introduced, top, backport) -> str | None:
        if all(v >= introduced for v in allowed):
            return None                      # always available in range
        if all(v < introduced for v in allowed):
            return (f"{top} exists only since Python {introduced[0]}.{introduced[1]} "
                    "and is NEVER available in this project's declared range; declare "
                    f"the '{backport}' backport or raise requires-python.")
        return (f"{top} exists only since Python {introduced[0]}.{introduced[1]} but the "
                f"allowed range includes older versions without the '{backport}' backport "
                "— breaks on the older interpreters the project claims to support.")

    @staticmethod
    def _p008(imp, detail: str):
        return Finding(rule_id="P008", severity=Severity.BLUE,
                       title="stdlib availability mismatch within the project's requires-python range",
                       file=imp.file, line=imp.line, snippet=imp.module,
                       detail=detail, language="python", engine="auditor")

    _MAX_MINOR = 20

    def _minors_from_spec(self, sset):
        """Which 3.x minors an already-parsed SpecifierSet admits, judged via
        PEP 440 `packaging`. A minor counts as reachable if ANY patch of it
        satisfies the spec. Candidate patches are boundary-derived — {0, a large
        sentinel, and every patch literal in the spec ±1} — so exact/edge specs
        like ==3.12.26 or >3.12.25,<3.13 are handled without a fixed patch cap
        (which would have missed patch numbers above the cap). Returns sorted
        allowed (3, minor) tuples, or None when the range admits none."""
        reachable = _reachable_minors(sset, self._MAX_MINOR)
        allowed = sorted((3, m) for m in reachable)
        return allowed or None

    def _allowed_minors(self, root: Path):
        """Legacy convenience wrapper (standalone callers/tests): the allowed
        minors, or None when unspecified/invalid/out-of-model => no P008 claims.
        project_rules does NOT use this — it goes through
        _requires_python_state, which reads pyproject exactly once."""
        state, allowed, _reason = self._requires_python_state(root)
        return allowed if state == "ok" else None


# ── Rule Capability Catalog (owned HERE: P008 is a Python-project rule) ─────
from auditor.core.catalog import RuleDescriptor as _RD  # noqa: E402  (deliberate late import: catalog block lives next to its rules)

DESCRIPTORS = [
    _RD("P008", "Stdlib drift vs requires-python",
        "Imports use stdlib modules added after (or removed before) the project's declared requires-python range.",
        category="stdlib", default_level="note", default_precision="exact",
        engine="pattern-engine", scope="project", source="builtin",
        languages=("python",)),
]


def _python_rule_descriptors(self):
    return list(DESCRIPTORS)


PythonAdapter.rule_descriptors = _python_rule_descriptors  # type: ignore[method-assign]

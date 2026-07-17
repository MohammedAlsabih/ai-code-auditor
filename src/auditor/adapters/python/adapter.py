from __future__ import annotations

import re
import tomllib
from dataclasses import replace
from pathlib import Path

from auditor.adapters.python.aliases import IMPORT_TO_DIST
from auditor.core.interfaces import LanguageAdapter, SyntaxProfile
from auditor.core.models import DeclaredDep, Finding, ImportRef, Severity, SourceFile
from auditor.registries.pypi import canonical

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SETUP_LIST = re.compile(r"install_requires\s*=\s*\[(.*?)\]", re.S)
_QUOTED = re.compile(r"""["']([^"']+)["']""")
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


def _reachable_minors(sset, spec: str, max_minor: int) -> set[int]:
    """The set of 3.x minors admitted by the specifier: a synthetic patch sweep
    (0, a large sentinel, spec patch literals ±1) plus explicit version literals
    and their numeric neighbours (for prerelease-only ranges)."""
    from packaging.version import Version
    patches = {0, 10_000}
    for mt in re.finditer(r"3\.\d+\.(\d+)", spec):
        p = int(mt.group(1))
        patches.update({max(0, p - 1), p, p + 1})
    reachable: set[int] = set()
    for minor in range(0, max_minor + 1):
        if any(sset.contains(Version(f"3.{minor}.{c}"), prereleases=True) for c in patches):
            reachable.add(minor)
    literals: set[str] = set()
    for mt in re.finditer(r"3\.\d+(?:\.\w+)*", spec):
        literals.update(_numeric_neighbours(mt.group(0)))
    for lit in literals:
        try:
            v = Version(lit)
        except Exception:
            continue
        if sset.contains(v, prereleases=True) and len(v.release) >= 2:
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


class PythonAdapter(LanguageAdapter):
    name = "python"
    ecosystem = "pypi"
    source_globs = (".py",)

    def __init__(self) -> None:
        self._internal_roots: set[str] = set()
        self._local_regular: set[str] = set()
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
        """Resolve + recurse into a -r/-c include, recording a diagnostic note
        for a missing file or one escaping the scan root (never silent)."""
        role = "constraint" if is_c else "requirement"
        if not fname:
            self._note(f"{rel}: empty {role} include directive")
            return []
        target = (path.parent / fname).resolve()
        if not target.is_file():
            self._note(f"{rel}: {role} include not found: {fname}")
            return []
        if not (target == self._scan_root or self._scan_root in target.parents):
            self._note(f"{rel}: {role} include outside scan root, NOT read: {fname}")
            return []
        return self._parse_requirements(target, seen, depth + 1,
                                        constraint=constraint or is_c)

    def _note(self, message: str) -> None:
        if self._diag is not None:
            self._diag.notes.append(message)

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

    def _schema_note(self, path: Path, what: str) -> None:
        if self._diag is not None:
            self._diag.notes.append(
                f"{path.name}: unexpected schema for {what} — section skipped")

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
        uv_local = self._uv_local_names(data)
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

    def _poetry_deps(self, data: dict, path: Path) -> list[DeclaredDep]:
        tool = data.get("tool")
        poetry = tool.get("poetry") if isinstance(tool, dict) else None
        poetry = poetry if isinstance(poetry, dict) else {}
        tables = []
        main = poetry.get("dependencies")
        if isinstance(main, dict):
            tables.append(main)
        elif main is not None:
            self._schema_note(path, "tool.poetry.dependencies")
        groups = poetry.get("group")
        if isinstance(groups, dict):
            for grp in groups.values():
                if isinstance(grp, dict) and isinstance(grp.get("dependencies"), dict):
                    tables.append(grp["dependencies"])
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

    @staticmethod
    def _uv_local_names(data: dict) -> set[str]:
        """Canonical names declared with a local/vcs/workspace [tool.uv.sources]
        entry — these resolve off-registry and must NOT be PyPI-checked (H001)."""
        tool = data.get("tool")
        uv = tool.get("uv") if isinstance(tool, dict) else None
        sources = uv.get("sources") if isinstance(uv, dict) else None
        if not isinstance(sources, dict):
            return set()
        local_keys = ("path", "git", "url", "workspace")
        return {canonical(name) for name, src in sources.items()
                if isinstance(src, dict) and any(k in src for k in local_keys)}

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

    def _parse_setup_py(self, path: Path) -> list[DeclaredDep]:
        m = _SETUP_LIST.search(self._read(path))
        if not m:
            return []
        return [d for d in (self._from_pep508(s, path.name) for s in _QUOTED.findall(m.group(1)))
                if d is not None]

    _IMPORT_QUERY = "[(import_statement) (import_from_statement)] @imp"

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        self.ensure_grammars()
        self._last_files = files   # reused by project_rules (P008)
        regular: set[str] = set()      # regular packages / .py file modules (claim subtree)
        namespace: set[str] = set()    # PEP 420 namespace dirs (claim only exact + children)
        for base in (root, root / "src", root / "lib"):
            if base.is_dir():
                self._scan_local(base, regular, namespace)
        self._local_regular = regular
        self._local_namespace = namespace
        self._internal_roots = {m.split(".")[0] for m in (regular | namespace)}

    @staticmethod
    def _scan_local(base: Path, regular: set[str], namespace: set[str],
                    max_depth: int = 6) -> None:
        import os
        from auditor.core.walk import IGNORE_DIRS
        base_len = len(base.parts)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            rel = Path(dirpath).parts[base_len:]
            if len(rel) > max_depth:
                dirnames[:] = []
                continue
            if rel:   # a subdirectory of base: a package (regular if __init__.py)
                dotted = ".".join(rel)
                (regular if "__init__.py" in filenames else namespace).add(dotted)
            for f in filenames:
                if f.endswith(".py") and f != "__init__.py":
                    stem = f[:-3]
                    regular.add(".".join(rel + (stem,)) if rel else stem)

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

    def is_internal(self, imp: ImportRef) -> bool:
        import sys
        top = imp.top_level
        if top in sys.stdlib_module_names or top == "__future__" \
                or top in self.REMOVED_STDLIB:
            return True
        mod = imp.module
        if mod in self._local_regular or mod in self._local_namespace:
            return True
        # a regular local module (package with __init__ or a .py file) claims its
        # whole dotted subtree; a namespace dir claims ONLY itself and existing
        # children (so a local `google.myapp` does NOT make `google.cloud.X`
        # internal — that resolves to the external google-cloud package)
        return any(mod == m or mod.startswith(m + ".") for m in self._local_regular)

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
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = tomllib.loads(self._read(pyproject))
            except tomllib.TOMLDecodeError:
                return None
            tool = data.get("tool") if isinstance(data, dict) else None
            tool = tool if isinstance(tool, dict) else {}
            uv = tool.get("uv")
            uv = uv if isinstance(uv, dict) else {}
            poetry = tool.get("poetry")
            poetry = poetry if isinstance(poetry, dict) else {}
            if uv.get("index") or poetry.get("source"):
                return "custom index configured in pyproject.toml"
        return None

    def project_rules(self, root: Path, frameworks: list[str]) -> list:
        """P008 (blue): stdlib drift in BOTH directions relative to the project's
        OWN requires-python range. Emitted ONLY when requires-python is
        parseable. A declared backport silences the finding."""
        allowed = self._allowed_minors(root)
        if not allowed:
            return []
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

    def _allowed_minors(self, root: Path):
        """Which 3.x minors the requires-python range admits, judged via PEP 440
        `packaging`. A minor counts as reachable if ANY patch of it satisfies the
        spec. Candidate patches are boundary-derived — {0, a large sentinel, and
        every patch literal in the spec ±1} — so exact/edge specs like
        ==3.12.26 or >3.12.25,<3.13 are handled without a fixed patch cap (which
        would have missed patch numbers above the cap). Returns sorted allowed
        (3, minor) tuples, or None when unspecified/invalid => no P008 claims."""
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        pyproject = root / "pyproject.toml"
        if not pyproject.is_file():
            return None
        try:
            data = tomllib.loads(self._read(pyproject))
        except tomllib.TOMLDecodeError:
            return None
        proj = data.get("project")
        spec = proj.get("requires-python") if isinstance(proj, dict) else None
        if not isinstance(spec, str) or not spec.strip():
            return None   # absent or malformed (e.g. a list) => no P008 claims
        spec = spec.strip()
        try:
            sset = SpecifierSet(spec)
        except InvalidSpecifier:
            return None
        reachable = _reachable_minors(sset, spec, self._MAX_MINOR)
        allowed = sorted((3, m) for m in reachable)
        return allowed or None

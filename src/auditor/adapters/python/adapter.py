from __future__ import annotations

import re
import tomllib
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


def _dir_has_py(d: Path, max_depth: int = 3) -> bool:
    """True if the directory tree (bounded) contains any .py file — treats the
    dir as the project's own package even without __init__.py (PEP 420)."""
    from auditor.core.walk import IGNORE_DIRS
    import os
    base_depth = len(d.parts)
    for dirpath, dirnames, filenames in os.walk(d):
        dirnames[:] = [n for n in dirnames if n not in IGNORE_DIRS]
        if len(Path(dirpath).parts) - base_depth > max_depth:
            dirnames[:] = []
            continue
        if any(f.endswith(".py") for f in filenames):
            return True
    return False


class PythonAdapter(LanguageAdapter):
    name = "python"
    ecosystem = "pypi"
    source_globs = (".py",)

    def __init__(self) -> None:
        self._internal_roots: set[str] = set()

    def detect(self, root: Path) -> bool:
        if (root / "pyproject.toml").is_file() or (root / "setup.py").is_file() \
                or (root / "Pipfile").is_file():
            return True
        return any(root.glob("requirements*.txt"))

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        self._scan_root = root.resolve()   # confines -r/-c include following
        deps: list[DeclaredDep] = []
        seen_files: set[Path] = set()
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

    def _parse_requirements(self, path: Path, seen: set[Path],
                            depth: int = 0) -> list[DeclaredDep]:
        rp = path.resolve()
        if rp in seen or depth > 10:
            return []
        seen.add(rp)
        out: list[DeclaredDep] = []
        rel = path.name
        for i, raw in enumerate(self._read(path).splitlines(), 1):
            line = raw.split(" #", 1)[0].strip() if " #" in raw else raw.strip()
            if not line or line.startswith("#"):
                continue
            inc = self._include_target(line, path)
            if inc is not None:
                out += self._parse_requirements(inc, seen, depth + 1)
                continue
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

    def _include_target(self, line: str, path: Path) -> Path | None:
        """Resolve a -r/-c include to a file INSIDE the scan root, else None."""
        for flag in _INCLUDE_FLAGS:
            if line == flag or line.startswith(flag + " ") or line.startswith(flag + "="):
                rest = line[len(flag):].lstrip(" =").strip().strip("'\"")
                if not rest:
                    return None
                target = (path.parent / rest).resolve()
                if target.is_file() and (target == self._scan_root
                                         or self._scan_root in target.parents):
                    return target
                return None
        return None

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

    def _parse_pyproject(self, path: Path) -> list[DeclaredDep]:
        try:
            data = tomllib.loads(self._read(path))
        except tomllib.TOMLDecodeError as e:
            self._manifest_error(path, e)
            return []
        specs: list[str] = list(data.get("project", {}).get("dependencies", []))
        for group in data.get("project", {}).get("optional-dependencies", {}).values():
            specs += list(group)
        # PEP 735 [dependency-groups]: list items are PEP 508 strings or
        # {include-group=...} tables (the latter reference other groups we also read)
        for group in data.get("dependency-groups", {}).values():
            if isinstance(group, list):
                specs += [s for s in group if isinstance(s, str)]
        out = [self._from_pep508(s, path.name) for s in specs]
        # Poetry: main + all group tables (Poetry 1.2+ [tool.poetry.group.*])
        poetry = data.get("tool", {}).get("poetry", {})
        poetry_tables = [poetry.get("dependencies", {})]
        for grp in poetry.get("group", {}).values():
            if isinstance(grp, dict):
                poetry_tables.append(grp.get("dependencies", {}))
        for table in poetry_tables:
            for k, v in table.items():
                if k.lower() == "python":
                    continue
                skip = isinstance(v, dict) and any(
                    key in v for key in ("path", "git", "url", "file"))
                out.append(DeclaredDep(name=canonical(k), ecosystem="pypi",
                                       source_file=path.name, raw=f"{k} = {v!r}",
                                       skip_registry=skip))
        return [d for d in out if d is not None]

    def _parse_pipfile(self, path: Path) -> list[DeclaredDep]:
        try:
            data = tomllib.loads(self._read(path))
        except tomllib.TOMLDecodeError as e:
            self._manifest_error(path, e)
            return []
        out = []
        for section in ("packages", "dev-packages"):
            for name, spec in (data.get(section) or {}).items():
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
        roots: set[str] = set()
        for base in (root, root / "src", root / "lib"):
            if base.is_dir():
                self._collect_roots(base, roots)
        self._internal_roots = roots

    @staticmethod
    def _collect_roots(base: Path, roots: set[str]) -> None:
        from auditor.core.walk import IGNORE_DIRS
        try:
            children = list(base.iterdir())
        except OSError:
            return
        for child in children:
            if child.suffix == ".py":
                roots.add(child.stem)
            elif child.is_dir() and child.name not in IGNORE_DIRS \
                    and _dir_has_py(child):
                # regular package (__init__.py) OR PEP 420 namespace package OR
                # any repo-local source dir — all are the project's own code
                roots.add(child.name)

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
        return top in sys.stdlib_module_names or top == "__future__" \
            or top in self.REMOVED_STDLIB or top in self._internal_roots

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        names = {canonical(imp.top_level)}
        alias = IMPORT_TO_DIST.get(imp.top_level)
        if alias:
            names.add(canonical(alias))
        for dep in declared:
            if canonical(dep.name) in names:
                return dep
        return None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        alias = IMPORT_TO_DIST.get(imp.top_level)
        return [canonical(alias)] if alias else [canonical(imp.top_level)]

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
        for req in root.glob("requirements*.txt"):
            text = self._read(req)
            if any(line.strip().startswith(markers) for line in text.splitlines()):
                return f"custom index configured in {req.name}"
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = tomllib.loads(self._read(pyproject))
            except tomllib.TOMLDecodeError:
                return None
            tool = data.get("tool", {})
            if tool.get("uv", {}).get("index") or tool.get("poetry", {}).get("source"):
                return "custom index configured in pyproject.toml"
        return None

    def project_rules(self, root: Path, frameworks: list[str]) -> list:
        """P008 (blue): stdlib drift in BOTH directions relative to the project's
        OWN requires-python range. Emitted ONLY when requires-python is
        parseable. A declared backport silences the finding."""
        allowed = self._allowed_minors(root)
        if not allowed:
            return []
        floor = min(allowed)
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
        from packaging.version import Version
        pyproject = root / "pyproject.toml"
        if not pyproject.is_file():
            return None
        try:
            data = tomllib.loads(self._read(pyproject))
        except tomllib.TOMLDecodeError:
            return None
        spec = data.get("project", {}).get("requires-python")
        if not isinstance(spec, str) or not spec.strip():
            return None   # absent or malformed (e.g. a list) => no P008 claims
        spec = spec.strip()
        try:
            sset = SpecifierSet(spec)
        except InvalidSpecifier:
            return None
        patches = {0, 10_000}
        for mt in re.finditer(r"3\.\d+\.(\d+)", spec):
            p = int(mt.group(1))
            patches.update({max(0, p - 1), p, p + 1})
        allowed = [(3, minor) for minor in range(0, self._MAX_MINOR + 1)
                   if any(sset.contains(Version(f"3.{minor}.{c}"), prereleases=True)
                          for c in patches)]
        return allowed or None

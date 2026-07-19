from __future__ import annotations

import re
from pathlib import Path

import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException

from auditor.adapters.java.known_artifacts import PACKAGE_TO_ARTIFACT
from auditor.core.interfaces import LanguageAdapter, SyntaxProfile
from auditor.core.models import DeclaredDep, ImportRef, SourceFile

_JDK_PREFIXES = ("java.", "jdk.", "sun.", "com.sun.",
                 "org.w3c.dom", "org.xml.sax", "org.ietf.jgss")
# javax is NOT blanket-JDK (review-refuted: servlet/persistence/mail/validation/
# inject/ws.rs/annotation/xml.bind... are external Maven artifacts). These are
# the javax prefixes actually exported by JDK 21 modules (docs.oracle.com, per
# module). Longest-prefix semantics: javax.annotation.processing is JDK while
# javax.annotation.PostConstruct is external and simply won't match this list.
_JDK_JAVAX = (
    "javax.accessibility", "javax.annotation.processing", "javax.crypto",
    "javax.imageio", "javax.lang.model", "javax.management", "javax.naming",
    "javax.net", "javax.print", "javax.rmi.ssl", "javax.script",
    "javax.security.auth", "javax.security.cert", "javax.security.sasl",
    "javax.smartcardio", "javax.sound", "javax.sql", "javax.swing",
    "javax.tools", "javax.transaction.xa", "javax.xml",
)
# JEP 320 removed these from the JDK even though they sit under javax.xml.*
_EXTERNAL_JAVAX_OVERRIDES = ("javax.xml.bind", "javax.xml.ws", "javax.xml.soap")
_GRADLE_DEP = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
    r"testRuntimeOnly|annotationProcessor|kapt|classpath)\s*[\(\s]\s*"
    r"""["']([\w.\-]+):([\w.\-]+)(?::[^"']+)?["']""")
_IMPORT_QUERY = "(import_declaration) @imp"
_PACKAGE_QUERY = "(package_declaration) @pkg"


def _top_level(package_path: str) -> str:
    parts = package_path.split(".")
    keep = []
    for part in parts:
        if part[:1].isupper():
            break
        keep.append(part)
    return ".".join(keep) if keep else package_path


class JavaAdapter(LanguageAdapter):
    name = "java"
    ecosystem = "maven"
    source_globs = (".java",)
    mapping_precision = "heuristic"   # curated prefix map => H002/H007/H008/H010 are heuristic

    def __init__(self) -> None:
        self._own_packages: tuple[str, ...] = ()

    def detect(self, root: Path) -> bool:
        return any((root / f).is_file() for f in ("pom.xml", "build.gradle", "build.gradle.kts"))

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        self._scan_root = root.resolve()   # central symlink guard for manifests
        deps: list[DeclaredDep] = []
        pom = root / "pom.xml"
        if pom.is_file():
            deps += self._parse_pom(pom)
        for gradle in ("build.gradle", "build.gradle.kts"):
            g = root / gradle
            if g.is_file():
                deps += self._parse_gradle(g)
        seen: set[str] = set()
        out = []
        for d in deps:
            if d.name not in seen:
                seen.add(d.name)
                out.append(d)
        return out

    def _parse_pom(self, path: Path) -> list[DeclaredDep]:
        try:
            root = ET.fromstring(self._read(path))   # defused + 2MB-capped
        except (ET.ParseError, DefusedXmlException) as e:
            self._manifest_error(path, e)
            return []
        out = []
        for dep in root.iter():
            if not dep.tag.endswith("}dependency") and dep.tag != "dependency":
                continue
            group = artifact = None
            for child in dep:
                tag = child.tag.rsplit("}", 1)[-1]
                if tag == "groupId":
                    group = (child.text or "").strip()
                elif tag == "artifactId":
                    artifact = (child.text or "").strip()
            if group and artifact:
                out.append(DeclaredDep(
                    name=f"{group}:{artifact}", ecosystem="maven", source_file=path.name,
                    raw=f"{group}:{artifact}", skip_registry="${" in group or "${" in artifact))
        return out

    def _parse_gradle(self, path: Path) -> list[DeclaredDep]:
        text = self._read(path)
        return [DeclaredDep(name=f"{g}:{a}", ecosystem="maven", source_file=path.name,
                            raw=f"{g}:{a}")
                for g, a in _GRADLE_DEP.findall(text)]

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        from auditor.core.treesitter import captures, node_text, parse_source
        self.ensure_grammars()
        pkgs: set[str] = set()
        for sf in files:
            parse_source(sf)
            for node in captures("java", sf.tree.root_node, _PACKAGE_QUERY).get("pkg", []):
                text = node_text(node).removeprefix("package").strip().rstrip(";").strip()
                if text:
                    pkgs.add(text)
        self._own_packages = tuple(sorted(pkgs))

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, line_of, node_text, parse_source
        self.ensure_grammars()
        out: list[ImportRef] = []
        for sf in files:
            parse_source(sf)
            for node in captures("java", sf.tree.root_node, _IMPORT_QUERY).get("imp", []):
                text = node_text(node).removeprefix("import").strip().rstrip(";").strip()
                text = text.removeprefix("static").strip()
                module = text.removesuffix(".*")
                if not module:
                    continue
                out.append(ImportRef(module=module, file=sf.rel, line=line_of(node),
                                     top_level=_top_level(module)))
        return out

    def is_internal(self, imp: ImportRef) -> bool:
        m = imp.module
        if m.startswith(_JDK_PREFIXES):
            return True
        if m.startswith("javax."):
            if any(m == p or m.startswith(p + ".") for p in _EXTERNAL_JAVAX_OVERRIDES):
                return False
            return any(m == p or m.startswith(p + ".") for p in _JDK_JAVAX)
        return any(m == p or m.startswith(p + ".") for p in self._own_packages)

    def _known_map_hit(self, imp: ImportRef) -> str | None:
        best = None
        for prefix, coords in PACKAGE_TO_ARTIFACT.items():
            if imp.module == prefix or imp.module.startswith(prefix + "."):
                if best is None or len(prefix) > best[0]:
                    best = (len(prefix), coords)
        return best[1] if best else None

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        coords = self._known_map_hit(imp)
        if coords:
            # the curated map knows the EXACT artifact — require the FULL
            # group:artifact. A different artifact under the same group must NOT
            # masquerade as the provider (CP-8.3: no wrong-artifact hiding).
            return next((d for d in declared if d.name == coords), None)
        # no curated mapping: a declared group that owns the import's namespace
        for dep in declared:
            group = dep.name.split(":", 1)[0]
            if group and (imp.module == group or imp.module.startswith(group + ".")):
                return dep
        return None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        coords = self._known_map_hit(imp)
        return [coords] if coords else []

    def language_rules(self):
        from auditor.adapters.java.rules import MissingTryWithResources, StringEqualsCompare
        return [StringEqualsCompare(), MissingTryWithResources()]

    def grammars(self) -> dict[str, object]:
        import tree_sitter_java
        return {"java": tree_sitter_java.language()}

    def syntax(self):
        return SyntaxProfile(
            catch_query="(catch_clause) @c",
            catch_body_types=("block",),
            sql_concat_query="(binary_expression) @n",
            # Java has no string interpolation — concat only (review-verified)
        )

    def private_registry_reason(self, root: Path) -> str | None:
        # repo-level settings.gradle / parent pom above the project also apply
        for d in self._config_search_dirs(root):
            pom = d / "pom.xml"
            if pom.is_file() and "<repositories>" in self._read(pom):
                return f"custom <repositories> configured in {pom.as_posix()}"
            for gradle in ("build.gradle", "build.gradle.kts", "settings.gradle",
                           "settings.gradle.kts"):
                g = d / gradle
                if g.is_file():
                    text = self._read(g)
                    if re.search(r"maven\s*[{(]\s*(url|setUrl)", text):
                        return f"custom maven repository configured in {g.as_posix()}"
        return None


# ── Rule Capability Catalog hook (owner: java rules module) ─────────────────
from auditor.adapters.java import rules as _jrules  # noqa: E402  (deliberate late import: catalog block lives next to its rules)


def _java_rule_descriptors(self):
    return list(_jrules.DESCRIPTORS)


JavaAdapter.rule_descriptors = _java_rule_descriptors  # type: ignore[method-assign]

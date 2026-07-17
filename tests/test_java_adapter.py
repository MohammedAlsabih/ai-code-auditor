from pathlib import Path

from auditor.adapters.java.adapter import JavaAdapter
from auditor.core.models import DeclaredDep, ImportRef
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.22.1</version>
    </dependency>
    <dependency>
      <groupId>com.ai.magic</groupId>
      <artifactId>super-utils</artifactId>
      <version>1.0</version>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>internal-lib</artifactId>
    </dependency>
  </dependencies>
</project>"""


def test_detect_and_pom_parsing(tmp_path):
    a = JavaAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "pom.xml", POM)
    assert a.detect(tmp_path)
    deps = {d.name: d for d in a.parse_dependencies(tmp_path)}
    assert set(deps) == {"com.fasterxml.jackson.core:jackson-databind",
                         "com.ai.magic:super-utils",
                         "${project.groupId}:internal-lib"}
    assert deps["${project.groupId}:internal-lib"].skip_registry is True


def test_gradle_parsing(tmp_path):
    _mk(tmp_path, "build.gradle", "\n".join([
        "dependencies {",
        "    implementation 'com.google.code.gson:gson:2.11.0'",
        '    testImplementation("org.mockito:mockito-core:5.0.0")',
        "    api 'com.squareup.okhttp3:okhttp:4.12.0'",
        "}",
    ]))
    names = {d.name for d in JavaAdapter().parse_dependencies(tmp_path)}
    assert names == {"com.google.code.gson:gson", "org.mockito:mockito-core",
                     "com.squareup.okhttp3:okhttp"}


def test_broken_pom_is_noted_not_silent(tmp_path):
    from auditor.core.models import Diagnostics
    _mk(tmp_path, "pom.xml", "<project><dependencies>")
    diag = Diagnostics()
    assert JavaAdapter().parse_dependencies(tmp_path, diag=diag) == []
    assert any("pom.xml" in e for e in diag.manifest_errors)


def test_imports_top_level_stops_at_class(tmp_path):
    _mk(tmp_path, "pom.xml", POM)
    _mk(tmp_path, "src/main/java/com/example/Main.java", "\n".join([
        "package com.example;",
        "import java.util.List;",
        "import com.fasterxml.jackson.databind.ObjectMapper;",
        "import com.google.gson.Gson;",
        "import com.hallucinated.tools.Helper;",
        "import com.example.util.Other;",
        "import static org.junit.jupiter.api.Assertions.assertTrue;",
        "class Main {}",
    ]))
    a = JavaAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    a.prepare(tmp_path, files)
    imps = {i.top_level: i for i in a.extract_imports(files)}
    assert set(imps) == {"java.util", "com.fasterxml.jackson.databind",
                         "com.google.gson", "com.hallucinated.tools",
                         "com.example.util", "org.junit.jupiter.api"}
    assert a.is_internal(imps["java.util"])
    assert a.is_internal(imps["com.example.util"])       # own package prefix
    assert not a.is_internal(imps["com.google.gson"])


def test_javax_split_jdk_vs_external():
    a = JavaAdapter()
    jdk = ["javax.swing.JFrame", "javax.crypto.Cipher", "javax.annotation.processing",
           "javax.transaction.xa", "javax.xml.parsers"]
    external = ["javax.servlet.http", "javax.persistence", "javax.annotation",
                "javax.xml.bind", "javax.transaction", "javax.inject"]
    for m in jdk:
        assert a.is_internal(ImportRef(m, "F.java", 1, top_level=m)), m
    for m in external:
        assert not a.is_internal(ImportRef(m, "F.java", 1, top_level=m)), m
    # JUnit4 regression: declared junit:junit must match org.junit.* imports
    declared = [DeclaredDep(name="junit:junit", ecosystem="maven", source_file="pom.xml")]
    assert a.match_declared(ImportRef("org.junit.Test", "T.java", 1, top_level="org.junit"),
                            declared) is not None


def test_match_and_candidates():
    a = JavaAdapter()
    declared = [DeclaredDep(name="com.fasterxml.jackson.core:jackson-databind",
                            ecosystem="maven", source_file="pom.xml")]
    hit = a.match_declared(
        ImportRef("com.fasterxml.jackson.databind.ObjectMapper", "M.java", 1,
                  top_level="com.fasterxml.jackson.databind"), declared)
    assert hit is not None  # groupId prefix com.fasterxml.jackson matches via known map
    gson = ImportRef("com.google.gson.Gson", "M.java", 1, top_level="com.google.gson")
    assert a.match_declared(gson, declared) is None
    assert a.registry_candidates(gson) == ["com.google.code.gson:gson"]
    unknown = ImportRef("com.hallucinated.tools.H", "M.java", 1,
                        top_level="com.hallucinated.tools")
    assert a.registry_candidates(unknown) == []


def test_java_repo_e2e(fixtures_dir):
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import PackageInfo
    from tests.conftest import FakeRegistry

    root = fixtures_dir / "java_repo"
    a = JavaAdapter()
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    a.prepare(root, files)
    declared = a.parse_dependencies(root)
    reg = FakeRegistry("maven", {
        "com.fasterxml.jackson.core:jackson-databind": PackageInfo(True, created="2012-01-01T00:00:00+00:00"),
        "com.google.code.gson:gson": PackageInfo(True, created="2008-09-01T00:00:00+00:00"),
    })
    findings = audit_hallucinations(a, root, files, declared, reg)
    ids = sorted(f.rule_id for f in findings)
    assert ids == ["H001", "H002", "H007"]  # super-utils / gson / hallucinated.tools
    # workflow-caught regression: mapping-based findings must carry heuristic
    assert all(f.precision == "heuristic" for f in findings
               if f.rule_id in ("H002", "H007", "H008", "H010"))
    assert next(f for f in findings if f.rule_id == "H001").precision == "exact"

from pathlib import Path

from auditor.adapters.dotnet.rules import (AsyncVoidMethod, BlockingTaskWait,
                                           RawSqlInterpolation)
from auditor.adapters.java.rules import MissingTryWithResources, StringEqualsCompare
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(code: str, language: str) -> SourceFile:
    ext = {"java": ".java", "csharp": ".cs"}[language]
    sf = SourceFile(path=Path("f" + ext), rel="f" + ext, language=language,
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def test_j001_string_eq():
    sf = _sf('class A { boolean f(String s) { return s == "admin"; } }', "java")
    assert [f.rule_id for f in StringEqualsCompare().check(sf)] == ["J001"]
    clean = _sf('class A { boolean f(String s) { return "admin".equals(s); } }', "java")
    assert StringEqualsCompare().check(clean) == []


def test_j002_resource_without_twr():
    sf = _sf('class A { void f() throws Exception { '
             'java.io.FileInputStream in = new java.io.FileInputStream("x"); } }', "java")
    assert [f.rule_id for f in MissingTryWithResources().check(sf)] == ["J002"]
    clean = _sf('class A { void f() throws Exception { '
                'try (java.io.FileInputStream in = new java.io.FileInputStream("x")) {} } }',
                "java")
    assert MissingTryWithResources().check(clean) == []


def test_d001_async_void():
    sf = _sf("class A { static async void Fire() { await Task.Delay(1); } }", "csharp")
    assert [f.rule_id for f in AsyncVoidMethod().check(sf)] == ["D001"]
    handler = _sf("class A { async void OnClick(object sender, EventArgs e) "
                  "{ await Task.Delay(1); } }", "csharp")
    assert AsyncVoidMethod().check(handler) == []


def test_d002_blocking_wait():
    sf = _sf("class A { void F() { var x = FetchAsync().Result; GetAsync().Wait(); "
             "var y = RunAsync().GetAwaiter().GetResult(); } }", "csharp")
    ids = [f.rule_id for f in BlockingTaskWait().check(sf)]
    assert ids == ["D002", "D002", "D002"]
    clean = _sf("class A { void F(SomeStruct s) { var r = s.Result; } }", "csharp")
    assert BlockingTaskWait().check(clean) == []


def test_precision_reaches_findings_not_just_rules():
    # regression: heuristic must arrive ON THE FINDING, never silently
    # defaulting back to "exact"
    j = _sf('class A { void f() throws Exception { '
            'java.io.FileInputStream in = new java.io.FileInputStream("x"); } }', "java")
    assert [f.precision for f in MissingTryWithResources().check(j)] == ["heuristic"]
    cs = _sf("class A { void F() { var x = FetchAsync().Result; } }", "csharp")
    assert [f.precision for f in BlockingTaskWait().check(cs)] == ["heuristic"]
    raw = _sf('class A { void F(Db db, string id) { '
              'db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}"); } }', "csharp")
    assert [f.precision for f in RawSqlInterpolation().check(raw)] == ["heuristic"]
    eq = _sf('class A { boolean f(String s) { return s == "admin"; } }', "java")
    assert [f.precision for f in StringEqualsCompare().check(eq)] == ["exact"]


def test_d003_raw_sql():
    sf = _sf('class A { void F(Db db, string id) { '
             'db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}"); } }', "csharp")
    assert [f.rule_id for f in RawSqlInterpolation().check(sf)] == ["D003"]
    clean = _sf('class A { void F(Db db) { db.Users.FromSqlRaw("SELECT * FROM Users"); } }',
                "csharp")
    assert RawSqlInterpolation().check(clean) == []

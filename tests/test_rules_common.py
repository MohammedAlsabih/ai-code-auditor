from pathlib import Path

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.adapters.java.adapter import JavaAdapter
from auditor.adapters.python.adapter import PythonAdapter
from auditor.adapters.typescript.adapter import TypeScriptAdapter
from auditor.core.models import SourceFile
from auditor.core.rules_common import (EmptyCatch, SecretsRule, SmellComments,
                                       SqlStringBuild, common_rules)
from auditor.core.treesitter import parse_source

PROFILES = {
    "python": PythonAdapter().syntax(),
    "java": JavaAdapter().syntax(),
    "csharp": DotnetAdapter().syntax(),
    "typescript": TypeScriptAdapter().syntax(),
    "tsx": TypeScriptAdapter().syntax(),
}


def _sf(code: str, language: str, name: str = "f") -> SourceFile:
    ext = {"python": ".py", "java": ".java", "csharp": ".cs",
           "typescript": ".ts", "tsx": ".tsx"}[language]
    sf = SourceFile(path=Path(name + ext), rel=name + ext, language=language,
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def _catch(lang):
    return EmptyCatch(PROFILES[lang])


def _sql(lang):
    return SqlStringBuild(PROFILES[lang])


def test_p001_empty_except_python():
    sf = _sf("try:\n    x = 1\nexcept Exception:\n    pass\n", "python")
    assert [f.rule_id for f in _catch("python").check(sf)] == ["P001"]


def test_p001_handled_except_is_clean():
    sf = _sf("try:\n    x = 1\nexcept Exception as e:\n    print(e)\n", "python")
    assert _catch("python").check(sf) == []


def test_p001_empty_catch_all_curly_languages():
    cases = [
        ("class A { void f() { try { g(); } catch (Exception e) { } } }", "java"),
        ("class A { void F() { try { G(); } catch (System.Exception) { } } }", "csharp"),
        ("try { f(); } catch (e) { }", "typescript"),
    ]
    for code, lang in cases:
        sf = _sf(code, lang)
        assert [f.rule_id for f in _catch(lang).check(sf)] == ["P001"], lang


def test_p002_known_secret_tokens_masked():
    sf = _sf('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', "python")
    fs = SecretsRule().check(sf)
    assert [f.rule_id for f in fs] == ["P002"]
    assert "AKIAIOSFODNN7EXAMPLE" not in fs[0].snippet  # masked


def test_p003_generic_credential_and_placeholder_filter():
    hot = _sf('password = "hunter2secret99"\n', "python")
    assert [f.rule_id for f in SecretsRule().check(hot)] == ["P003"]
    for benign in ('password = "changeme"\n', 'password = os.environ["PW"]\n',
                   'password = "<YOUR-PASSWORD>"\n'):
        assert SecretsRule().check(_sf(benign, "python")) == [], benign


def test_p004_sql_composition_python_fstring():
    sf = _sf('q = f"SELECT * FROM users WHERE id = {uid}"\n', "python")
    assert [f.rule_id for f in _sql("python").check(sf)] == ["P004"]


def test_p005_sql_reaching_execute_sink():
    sf = _sf('cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n', "python")
    assert [f.rule_id for f in _sql("python").check(sf)] == ["P005"]


def test_p004_ts_template_and_csharp_interpolation():
    ts = _sf("const q = `SELECT * FROM t WHERE id = ${id}`;", "typescript")
    assert [f.rule_id for f in _sql("typescript").check(ts)] == ["P004"]
    cs = _sf('class A { string Q(string i) { return $"SELECT * FROM T WHERE Id = {i}"; } }',
             "csharp")
    assert [f.rule_id for f in _sql("csharp").check(cs)] == ["P004"]


def test_p004_literal_sql_is_clean():
    sf = _sf('q = "SELECT * FROM users WHERE id = 1"\n', "python")
    assert _sql("python").check(sf) == []


def test_p007_smell_comments():
    sf = _sf("# TODO: implement error handling\n"
             "# In a real application, validate input\n"
             "x = 1\n", "python")
    assert [f.rule_id for f in SmellComments().check(sf)] == ["P007", "P007"]


def test_factory_and_precision():
    rules = common_rules(PROFILES["python"])
    assert [r.__class__.__name__ for r in rules] == \
        ["EmptyCatch", "SecretsRule", "SqlStringBuild", "SmellComments"]
    assert next(r for r in rules if r.id == "P004").precision == "heuristic"


def test_no_language_names_in_core_rules_module():
    import inspect

    import auditor.core.rules_common as mod
    src = inspect.getsource(mod)
    for token in ('"python"', '"java"', '"csharp"', '"typescript"', '"tsx"'):
        assert token not in src, f"core neutrality violated: {token} in rules_common"

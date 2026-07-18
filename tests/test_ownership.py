from auditor.core.models import Finding, Severity
from auditor.core.ownership import assign_findings, fs_case_insensitive, norm


def _f(path):
    return Finding("S:x", Severity.YELLOW, "t", path, 1, engine="semgrep")


def test_case_sensitivity_respects_filesystem_mode():
    owner = {norm("web/Foo.ts", False): 0}
    got, bucket, _ = assign_findings([_f("web/foo.ts")], owner,
                                     [(("web",), 0)], {0: "web/"},
                                     {0: (".ts",)}, insensitive=False)
    # sensitive fs: foo.ts is NOT Foo.ts — exact map misses, fallback still owns
    # it by suffix+root, but the two names never collapse into one key
    assert norm("web/Foo.ts", False) != norm("web/foo.ts", False)
    assert 0 in got
    got_i, _, _ = assign_findings([_f("web/FOO.ts")],
                                  {norm("web/Foo.ts", True): 0},
                                  [(("web",), 0)], {0: "web/"},
                                  {0: (".ts",)}, insensitive=True)
    assert 0 in got_i  # insensitive fs: exact map hits across case


def test_prefix_collision_api_vs_api_old():
    got, bucket, _ = assign_findings([_f("api-old/src/index.ts")], {},
                                     [(("api",), 0)], {0: "api/"},
                                     {0: (".ts",)}, insensitive=True)
    assert got == {} and len(bucket) == 1  # 'api' must NOT swallow 'api-old'


def test_unowned_non_source_goes_to_repo_bucket_even_with_root_project():
    got, bucket, _ = assign_findings([_f("Dockerfile")], {},
                                     [((), 0)], {0: ""},
                                     {0: (".py",)}, insensitive=True)
    assert got == {} and [b.file for b in bucket] == ["Dockerfile"]


def test_two_projects_same_root_disambiguated_by_globs_and_owner_map():
    owner = {norm("a.py", True): 0, norm("b.ts", True): 1}
    got, bucket, _ = assign_findings([_f("a.py"), _f("b.ts"), _f("c.ts")], owner,
                                     [((), 0), ((), 1)], {0: "", 1: ""},
                                     {0: (".py",), 1: (".ts",)}, insensitive=True)
    assert set(got) == {0, 1} and [x.file for x in got[1]] == ["b.ts", "c.ts"]


def test_path_escape_dropped():
    got, bucket, dropped = assign_findings([_f("../outside.py")], {},
                                           [((), 0)], {0: ""},
                                           {0: (".py",)}, insensitive=True)
    assert got == {} and bucket == [] and dropped == ["../outside.py"]


def test_fs_probe_runs(tmp_path):
    p = tmp_path / "Sample.txt"
    p.write_text("x", encoding="utf-8")
    assert isinstance(fs_case_insensitive(p), bool)  # True on Windows/mac default

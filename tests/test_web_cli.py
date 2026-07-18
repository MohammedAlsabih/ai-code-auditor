import uvicorn

from auditor import cli


def _valid_report(tmp_path):
    p = tmp_path / "report.json"
    p.write_text('{"summary": {"counts": {}}, "projects": []}', encoding="utf-8")
    return p


def test_serve_binds_loopback_only(tmp_path, monkeypatch):
    """serve must hand uvicorn host=127.0.0.1 and the requested port."""
    captured = {}
    monkeypatch.setattr(uvicorn, "run",
                        lambda app, host, port, **kw: captured.update(host=host, port=port))
    rc = cli.main(["serve", str(_valid_report(tmp_path)), "--port", "9999"])
    assert rc == 0
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9999


def test_serve_host_constant_is_loopback():
    assert cli.SERVE_HOST == "127.0.0.1"


def test_serve_rejects_public_host_flag():
    """W1 exposes no --host flag, so a public bind can't even be requested."""
    import pytest
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["serve", "r.json", "--host", "0.0.0.0"])


def test_serve_bad_report_exits_2_without_starting_server(tmp_path, monkeypatch):
    """A corrupt report exits 2 with a clear message and never starts uvicorn —
    the browser never sees an internal traceback."""
    started = {"v": False}
    monkeypatch.setattr(uvicorn, "run",
                        lambda *a, **k: started.__setitem__("v", True))
    bad = tmp_path / "bad.json"
    bad.write_text("{ oops not json", encoding="utf-8")
    rc = cli.main(["serve", str(bad)])
    assert rc == 2
    assert started["v"] is False


def test_serve_repo_flag_is_optional(tmp_path, monkeypatch):
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    rc = cli.main(["serve", str(_valid_report(tmp_path))])   # no --repo
    assert rc == 0


def test_core_nuget_race_fix_is_present_in_worktree():
    """This web worktree must include Core fix 3aed542: the NuGet client resolves
    its service index under a lock via a local-then-publish build (no partial map)."""
    from auditor.registries.nuget import NuGetClient
    client = NuGetClient()
    assert hasattr(client, "_resources_lock")
    assert hasattr(client, "_build_resources")


def test_serve_missing_web_deps_prints_clear_message(tmp_path, monkeypatch, capsys):
    """If the [web] extra isn't installed, serve must exit 2 with an install hint,
    not a raw ModuleNotFoundError traceback."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "uvicorn" or name.startswith("auditor.web"):
            raise ModuleNotFoundError(f"No module named '{name}'", name=name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = cli.main(["serve", str(_valid_report(tmp_path))])
    assert rc == 2
    err = capsys.readouterr().err
    assert "Web explorer dependencies are not installed" in err
    assert 'pip install "ai-code-auditor[web]"' in err


def test_serve_unrelated_import_error_is_not_swallowed(tmp_path, monkeypatch):
    """A ModuleNotFoundError that is NOT a web dependency (i.e. a real bug) must
    propagate, not be masked as a missing-extra message."""
    import builtins

    import pytest
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "uvicorn":
            raise ModuleNotFoundError("No module named 'totally_unrelated'",
                                      name="totally_unrelated")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ModuleNotFoundError):
        cli.main(["serve", str(_valid_report(tmp_path))])


def test_built_spa_is_committed_in_package():
    """The wheel/checkout must carry the built SPA so it runs with no Node. Guards
    against the static bundle being re-ignored or dropped from packaging."""
    from auditor.web import app as webapp
    static = webapp._STATIC_DIR
    assert (static / "index.html").is_file()
    assets = static / "assets"
    assert any(p.suffix == ".js" for p in assets.iterdir())
    assert any(p.suffix == ".css" for p in assets.iterdir())

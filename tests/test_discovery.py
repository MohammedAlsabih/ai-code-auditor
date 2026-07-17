from pathlib import Path

from auditor.discovery import discover_projects, project_files


class FakeAdapter:
    def __init__(self, name, marker, globs):
        self.name = name
        self.ecosystem = name
        self.source_globs = globs
        self._marker = marker

    def detect(self, root: Path) -> bool:
        return (root / self._marker).is_file()

    def file_language(self, path: Path) -> str:
        return self.name


def _mk(tmp_path, rel, content=""):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_discovers_multiple_languages_in_monorepo(tmp_path):
    py = FakeAdapter("python", "requirements.txt", (".py",))
    ts = FakeAdapter("typescript", "package.json", (".ts",))
    _mk(tmp_path, "requirements.txt")
    _mk(tmp_path, "web/package.json", "{}")
    _mk(tmp_path, "node_modules/pkg/package.json", "{}")  # ignored dir
    found = discover_projects(tmp_path, [py, ts])
    names = [(a.name, p.relative_to(tmp_path).as_posix() or ".") for a, p in found]
    assert ("python", ".") in names and ("typescript", "web") in names
    assert len(found) == 2


def test_project_files_excludes_nested_same_language_projects(tmp_path):
    py = FakeAdapter("python", "requirements.txt", (".py",))
    _mk(tmp_path, "requirements.txt")
    _mk(tmp_path, "app.py", "x=1")
    _mk(tmp_path, "libs/sub/requirements.txt")
    _mk(tmp_path, "libs/sub/inner.py", "y=2")
    projects = discover_projects(tmp_path, [py])
    roots = {p for _, p in projects}
    assert roots == {tmp_path, tmp_path / "libs" / "sub"}
    top_files = project_files(tmp_path, py, projects)
    assert [f.rel for f in top_files] == ["app.py"]
    sub_files = project_files(tmp_path / "libs" / "sub", py, projects)
    assert [f.rel for f in sub_files] == ["inner.py"]


def test_manifestless_language_falls_back_to_root_project(tmp_path):
    py = FakeAdapter("python", "requirements.txt", (".py",))
    _mk(tmp_path, "scripts/tool.py", "x=1")
    found = discover_projects(tmp_path, [py])
    assert [(a.name, p) for a, p in found] == [("python", tmp_path)]


def test_manifestless_tail_gets_fallback_even_when_language_detected_elsewhere(tmp_path):
    # regression: detecting python in services/api must NOT suppress the root
    # fallback that covers the manifestless tools/audit.py
    py = FakeAdapter("python", "requirements.txt", (".py",))
    _mk(tmp_path, "services/api/requirements.txt")
    _mk(tmp_path, "services/api/app.py", "x=1")
    _mk(tmp_path, "tools/audit.py", "y=2")
    projects = discover_projects(tmp_path, [py])
    roots = {p for _, p in projects}
    assert tmp_path / "services" / "api" in roots   # standalone project
    assert tmp_path in roots                          # root fallback present

    api_files = project_files(tmp_path / "services" / "api", py, projects)
    assert [f.rel for f in api_files] == ["app.py"]

    root_files = project_files(tmp_path, py, projects)
    assert [f.rel for f in root_files] == ["tools/audit.py"]  # app.py NOT double-covered

"""REAL-CORPUS-1A acquisition: deterministic, no network.

Every test here drives the acquisition tool against LOCAL fixture
repositories created with real `git` on a temp path. Nothing reaches the
internet, and the one test that would needs an explicit opt-in that is not
set in CI.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools.real_corpus import (
    ALLOWED_HOSTS,
    MAX_SOURCE_FILES,
    MIN_SOURCE_FILES,
    SUPPORTED_LANGUAGES,
    VENDOR_DIRS,
    AcquisitionError,
    RepoSpec,
    acquire,
    acquire_one,
    git_env,
    inspect_tree,
    load_manifest,
    sample_id,
    url_problem,
)

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git is not installed")


# ---- local fixture repositories ------------------------------------------------------

def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run([GIT, *args], cwd=str(cwd), capture_output=True,
                          text=True, check=True)
    return proc.stdout.strip()


def make_repo(root: Path, name: str, *, files: dict[str, str],
              submodule: bool = False) -> tuple[Path, str]:
    """A real git repository on disk, so acquisition is exercised against
    git's actual behaviour rather than a mock of it."""
    path = root / name
    path.mkdir(parents=True)
    _git(path, "init", "--quiet", "-b", "main")
    _git(path, "config", "user.email", "t@example.invalid")
    _git(path, "config", "user.name", "T")
    for rel, text in files.items():
        f = path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    if submodule:
        (path / ".gitmodules").write_text(
            '[submodule "x"]\n\tpath = x\n\turl = https://example.invalid/x\n',
            encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "--quiet", "-m", "fixture")
    return path, _git(path, "rev-parse", "HEAD")


MIT_TEXT = ("MIT License\n\nPermission is hereby granted, free of charge, to "
            "any person obtaining a copy of this software.\n")


def python_files(n: int, *, license_text: str | None = MIT_TEXT) -> dict[str, str]:
    out = {"pyproject.toml": '[project]\nname = "x"\nversion = "1"\n'}
    if license_text is not None:
        out["LICENSE"] = license_text
    for i in range(n):
        out[f"pkg/mod_{i}.py"] = f"def f_{i}():\n    return {i}\n"
    return out


@pytest.fixture
def local_runner():
    """Runs the tool's own argv, but rewrites the remote URL to a local path
    so `git fetch` never leaves the machine. Everything else — the flags, the
    hooks path, the pinned-SHA fetch, the detached checkout — is the real
    code path."""
    mapping: dict[str, str] = {}

    def run(argv, **kw):
        argv = [str(a) for a in argv]
        argv = [mapping.get(a, a) for a in argv]
        kw.pop("env", None)          # a local path needs the real environment
        return subprocess.run(argv, **kw)

    run.mapping = mapping            # type: ignore[attr-defined]
    return run


# ---- url policy ----------------------------------------------------------------------

@pytest.mark.parametrize("url, why", [
    ("http://github.com/a/b", "plain http"),
    ("git://github.com/a/b", "git protocol"),
    ("ssh://git@github.com/a/b", "ssh"),
    ("https://user:pw@github.com/a/b", "credentials"),
    ("https://github.com/a/b?token=1", "query string"),
    ("https://github.com/a/b#frag", "fragment"),
    ("https://github.com:8443/a/b", "custom port"),
    ("https://evil.example/a/b", "host not allowed"),
    ("https://github.com/a/../../b", "traversal"),
    ("https://github.com", "no repository path"),
    ("https://github.com/a b", "whitespace"),
])
def test_only_plain_public_https_urls_are_accepted(url, why):
    assert url_problem(url) is not None, why


def test_the_allowed_hosts_are_accepted():
    for host in ALLOWED_HOSTS:
        assert url_problem(f"https://{host}/owner/repo") is None


# ---- manifest contract ---------------------------------------------------------------

def _entry(**over):
    base = {"repo_id": "sample-one", "url": "https://github.com/o/r",
            "commit": "a" * 40, "license_spdx": "MIT", "language": "python"}
    base.update(over)
    return base


def _write_manifest(tmp_path: Path, entries: list[dict]) -> Path:
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps({"repositories": entries}), encoding="utf-8")
    return p


def test_a_well_formed_manifest_loads(tmp_path):
    specs = load_manifest(_write_manifest(tmp_path, [
        _entry(), _entry(repo_id="sample-two", url="https://gitlab.com/o/r2",
                         commit="b" * 40, language="typescript")]))
    assert [s.repo_id for s in specs] == ["sample-one", "sample-two"]


@pytest.mark.parametrize("entry, why", [
    (_entry(commit="main"), "a branch name is not a pin"),
    (_entry(commit="a" * 7), "a short sha is not a pin"),
    (_entry(commit="A" * 40), "uppercase is not the canonical form"),
    (_entry(language="ruby"), "a language the catalog cannot scan"),
    (_entry(repo_id="Has Spaces"), "unusable repo id"),
    (_entry(license_spdx=""), "no licence recorded"),
    (_entry(url="https://evil.example/o/r"), "host not allowed"),
])
def test_a_malformed_entry_is_refused(tmp_path, entry, why):
    with pytest.raises(AcquisitionError):
        load_manifest(_write_manifest(tmp_path, [entry]))


def test_extra_or_missing_fields_are_refused(tmp_path):
    with pytest.raises(AcquisitionError, match="exactly"):
        load_manifest(_write_manifest(
            tmp_path, [{**_entry(), "notes": "a path C:/x"}]))
    missing = _entry()
    del missing["license_spdx"]
    with pytest.raises(AcquisitionError, match="exactly"):
        load_manifest(_write_manifest(tmp_path, [missing]))


@pytest.mark.parametrize("field", ["repo_id", "url", "commit"])
def test_duplicates_are_refused(tmp_path, field):
    a, b = _entry(), _entry(repo_id="sample-two", url="https://github.com/o/s",
                            commit="b" * 40)
    b[field] = a[field]
    with pytest.raises(AcquisitionError, match="duplicate"):
        load_manifest(_write_manifest(tmp_path, [a, b]))


# ---- the git invocation itself -------------------------------------------------------

def test_the_git_environment_cannot_prompt_or_read_user_config():
    env = git_env({"PATH": "/usr/bin", "SystemRoot": "C:\\Windows",
                   "HOME": "/home/someone", "USERPROFILE": "C:\\Users\\someone",
                   "GITHUB_TOKEN": "ghp_secret", "SSH_AUTH_SOCK": "/tmp/s",
                   "GIT_ASKPASS": "/usr/bin/leak"})
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ASKPASS"] == "" and env["SSH_ASKPASS"] == ""
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_ALLOW_PROTOCOL"] == "https"
    # no user identity reaches git: no dotfiles, no netrc, no keychain
    assert "HOME" not in env and "USERPROFILE" not in env
    # and nothing that could authenticate is carried through
    assert "GITHUB_TOKEN" not in env and "SSH_AUTH_SOCK" not in env
    assert not any("TOKEN" in k or "SECRET" in k or "KEY" in k for k in env)


def test_the_git_environment_keeps_what_the_OS_needs_to_resolve_a_name():
    """Found by running it: stripping the environment to PATH alone makes git
    on Windows fail with "getaddrinfo() thread failed to start". Safer-looking
    is not safer if it cannot work."""
    env = git_env({"PATH": "/usr/bin", "SystemRoot": "C:\\Windows",
                   "COMSPEC": "C:\\Windows\\system32\\cmd.exe",
                   "TEMP": "C:\\Temp"})
    assert env["PATH"] == "/usr/bin"
    assert env["SystemRoot"] == "C:\\Windows"
    assert env["COMSPEC"].endswith("cmd.exe")
    assert env["TEMP"] == "C:\\Temp"


def test_acquisition_pins_the_commit_and_never_uses_a_shell(tmp_path,
                                                            local_runner):
    origin, sha = make_repo(tmp_path / "origins", "src", files=python_files(40))
    url = "https://github.com/o/pinned"
    local_runner.mapping[url] = str(origin)
    calls: list[list[str]] = []

    def recording(argv, **kw):
        calls.append([str(a) for a in argv])
        assert kw.get("shell") is False, "a shell must never be used"
        return local_runner(argv, **kw)

    spec = RepoSpec("pinned", url, sha, "MIT", "python")
    result = acquire_one(spec, tmp_path / "repos", run=recording)

    assert result.accepted, result.reason
    assert result.head == sha
    assert result.source_files == 40
    assert result.has_manifest is True
    fetch = next(c for c in calls if "fetch" in c)
    assert sha in fetch                      # the SHA itself, not a branch
    assert "--depth" in fetch and "--no-tags" in fetch
    assert "--recurse-submodules=no" in fetch
    assert all("core.hooksPath=" in "".join(c) for c in calls)
    checkout = next(c for c in calls if "checkout" in c)
    assert "--detach" in checkout


def test_a_tree_whose_head_is_not_the_pin_is_rejected(tmp_path, local_runner):
    origin, sha = make_repo(tmp_path / "origins", "src", files=python_files(40))
    url = "https://github.com/o/moved"
    local_runner.mapping[url] = str(origin)
    # a manifest that pins a commit this origin does not have
    spec = RepoSpec("moved", url, "c" * 40, "MIT", "python")
    result = acquire_one(spec, tmp_path / "repos", run=local_runner)
    assert result.accepted is False
    assert "fetch failed" in result.reason
    assert not (tmp_path / "repos" / "moved").exists()   # no partial tree


def test_a_failed_acquisition_leaves_nothing_behind(tmp_path):
    def always_fails(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "boom")
    spec = RepoSpec("nope", "https://github.com/o/r", "a" * 40, "MIT",
                    "python")
    result = acquire_one(spec, tmp_path / "repos", run=always_fails)
    assert result.accepted is False
    assert not (tmp_path / "repos" / "nope").exists()


# ---- the plan's inclusion / exclusion rules ------------------------------------------

def test_a_repository_that_vendors_foreign_source_is_excluded(tmp_path):
    for vendor in VENDOR_DIRS[:3]:
        files = python_files(40)
        files[f"{vendor}/dep/thing.py"] = "x = 1\n"
        tree, sha = make_repo(tmp_path / vendor, "src", files=files)
        spec = RepoSpec("vendored", "https://github.com/o/r", sha, "MIT",
                        "python")
        result = inspect_tree(spec, tree)
        assert result.accepted is False
        assert "vendors" in result.reason


def test_a_repository_needing_submodules_is_excluded(tmp_path):
    tree, sha = make_repo(tmp_path, "src", files=python_files(40),
                          submodule=True)
    spec = RepoSpec("subs", "https://github.com/o/r", sha, "MIT", "python")
    result = inspect_tree(spec, tree)
    assert result.accepted is False and "submodules" in result.reason


def test_a_repository_with_no_dependency_manifest_is_excluded(tmp_path):
    files = {f"pkg/m{i}.py": "x = 1\n" for i in range(40)}
    files["LICENSE"] = MIT_TEXT
    tree, sha = make_repo(tmp_path, "src", files=files)
    spec = RepoSpec("nomani", "https://github.com/o/r", sha, "MIT", "python")
    result = inspect_tree(spec, tree)
    assert result.accepted is False
    assert "H family cannot fire" in result.reason


def test_a_repository_with_no_licence_is_excluded(tmp_path):
    tree, sha = make_repo(tmp_path, "src",
                          files=python_files(40, license_text=None))
    spec = RepoSpec("nolic", "https://github.com/o/r", sha, "MIT", "python")
    result = inspect_tree(spec, tree)
    assert result.accepted is False
    assert "no licence file" in result.reason


def test_a_declared_licence_the_tree_does_not_corroborate_is_refused(tmp_path):
    """The manifest's SPDX id is a claim about the world; it is checked
    against the file that is actually there, not taken on trust."""
    tree, sha = make_repo(tmp_path, "src", files=python_files(40))  # MIT text
    wrong = RepoSpec("wrong", "https://github.com/o/r", sha, "Apache-2.0",
                     "python")
    result = inspect_tree(spec=wrong, tree=tree)
    assert result.accepted is False
    assert "does not read like Apache-2.0" in result.reason
    right = RepoSpec("right", "https://github.com/o/r", sha, "MIT", "python")
    assert inspect_tree(spec=right, tree=tree).accepted is True


def test_an_unrecognised_licence_id_is_refused(tmp_path):
    tree, sha = make_repo(tmp_path, "src", files=python_files(40))
    spec = RepoSpec("odd", "https://github.com/o/r", sha, "WTFPL", "python")
    result = inspect_tree(spec, tree)
    assert result.accepted is False
    assert "not one this round recognises" in result.reason


@pytest.mark.parametrize("count, why", [
    (MIN_SOURCE_FILES - 1, "too small to be a codebase"),
    (MIN_SOURCE_FILES, "at the floor, accepted"),
])
def test_the_size_floor_is_applied(tmp_path, count, why):
    tree, sha = make_repo(tmp_path / str(count), "src",
                          files=python_files(count))
    spec = RepoSpec("sized", "https://github.com/o/r", sha, "MIT", "python")
    result = inspect_tree(spec, tree)
    assert result.accepted is (count >= MIN_SOURCE_FILES), why


def test_the_size_ceiling_is_applied(tmp_path, monkeypatch):
    """The ceiling exists so one repository cannot dominate the corpus. It is
    driven here rather than by writing 5001 files."""
    monkeypatch.setattr("tools.real_corpus.MAX_SOURCE_FILES", 40)
    tree, sha = make_repo(tmp_path, "src", files=python_files(45))
    spec = RepoSpec("huge", "https://github.com/o/r", sha, "MIT", "python")
    result = inspect_tree(spec, tree)
    assert result.accepted is False
    assert f"(maximum {MAX_SOURCE_FILES}" not in result.reason  # patched value
    assert "maximum 40" in result.reason


def test_vendored_files_are_not_counted_towards_size(tmp_path):
    files = python_files(40)
    for i in range(50):
        files[f"node_modules/pkg/v{i}.py"] = "x = 1\n"
    tree, _sha = make_repo(tmp_path, "src", files=files)
    spec = RepoSpec("counted", "https://github.com/o/r", "a" * 40, "MIT",
                    "python")
    result = inspect_tree(spec, tree)
    # excluded outright for vendoring — and the count never included them
    assert result.accepted is False
    assert result.source_files in (0, 40)


def test_the_supported_languages_match_the_real_catalog():
    """If the catalog gains or loses a language, this list must move with it
    — otherwise the corpus would silently under- or over-represent the tool."""
    from auditor.adapters import default_adapters
    from auditor.core.catalog import collect_catalog

    adapters = default_adapters()
    catalog = collect_catalog(adapters.values()
                              if isinstance(adapters, dict) else adapters)
    catalog_languages = {lang for rule in catalog
                         for lang in (rule.get("languages") or [])}
    assert catalog_languages <= set(SUPPORTED_LANGUAGES), (
        f"catalog has languages the corpus plan does not cover: "
        f"{sorted(catalog_languages - set(SUPPORTED_LANGUAGES))}")


# ---- identity ------------------------------------------------------------------------

def test_sample_ids_are_stable_and_repository_scoped():
    a = sample_id("repo-one", "fingerprint-x")
    assert a == sample_id("repo-one", "fingerprint-x")     # stable
    assert len(a) == 16 and all(c in "0123456789abcdef" for c in a)
    # the same identity in a different repository is a DIFFERENT unit
    assert a != sample_id("repo-two", "fingerprint-x")
    assert a != sample_id("repo-one", "fingerprint-y")


def test_ids_do_not_collide_across_a_large_population():
    ids = {sample_id(f"repo-{i % 7}", f"unit-{i}") for i in range(20000)}
    assert len(ids) == 20000


# ---- end to end, still offline -------------------------------------------------------

def test_acquire_reports_accepted_and_rejected_without_leaking_paths(
        tmp_path, local_runner):
    good, good_sha = make_repo(tmp_path / "o1", "good", files=python_files(40))
    small, small_sha = make_repo(tmp_path / "o2", "small",
                                 files=python_files(5))
    local_runner.mapping["https://github.com/o/good"] = str(good)
    local_runner.mapping["https://github.com/o/small"] = str(small)
    manifest = _write_manifest(tmp_path, [
        _entry(repo_id="good", url="https://github.com/o/good",
               commit=good_sha),
        _entry(repo_id="small", url="https://github.com/o/small",
               commit=small_sha),
    ])
    summary = acquire(manifest, tmp_path / "root", run=local_runner)

    assert summary["requested"] == 2
    assert summary["accepted"] == 1 and summary["rejected"] == 1
    rows = {r["repo_id"]: r for r in summary["repositories"]}
    assert rows["good"]["accepted"] is True
    assert rows["small"]["accepted"] is False
    assert "source files" in rows["small"]["reason"]
    # the summary is safe to commit: no path of any kind
    blob = json.dumps(summary)
    assert str(tmp_path) not in blob
    assert "\\\\" not in blob and "/o1/" not in blob


def test_everything_is_written_under_the_confined_root(tmp_path, local_runner):
    good, sha = make_repo(tmp_path / "o", "good", files=python_files(40))
    local_runner.mapping["https://github.com/o/good"] = str(good)
    manifest = _write_manifest(tmp_path, [
        _entry(repo_id="good", url="https://github.com/o/good", commit=sha)])
    root = tmp_path / "root"
    acquire(manifest, root, run=local_runner)
    assert (root / "repos" / "good").is_dir()
    assert sorted(p.name for p in root.iterdir()) == ["repos"]

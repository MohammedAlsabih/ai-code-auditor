"""REAL-CORPUS-1A: acquire real public repositories, pinned to a commit.

Implements the acquisition half of the plan frozen in
`docs/quality/REAL-CORPUS-1A-plan.md`. It downloads nothing that is not named
in a manifest, checks out nothing but the pinned SHA, and writes only inside
`.quality-local/real-corpus/`, which is gitignored.

Nothing here measures anything. It fetches code and records what it fetched.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# ---- the confined workspace ---------------------------------------------------------

LOCAL_ROOT = Path(".quality-local") / "real-corpus"
REPOS_DIRNAME = "repos"

# The plan's host allowlist. Mirrors the product's own Alpha policy rather
# than inventing a second one.
ALLOWED_HOSTS = ("github.com", "gitlab.com")

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,38}[a-z0-9]$")
_SPDX_RE = re.compile(r"^[A-Za-z0-9.+-]{2,40}$")

# Languages the catalog actually has rules for (checked against the live
# catalog by a test, so this cannot drift silently).
SUPPORTED_LANGUAGES = ("typescript", "tsx", "csharp", "python", "java")

# Source extensions per language, used only to count a repository's size.
_LANG_SUFFIXES: dict[str, tuple[str, ...]] = {
    "typescript": (".ts", ".mts", ".cts"),
    "tsx": (".tsx",),
    "csharp": (".cs",),
    "python": (".py",),
    "java": (".java",),
}

# Directories whose presence means the repository vendors foreign source.
# Plan exclusion: a finding in vendored code is not a finding about the repo.
VENDOR_DIRS = ("node_modules", "vendor", "third_party", "thirdparty",
               "external", "externals", "bundled")

MANIFEST_GLOBS = {
    "typescript": ("package.json",),
    "tsx": ("package.json",),
    "csharp": ("*.csproj", "Directory.Build.props"),
    "python": ("requirements.txt", "pyproject.toml", "setup.py"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
}

MIN_SOURCE_FILES = 30
MAX_SOURCE_FILES = 5000

# Where a licence is conventionally kept, and the phrase that has to appear in
# it for a declared SPDX id to be believed. This is a CHECK, not a detector:
# it refuses a manifest that claims a licence the tree does not corroborate,
# and it is deliberately unable to invent an id of its own.
LICENSE_FILENAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE",
                     "LICENCE.md", "LICENCE.txt", "COPYING", "COPYING.txt",
                     "LICENSE-MIT", "LICENSE-APACHE")
_LICENSE_MARKERS: dict[str, tuple[str, ...]] = {
    "MIT": ("MIT License", "Permission is hereby granted, free of charge"),
    "Apache-2.0": ("Apache License", "Version 2.0"),
    "BSD-2-Clause": ("Redistribution and use in source and binary forms",),
    "BSD-3-Clause": ("Redistribution and use in source and binary forms",),
    "ISC": ("ISC License", "Permission to use, copy, modify"),
    "MPL-2.0": ("Mozilla Public License",),
    "LGPL-2.1": ("GNU Lesser General Public License",),
    "LGPL-3.0": ("GNU Lesser General Public License",),
    "GPL-2.0": ("GNU General Public License",),
    "GPL-3.0": ("GNU General Public License",),
    "AGPL-3.0": ("GNU Affero General Public License",),
}


def license_problem(tree: Path, declared: str) -> str | None:
    """Why the declared licence is not corroborated by the tree, or None.

    The plan requires a licence that is present AND identifiable. Recording an
    SPDX id from memory would make the manifest a claim about the world that
    nothing checks; this reads the file that is actually there."""
    found: Path | None = None
    for name in LICENSE_FILENAMES:
        candidate = tree / name
        if candidate.is_file():
            found = candidate
            break
    if found is None:
        return "no licence file in the repository root"
    markers = _LICENSE_MARKERS.get(declared)
    if markers is None:
        return f"licence id {declared!r} is not one this round recognises"
    try:
        head = found.read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError:
        return "the licence file could not be read"
    if not any(m.lower() in head.lower() for m in markers):
        return f"the licence file does not read like {declared}"
    return None


class AcquisitionError(Exception):
    """A repository cannot be acquired. The message is safe to print: it
    never contains a filesystem path or any repository content."""


# ---- manifest entries ----------------------------------------------------------------

@dataclass(frozen=True)
class RepoSpec:
    """One line of the corpus manifest — the only thing ever committed about
    a repository. Deliberately has no field for a path."""

    repo_id: str
    url: str
    commit: str
    license_spdx: str
    language: str

    def validate(self) -> None:
        if not _REPO_ID_RE.match(self.repo_id):
            raise AcquisitionError("repo_id must be lowercase [a-z0-9_-]")
        if not _SHA_RE.match(self.commit):
            raise AcquisitionError(
                f"{self.repo_id}: commit must be a full 40-hex SHA — a branch "
                "or tag is not a pin")
        if self.language not in SUPPORTED_LANGUAGES:
            raise AcquisitionError(
                f"{self.repo_id}: language {self.language!r} is not one the "
                "catalog has rules for")
        if not _SPDX_RE.match(self.license_spdx):
            raise AcquisitionError(f"{self.repo_id}: license id is not usable")
        problem = url_problem(self.url)
        if problem is not None:
            raise AcquisitionError(f"{self.repo_id}: {problem}")


def url_problem(url: str) -> str | None:
    """Why this URL may not be fetched, or None. Same shape of rule as the
    library's own git-url guard: https only, known host, no credentials, no
    query, no fragment."""
    u = (url or "").strip()
    if not u.lower().startswith("https://"):
        return "only https:// is allowed"
    if any(c.isspace() for c in u) or "\\" in u:
        return "the url contains invalid characters"
    if "@" in u:
        return "credentials in the url are not allowed"
    if "?" in u or "#" in u:
        return "query strings and fragments are not allowed"
    rest = u[len("https://"):]
    slash = rest.find("/")
    if slash <= 0 or slash == len(rest) - 1:
        return "the url must include a host and a repository path"
    host = rest[:slash].lower()
    if ":" in host:
        return "custom ports are not allowed"
    if host not in ALLOWED_HOSTS:
        return f"host must be one of {', '.join(ALLOWED_HOSTS)}"
    if ".." in rest:
        return "path traversal is not allowed"
    return None


def load_manifest(path: Path) -> list[RepoSpec]:
    """Read and fully validate a manifest. Duplicate ids, duplicate URLs and
    duplicate commits are all refused — a corpus that counts one repository
    twice reports a denominator that does not exist."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AcquisitionError("the manifest could not be read as JSON") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("repositories"),
                                                   list):
        raise AcquisitionError("the manifest must hold a 'repositories' list")
    specs: list[RepoSpec] = []
    for item in raw["repositories"]:
        if not isinstance(item, dict):
            raise AcquisitionError("each repository entry must be an object")
        allowed = {"repo_id", "url", "commit", "license_spdx", "language"}
        if set(item) != allowed:
            raise AcquisitionError(
                "a repository entry must carry exactly "
                f"{', '.join(sorted(allowed))}")
        spec = RepoSpec(**item)
        spec.validate()
        specs.append(spec)
    for field_name in ("repo_id", "url", "commit"):
        seen = [getattr(s, field_name) for s in specs]
        dupes = {v for v in seen if seen.count(v) > 1}
        if dupes:
            raise AcquisitionError(
                f"duplicate {field_name} in the manifest: {sorted(dupes)}")
    return specs


# ---- safe git ------------------------------------------------------------------------

# Variables the OS itself needs for a process to resolve a name and open a
# TLS socket. Stripping the environment down to PATH alone looks safer and is
# not: on Windows, git without SystemRoot fails with
# "getaddrinfo() thread failed to start" — found by running this, not by
# reading it. The allowlist is what the OS needs, and nothing about the user.
_OS_PASSTHROUGH = ("SystemRoot", "SYSTEMROOT", "windir", "COMSPEC", "PATHEXT",
                   "TEMP", "TMP", "TMPDIR", "NUMBER_OF_PROCESSORS",
                   "PROCESSOR_ARCHITECTURE", "LANG", "LC_ALL")


def git_env(environ: dict[str, str] | None = None) -> dict[str, str]:
    """A git environment that cannot prompt, cannot read the user's config,
    cannot run hooks, and cannot be talked into a non-https protocol —
    carrying only the OS variables a network call actually requires.

    Deliberately absent: every credential helper, every token, HOME and
    USERPROFILE (so no `~/.gitconfig`, no `~/.netrc`, no keychain), and
    anything else from the caller's environment."""
    import os as _os

    src = _os.environ if environ is None else environ
    env = {name: src[name] for name in _OS_PASSTHROUGH if name in src}
    env["PATH"] = src.get("PATH", "")
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": _os.devnull,
        "GIT_CONFIG_SYSTEM": _os.devnull,
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
        # no HOME / USERPROFILE: no user config, no netrc, no credential store
    })
    return env


def _git_argv(repo_dir: Path, *args: str) -> list[str]:
    """Fixed argv, no shell. `core.hooksPath` is pointed at a path that does
    not exist, so a fetched repository cannot execute anything on checkout."""
    return [
        "git",
        "-c", "core.hooksPath=" + str(repo_dir / ".nohooks"),
        "-c", "protocol.version=2",
        "-c", "advice.detachedHead=false",
        "-C", str(repo_dir),
        *args,
    ]


@dataclass
class RepoResult:
    repo_id: str
    accepted: bool
    reason: str = ""
    source_files: int = 0
    source_bytes: int = 0
    by_language: dict[str, int] = field(default_factory=dict)
    has_manifest: bool = False
    head: str = ""


def acquire_one(spec: RepoSpec, repos_root: Path, *,
                run: Callable[..., Any] | None = None) -> RepoResult:
    """Fetch exactly one pinned commit into `repos_root/<repo_id>`.

    `run` is the subprocess runner and exists so the tests can drive this
    against local fixture repositories with no network at all."""
    runner = run if run is not None else subprocess.run
    spec.validate()
    target = repos_root / spec.repo_id
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    env = git_env()

    def git(*args: str, what: str) -> str:
        proc = runner(_git_argv(target, *args), capture_output=True,
                      text=True, env=env, shell=False, timeout=1800)
        if proc.returncode != 0:
            raise AcquisitionError(f"{spec.repo_id}: {what} failed")
        return (proc.stdout or "").strip()

    try:
        git("init", "--quiet", what="init")
        git("remote", "add", "origin", spec.url, what="remote add")
        # the pinned SHA is fetched DIRECTLY: no branch, no tags, no
        # submodules, depth 1 — the only object that can be checked out is
        # the one the manifest names
        git("fetch", "--depth", "1", "--no-tags", "--recurse-submodules=no",
            "origin", spec.commit, what="fetch")
        git("checkout", "--quiet", "--detach", "FETCH_HEAD", what="checkout")
        head = git("rev-parse", "HEAD", what="rev-parse")
    except AcquisitionError as e:
        shutil.rmtree(target, ignore_errors=True)
        return RepoResult(spec.repo_id, False, str(e))

    if head != spec.commit:
        shutil.rmtree(target, ignore_errors=True)
        return RepoResult(spec.repo_id, False,
                          f"{spec.repo_id}: HEAD does not match the pinned "
                          "commit")
    return inspect_tree(spec, target, head=head)


def inspect_tree(spec: RepoSpec, tree: Path, *, head: str = "") -> RepoResult:
    """Apply the plan's inclusion/exclusion rules to a checked-out tree."""
    if any((tree / d).is_dir() for d in VENDOR_DIRS):
        return RepoResult(spec.repo_id, False,
                          f"{spec.repo_id}: vendors third-party source in-tree")
    if (tree / ".gitmodules").is_file():
        return RepoResult(spec.repo_id, False,
                          f"{spec.repo_id}: requires submodules")
    licence = license_problem(tree, spec.license_spdx)
    if licence is not None:
        return RepoResult(spec.repo_id, False, f"{spec.repo_id}: {licence}")

    by_language: dict[str, int] = {}
    total_files = total_bytes = 0
    for lang, suffixes in _LANG_SUFFIXES.items():
        count = 0
        for suffix in suffixes:
            for f in tree.rglob(f"*{suffix}"):
                parts = set(f.parts)
                if parts & set(VENDOR_DIRS) or ".git" in parts:
                    continue
                count += 1
                try:
                    total_bytes += f.stat().st_size
                except OSError:
                    pass
        if count:
            by_language[lang] = count
        total_files += count

    has_manifest = any(
        any(tree.rglob(pattern))
        for pattern in MANIFEST_GLOBS.get(spec.language, ()))

    result = RepoResult(spec.repo_id, True, "", total_files, total_bytes,
                        by_language, has_manifest, head)
    if total_files < MIN_SOURCE_FILES:
        result.accepted, result.reason = False, (
            f"{spec.repo_id}: only {total_files} source files "
            f"(minimum {MIN_SOURCE_FILES})")
    elif total_files > MAX_SOURCE_FILES:
        result.accepted, result.reason = False, (
            f"{spec.repo_id}: {total_files} source files "
            f"(maximum {MAX_SOURCE_FILES})")
    elif not has_manifest:
        result.accepted, result.reason = False, (
            f"{spec.repo_id}: no dependency manifest, so the H family cannot "
            "fire")
    elif spec.language not in by_language:
        result.accepted, result.reason = False, (
            f"{spec.repo_id}: no {spec.language} sources found")
    return result


# ---- identity ------------------------------------------------------------------------

def sample_id(repo_id: str, identity: str) -> str:
    """Stable 16-hex id derived from the identity of the thing itself, so the
    same corpus always yields the same sample and two different things can
    never collide into one label."""
    digest = hashlib.sha256(f"{repo_id}:{identity}".encode("utf-8"))
    return digest.hexdigest()[:16]


def acquire(manifest_path: Path, root: Path, *,
            run: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Acquire every repository in the manifest. Returns a summary carrying
    counts only — no paths, no content."""
    specs = load_manifest(manifest_path)
    repos_root = root / REPOS_DIRNAME
    repos_root.mkdir(parents=True, exist_ok=True)
    results = [acquire_one(s, repos_root, run=run) for s in specs]
    accepted = [r for r in results if r.accepted]
    return {
        "requested": len(specs),
        "accepted": len(accepted),
        "rejected": len(results) - len(accepted),
        "repositories": [
            {"repo_id": r.repo_id, "accepted": r.accepted, "reason": r.reason,
             "source_files": r.source_files, "source_bytes": r.source_bytes,
             "by_language": dict(sorted(r.by_language.items())),
             "has_manifest": r.has_manifest}
            for r in sorted(results, key=lambda x: x.repo_id)],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        description="REAL-CORPUS-1A acquisition (no measurement)")
    p.add_argument("--manifest", required=True)
    p.add_argument("--root", default=str(LOCAL_ROOT))
    args = p.parse_args(argv)
    try:
        summary = acquire(Path(args.manifest), Path(args.root))
    except AcquisitionError as e:
        print(f"acquisition refused: {e}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

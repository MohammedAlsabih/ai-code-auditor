"""Project configuration (W2-B2.8A): a small, version-pinned `.auditor.toml`.

Scope in schema_version 1 ONLY:
- exclude_paths:             fully excluded from scanning
- dependency_exclude_paths:  code rules still run; dependency audit disabled
- npm_roots:                 manifestless dirs the USER declares npm-owned
- runtime_builtins:          extra per-ecosystem runtime built-in import names
- internal_packages:         per-ecosystem internal package names/prefixes
- complexity_threshold:      P006 cyclomatic threshold (default 10)

Contract: structured TOML parsing only (no code execution); repository-relative
POSIX paths only (absolute/drive/UNC/`..` rejected); a malformed file or an
unknown schema_version fails LOUDLY with a clear message — never a silent
ignore. Severity overrides / offline policy / SARIF are B2.8B, not here.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from auditor.errors import AuditorError

CONFIG_FILENAME = ".auditor.toml"
CONFIG_SCHEMA_VERSION = 1

_KNOWN_KEYS = {"schema_version", "exclude_paths", "dependency_exclude_paths",
               "npm_roots", "runtime_builtins", "internal_packages",
               "complexity_threshold"}
_ECOSYSTEMS = {"npm", "pypi", "nuget", "maven", "python"}
_GLOB_CHARS = ("*", "?", "[")


class ConfigError(AuditorError):
    """A malformed or rejected .auditor.toml. Messages name the FIELD and the
    reason only — an untrusted value or unknown key (which may carry a
    machine path or a secret) is NEVER echoed; only the known legal field
    names may appear."""


@dataclass(frozen=True)
class AuditorConfig:
    exclude_paths: tuple[str, ...] = ()
    dependency_exclude_paths: tuple[str, ...] = ()
    npm_roots: tuple[str, ...] = ()
    runtime_builtins: dict[str, tuple[str, ...]] = field(default_factory=dict)
    internal_packages: dict[str, tuple[str, ...]] = field(default_factory=dict)
    complexity_threshold: int | None = None
    loaded_from: str = ""   # display name only ("--config" or the filename)


def _reject_path(pattern: str) -> str | None:
    """Reason a path pattern is rejected, or None. POSIX repo-relative only."""
    if not pattern or not pattern.strip():
        return "empty path"
    try:
        pattern.encode("utf-8")
    except UnicodeEncodeError:
        return "entry is not valid UTF-8 text"
    if "\\" in pattern:
        return "backslash separators are not allowed (use POSIX '/')"
    if ":" in pattern:
        return "drive letters are not allowed"
    if pattern.startswith("/") or pattern.startswith("//"):
        return "absolute and UNC paths are not allowed"
    parts = pattern.split("/")
    if any(p == ".." for p in parts):
        return "'..' components are not allowed"
    if any(p == "" for p in parts):
        return "empty path components are not allowed"
    return None


def _path_list(data: dict, key: str) -> tuple[str, ...]:
    raw = data.get(key)
    if raw is None:
        return ()
    if not isinstance(raw, list) or any(not isinstance(x, str) for x in raw):
        raise ConfigError(f"config: {key} must be a list of strings")
    out: list[str] = []
    for p in raw:
        p = p.strip().rstrip("/")
        reason = _reject_path(p)
        if reason is not None:
            # the offending VALUE is never echoed (it may carry a machine
            # path or a secret) — field + reason only
            raise ConfigError(
                f"config: {key} contains an invalid entry: {reason}")
        if p not in out:
            out.append(p)
    return tuple(out)


def _name_map(data: dict, key: str) -> dict[str, tuple[str, ...]]:
    raw = data.get(key)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"config: {key} must be a table of ecosystem -> list")
    out: dict[str, tuple[str, ...]] = {}
    for eco, names in raw.items():
        if eco not in _ECOSYSTEMS:
            # the unknown ecosystem NAME is untrusted — never echoed
            raise ConfigError(
                f"config: {key} contains an unsupported ecosystem "
                f"(known: {', '.join(sorted(_ECOSYSTEMS))})")
        if not isinstance(names, list) or any(
                not isinstance(x, str) or not x.strip() for x in names):
            raise ConfigError(
                f"config: {key}.{eco} must be a list of non-empty strings")
        out[eco] = tuple(dict.fromkeys(n.strip() for n in names))
    return out


def load_config(repo_root: Path, explicit: str | None = None) -> AuditorConfig:
    """Load `--config PATH` when given, else auto-discover `.auditor.toml` at
    the target root. No file => empty defaults."""
    if explicit:
        path = Path(explicit)
        display = "--config file"
        if not path.is_file():
            raise ConfigError("config: --config file not found")
    else:
        path = repo_root / CONFIG_FILENAME
        display = CONFIG_FILENAME
        if not path.is_file():
            return AuditorConfig()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"config: {display} is not valid TOML: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"config: {display} must be a TOML table")
    version = data.get("schema_version")
    if version != CONFIG_SCHEMA_VERSION:
        # the raw value is untrusted — never echoed
        raise ConfigError(
            f"config: unsupported schema_version (expected {CONFIG_SCHEMA_VERSION})")
    unknown = sorted(set(data) - _KNOWN_KEYS)
    if unknown:
        # unknown key NAMES are untrusted too: count only + the legal names
        raise ConfigError(
            f"config: configuration contains {len(unknown)} unknown key(s) — "
            f"known keys: {', '.join(sorted(_KNOWN_KEYS))}")
    threshold = data.get("complexity_threshold")
    if threshold is not None and (
            isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= 100):
        raise ConfigError(
            "config: complexity_threshold must be an integer between 1 and 100")
    npm_roots = _path_list(data, "npm_roots")
    for r in npm_roots:
        if any(c in r for c in _GLOB_CHARS):
            raise ConfigError(
                "config: npm_roots contains an invalid entry: globs are not "
                "allowed (plain repository-relative directories only)")
        target = repo_root / r
        if not target.is_dir():
            raise ConfigError(
                "config: npm_roots contains an invalid entry: the directory "
                "does not exist in the repository")
        try:
            resolved = target.resolve()
            repo = repo_root.resolve()
            if resolved != repo and repo not in resolved.parents:
                raise ConfigError(
                    "config: npm_roots contains an invalid entry: the "
                    "directory escapes the repository (symlink?)")
        except OSError as e:
            raise ConfigError(
                "config: npm_roots contains an invalid entry: the directory "
                "cannot be resolved") from e
    return AuditorConfig(
        exclude_paths=_path_list(data, "exclude_paths"),
        dependency_exclude_paths=_path_list(data, "dependency_exclude_paths"),
        npm_roots=npm_roots,
        runtime_builtins=_name_map(data, "runtime_builtins"),
        internal_packages=_name_map(data, "internal_packages"),
        complexity_threshold=threshold,
        loaded_from=display,
    )


def path_matches(rel: str, pattern: str) -> bool:
    """True when repo-relative POSIX `rel` is selected by `pattern`.

    - a plain pattern selects the exact path or its whole subtree, on
      COMPONENT boundaries only ('apps/ap' never selects 'apps/api/x');
    - a glob pattern (fnmatch, case-sensitive) selects a matching full path
      or a matching directory's subtree.
    """
    rel = rel.strip("/")
    if not any(c in pattern for c in _GLOB_CHARS):
        return rel == pattern or rel.startswith(pattern + "/")
    if fnmatchcase(rel, pattern):
        return True
    # subtree of a glob-matched DIRECTORY: check each ancestor prefix
    parts = rel.split("/")
    for i in range(1, len(parts)):
        if fnmatchcase("/".join(parts[:i]), pattern):
            return True
    return False


def any_match(rel: str, patterns: tuple[str, ...]) -> bool:
    return any(path_matches(rel, p) for p in patterns)


# built-in dependency-audit exclusion: classic vendored-asset directories.
# Deliberately MINIMAL — 'generated' code often imports real packages, so it
# is config-only, never a builtin.
_VENDOR_SEGMENTS = frozenset({"vendor", "vendored"})


def is_vendored(rel: str) -> bool:
    return any(seg in _VENDOR_SEGMENTS for seg in rel.strip("/").split("/")[:-1])

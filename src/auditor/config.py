"""Project configuration: a small, version-pinned `.auditor.toml`.

schema_version 1 (W2-B2.8A):
- exclude_paths:             fully excluded from scanning
- dependency_exclude_paths:  code rules still run; dependency audit disabled
- npm_roots:                 manifestless dirs the USER declares npm-owned
- runtime_builtins:          extra per-ecosystem runtime built-in import names
- internal_packages:         per-ecosystem internal package names/prefixes
- complexity_threshold:      P006 cyclomatic threshold (default 10)

schema_version 2 (W2-B2.8B2) adds — and ONLY under v2; the same keys in a v1
file stay unknown-key errors:
- [policy] heuristic_errors = "review" | "block"
- [rule_levels]  RULE_ID = "error" | "warning" | "note"  (level overrides;
  ids are shape-checked here and validated against the tool catalog by the
  CLI before any scan runs)

Contract: structured TOML parsing only (no code execution); repository-relative
POSIX paths only (absolute/drive/UNC/`..` rejected); a malformed file or an
unknown schema_version fails LOUDLY with a clear message — never a silent
ignore.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from auditor.errors import AuditorError

CONFIG_FILENAME = ".auditor.toml"
CONFIG_SCHEMA_VERSIONS = (1, 2)

_KNOWN_KEYS_V1 = {"schema_version", "exclude_paths", "dependency_exclude_paths",
                  "npm_roots", "runtime_builtins", "internal_packages",
                  "complexity_threshold"}
_KNOWN_KEYS_V2 = _KNOWN_KEYS_V1 | {"policy", "rule_levels"}
_POLICY_KEYS = {"heuristic_errors"}
_HEURISTIC_ERROR_VALUES = ("review", "block")
_GATE_LEVELS = ("error", "warning", "note")
# rule-id SHAPE gate only (existence is checked against the catalog by the
# CLI): letters/digits and the separators our rule families actually use.
_RULE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9:._-]{0,63}$")
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
    # schema v2 gate policy (defaults = the tool contract; v1 files and the
    # no-config case keep exactly these values)
    heuristic_errors: str = "review"
    rule_levels: dict[str, str] = field(default_factory=dict)


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
    if version not in CONFIG_SCHEMA_VERSIONS:
        # the raw value is untrusted — never echoed
        raise ConfigError(
            "config: unsupported schema_version (expected "
            f"{' or '.join(str(v) for v in CONFIG_SCHEMA_VERSIONS)})")
    known = _KNOWN_KEYS_V1 if version == 1 else _KNOWN_KEYS_V2
    unknown = sorted(set(data) - known)
    if unknown:
        # unknown key NAMES are untrusted too: count only + the legal names.
        # NB: policy/rule_levels in a v1 file land here deliberately — v1
        # semantics never grow silently.
        raise ConfigError(
            f"config: configuration contains {len(unknown)} unknown key(s) — "
            f"known keys: {', '.join(sorted(known))}")
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
    heuristic_errors, rule_levels = _policy_tables(data)
    return AuditorConfig(
        exclude_paths=_path_list(data, "exclude_paths"),
        dependency_exclude_paths=_path_list(data, "dependency_exclude_paths"),
        npm_roots=npm_roots,
        runtime_builtins=_name_map(data, "runtime_builtins"),
        internal_packages=_name_map(data, "internal_packages"),
        complexity_threshold=threshold,
        loaded_from=display,
        heuristic_errors=heuristic_errors,
        rule_levels=rule_levels,
    )


def _policy_tables(data: dict) -> tuple[str, dict[str, str]]:
    """Parse `[policy]` + `[rule_levels]` (schema v2; absent under v1 by the
    unknown-key gate). Violating values or keys are NEVER echoed — field name,
    reason, and the legal values only."""
    heuristic_errors = "review"
    policy = data.get("policy")
    if policy is not None:
        if not isinstance(policy, dict):
            raise ConfigError("config: policy must be a table")
        unknown = sorted(set(policy) - _POLICY_KEYS)
        if unknown:
            raise ConfigError(
                f"config: policy contains {len(unknown)} unknown key(s) — "
                f"known keys: {', '.join(sorted(_POLICY_KEYS))}")
        raw = policy.get("heuristic_errors", "review")
        if raw not in _HEURISTIC_ERROR_VALUES:
            raise ConfigError(
                "config: policy.heuristic_errors must be one of: "
                f"{', '.join(_HEURISTIC_ERROR_VALUES)}")
        heuristic_errors = raw
    levels: dict[str, str] = {}
    table = data.get("rule_levels")
    if table is not None:
        if not isinstance(table, dict):
            raise ConfigError("config: rule_levels must be a table of "
                              "rule id -> level")
        for rule_id, level in table.items():
            if not isinstance(rule_id, str) or not _RULE_ID_RE.match(rule_id):
                # a malformed key may carry anything — never echoed
                raise ConfigError(
                    "config: rule_levels contains an invalid rule id "
                    "(letters/digits and ':', '.', '_', '-' only)")
            if level not in _GATE_LEVELS:
                raise ConfigError(
                    "config: rule_levels contains an invalid level — allowed: "
                    f"{', '.join(_GATE_LEVELS)}")
            levels[rule_id] = level
    return heuristic_errors, levels


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

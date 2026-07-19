from __future__ import annotations

import json
import shutil
import subprocess
from importlib.resources import files as pkg_files
from pathlib import Path

from auditor.core.models import Finding, Severity

_SEV_MAP = {"ERROR": Severity.RED, "WARNING": Severity.YELLOW, "INFO": Severity.BLUE}


def bundled_rules_path() -> Path:
    return Path(str(pkg_files("auditor") / "semgrep_rules" / "auditor-extra.yml"))


def find_binary(explicit: str | None = None) -> tuple[str, str] | None:
    candidates = [explicit] if explicit else ["opengrep", "semgrep"]
    for name in candidates:
        path = shutil.which(name) if name else None
        if not path:
            continue
        try:
            proc = subprocess.run([path, "--version"], capture_output=True,
                                  text=True, timeout=30)
            if proc.returncode == 0:
                return path, proc.stdout.strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def run_semgrep(binary: str, project_root: Path, extra_configs: list[str],
                expected_paths: set[str] | None = None) -> tuple[list[Finding], str]:
    """Returns (findings, status). Status in success | partial (...) | failed |
    failed (exit N) | timed_out | invalid_output — zero findings must NEVER be
    confusable with engine failure OR with incomplete coverage. Measured exit
    codes: clean scan = 0; config errors = 7 => not in (0,1). Completeness:
    rc+JSON validity do NOT prove it — semgrep can tolerate/skip files. We
    reconcile `paths.scanned` against the source files we EXPECTED it to cover
    (`expected_paths`, absolute POSIX). Any expected file missing from scanned,
    or a non-empty `errors`/`paths.skipped`, demotes success to partial."""
    cmd = [binary, "scan", "--json", "--quiet", "--config", str(bundled_rules_path())]
    if "semgrep" in Path(binary).stem.lower():
        # verified: semgrep CE accepts --metrics=off and still scans; without it
        # the CLI may phone metrics home. Opengrep ships without telemetry.
        cmd += ["--metrics", "off"]
    for cfg in extra_configs:
        cmd += ["--config", cfg]
    cmd.append(str(project_root))
    # Default invocation is fully local: the only --config is our bundled file,
    # so no Semgrep-registry fetch and no remote rules unless the USER passes
    # extra configs explicitly (their own licensed act).
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=600)
    except subprocess.TimeoutExpired:
        return [], "timed_out"
    except (OSError, subprocess.SubprocessError):
        return [], "failed"
    if proc.returncode not in (0, 1):
        return [], f"failed (exit {proc.returncode})"
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], "invalid_output"
    # Completeness reconciliation: errors + skipped + scanned-vs-expected
    paths = data.get("paths") or {}
    root = project_root.resolve()

    def _norm(p: str) -> str:
        # CP-8b.6: ONE base for scanned/results/expected. semgrep emits scanned
        # paths RELATIVE to the scan root — anchoring them to the CWD (the old
        # Path(p).resolve()) never matched the absolute expected set. Anchor
        # relative paths to project_root instead.
        pp = Path(p)
        if not pp.is_absolute():
            pp = project_root / p
        try:
            return pp.resolve().as_posix()
        except OSError:
            return pp.as_posix()

    scanned = {_norm(p) for p in (paths.get("scanned") or [])}
    reasons: list[str] = []
    n_errors = len(data.get("errors") or [])
    if n_errors:
        reasons.append(f"{n_errors} file errors")
    n_skipped = len(paths.get("skipped") or [])
    if n_skipped:
        reasons.append(f"{n_skipped} skipped")
    if expected_paths:
        exp = {_norm(p) for p in expected_paths}
        missing = exp - scanned if scanned else exp
        if missing:
            reasons.append(f"{len(missing)}/{len(exp)} expected files not scanned")
    results = data.get("results")
    if not isinstance(results, list):
        # a results block that is not a list at all is unusable OUTPUT — this
        # is different from one malformed result, which only degrades
        return [], "invalid_output"
    out: list[Finding] = []
    escaped = 0
    malformed = 0
    for res in results:
        # one malformed RESULT never sinks the audit: keep the good ones,
        # skip the broken one, and surface the count as a partial reason
        if not isinstance(res, dict) or not isinstance(res.get("path", ""), str):
            malformed += 1
            continue
        raw = res.get("path", "")
        p = Path(raw)
        if not p.is_absolute():
            p = project_root / raw          # relative result paths are anchored to root
        try:
            rp = p.resolve()
        except OSError:
            rp = p
        try:
            rel = rp.relative_to(root).as_posix()
        except ValueError:
            # a result path OUTSIDE the scan root is DROPPED, never reduced to a
            # bare basename that would masquerade as an in-repo finding (CP-8.6)
            escaped += 1
            continue
        extra = res.get("extra")
        if not isinstance(extra, dict):
            malformed += 1                  # no usable severity/message payload
            continue
        # semgrep's spec types extra.metadata as raw_json: dict/string/list/
        # null are ALL legal shapes — a non-dict simply means "no declared
        # precision"; it is neither an error nor invalid_output
        meta = extra.get("metadata")
        precision = meta.get("auditor-precision") if isinstance(meta, dict) else None
        if precision not in ("exact", "heuristic"):
            # rules without vetted metadata (e.g. third-party packs) are
            # pattern matches, not proofs — never silently exact
            precision = "heuristic"
        try:
            start = res.get("start")
            line = int(start.get("line", 0)) if isinstance(start, dict) else 0
            message = extra.get("message")
            message = message if isinstance(message, str) else ""
            out.append(Finding(
                rule_id="S:" + str(res.get("check_id", "unknown")),
                severity=_SEV_MAP.get(extra.get("severity", "WARNING"),
                                      Severity.YELLOW),
                title=(message or "semgrep finding").splitlines()[0][:100],
                file=rel, line=line,
                snippet="", detail=message, language="",
                engine="semgrep", precision=precision))
        except (TypeError, ValueError):
            malformed += 1
            continue
    if escaped:
        reasons.append(f"{escaped} result(s) outside scan root dropped")
    if malformed:
        reasons.append(f"{malformed} malformed result(s) skipped")
    status = "success" if not reasons else "partial (" + ", ".join(reasons) + ")"
    return out, status

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

    def _norm(p: str) -> str:
        try:
            return Path(p).resolve().as_posix()
        except OSError:
            return p.replace("\\", "/")

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
    root = project_root.resolve()
    out: list[Finding] = []
    escaped = 0
    for res in data.get("results", []):
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
        extra = res.get("extra", {})
        out.append(Finding(
            rule_id="S:" + res.get("check_id", "unknown"),
            severity=_SEV_MAP.get(extra.get("severity", "WARNING"), Severity.YELLOW),
            title=(extra.get("message") or "semgrep finding").splitlines()[0][:100],
            file=rel, line=int(res.get("start", {}).get("line", 0)),
            snippet="", detail=extra.get("message", ""), language="",
            engine="semgrep"))
    if escaped:
        reasons.append(f"{escaped} result(s) outside scan root dropped")
    status = "success" if not reasons else "partial (" + ", ".join(reasons) + ")"
    return out, status

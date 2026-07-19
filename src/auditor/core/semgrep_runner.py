from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from importlib.resources import files as pkg_files
from pathlib import Path

from auditor.core.models import Finding, Severity

_SEV_MAP = {"ERROR": Severity.RED, "WARNING": Severity.YELLOW, "INFO": Severity.BLUE}


@dataclass
class SemgrepRun:
    """STRUCTURED evidence of one engine invocation (B2-C). The ledger is
    built from these fields — never from parsing the human status_text.
    status_text keeps the exact legacy strings for display/compat."""
    findings: list[Finding] = field(default_factory=list)
    state: str = "failed"       # success | partial | failed | timed_out | invalid_output
    started: bool = False       # the process actually launched
    scanned_paths: set[str] = field(default_factory=set)       # normalized posix
    expected_paths: set[str] = field(default_factory=set)      # normalized posix
    missing_expected_paths: set[str] = field(default_factory=set)
    partial_reasons: list[str] = field(default_factory=list)   # ALL causes (display)
    # causes NOT attributable to a specific path (path-less engine errors,
    # missing scanned evidence, escaped/malformed results) — safe to record on
    # every project. Path-ATTRIBUTABLE causes live only in the path sets below
    # and are derived per project by exact membership.
    shared_partial_reasons: list[str] = field(default_factory=list)
    error_paths: set[str] = field(default_factory=set)     # cli_error with a path
    skipped_paths: set[str] = field(default_factory=set)   # skipped_target paths
    exit_code: int | None = None
    status_text: str = "failed"


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
    """LEGACY contract kept for existing callers/tests: (findings, status_text).
    New consumers use run_semgrep_structured — same single execution."""
    run = run_semgrep_structured(binary, project_root, extra_configs,
                                 expected_paths=expected_paths)
    return run.findings, run.status_text


def run_semgrep_structured(binary: str, project_root: Path,
                           extra_configs: list[str],
                           expected_paths: set[str] | None = None) -> SemgrepRun:
    """Returns a SemgrepRun. status_text in success | partial (...) | failed |
    failed (exit N) | timed_out | invalid_output — zero findings must NEVER be
    confusable with engine failure OR with incomplete coverage. Measured exit
    codes: clean scan = 0; config errors = 7 => not in (0,1). Completeness:
    rc+JSON validity do NOT prove it — semgrep can tolerate/skip files. We
    reconcile `paths.scanned` against the source files we EXPECTED it to cover
    (`expected_paths`, absolute POSIX). Any expected file missing from scanned,
    or a non-empty `errors`/`paths.skipped`, demotes success to partial."""
    # --verbose (NOT --quiet: they set opposite ends of the same logging
    # verbosity) is what makes semgrep include paths.scanned in the JSON
    # output (semgrep_output_v1.atd notes scanned appears with --verbose) —
    # completeness evidence is REQUESTED, not assumed. Extra logging goes to
    # stderr, which is captured separately from the JSON on stdout.
    cmd = [binary, "scan", "--json", "--verbose", "--config", str(bundled_rules_path())]
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
    exp_norm = {_norm_to(project_root, p) for p in (expected_paths or set())}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=600)
    except subprocess.TimeoutExpired:
        return SemgrepRun(state="timed_out", started=True, status_text="timed_out",
                          expected_paths=exp_norm, missing_expected_paths=set(exp_norm))
    except (OSError, subprocess.SubprocessError):
        return SemgrepRun(state="failed", started=False, status_text="failed",
                          expected_paths=exp_norm, missing_expected_paths=set(exp_norm))
    if proc.returncode not in (0, 1):
        return SemgrepRun(state="failed", started=True, exit_code=proc.returncode,
                          status_text=f"failed (exit {proc.returncode})",
                          expected_paths=exp_norm, missing_expected_paths=set(exp_norm))
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return SemgrepRun(state="invalid_output", started=True,
                          exit_code=proc.returncode, status_text="invalid_output",
                          expected_paths=exp_norm, missing_expected_paths=set(exp_norm))
    # STRUCTURAL validation first (fix round): the top level must be an
    # object, results/errors lists, paths an object, scanned/skipped lists of
    # strings. Anything else is output we cannot rely on => invalid_output —
    # never an AttributeError/TypeError, never a string counted as N items,
    # and the reason carries no stdout or machine paths.
    def _invalid() -> SemgrepRun:
        return SemgrepRun(state="invalid_output", started=True,
                          exit_code=proc.returncode, status_text="invalid_output",
                          expected_paths=exp_norm,
                          missing_expected_paths=set(exp_norm))

    def _str_list(v) -> bool:
        return isinstance(v, list) and all(isinstance(x, str) for x in v)

    if not isinstance(data, dict):
        return _invalid()
    results = data.get("results")
    if not isinstance(results, list):
        # a results block that is not a list at all is unusable OUTPUT — this
        # is different from one malformed result, which only degrades
        return _invalid()
    errors = data.get("errors")
    if errors is None:
        errors = []
    if not isinstance(errors, list):
        return _invalid()
    paths = data.get("paths")
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        return _invalid()
    scanned_raw = paths.get("scanned")          # None stays distinct: NO evidence
    if scanned_raw is not None and not _str_list(scanned_raw):
        return _invalid()
    skipped_raw = paths.get("skipped")
    if skipped_raw is None:
        skipped_raw = []
    if not isinstance(skipped_raw, list):
        return _invalid()

    root = project_root.resolve()
    # errors are cli_error OBJECTS (semgrep_output_v1.atd); one WITH a path is
    # attributable to the file's owning project, one without stays a shared
    # engine-level fact. A non-object element is not reliable error evidence —
    # fail closed as invalid_output, never crash, never count it as a file.
    error_paths: set[str] = set()
    global_errors = 0
    for e in errors:
        if not isinstance(e, dict):
            return _invalid()
        ep = e.get("path")
        if isinstance(ep, str) and ep.strip():
            error_paths.add(_norm_to(project_root, ep))
        else:
            global_errors += 1
    # paths.skipped entries are skipped_target OBJECTS {path, reason} per the
    # schema (a plain string is accepted as a legacy path-only form). [42] or
    # [{}] must never be laundered into "1 skipped" — invalid_output.
    skipped_paths: set[str] = set()
    for s in skipped_raw:
        if isinstance(s, str) and s.strip():
            skipped_paths.add(_norm_to(project_root, s))
            continue
        if isinstance(s, dict):
            sp = s.get("path")
            reason_ok = "reason" not in s or isinstance(s.get("reason"), str)
            if isinstance(sp, str) and sp.strip() and reason_ok:
                skipped_paths.add(_norm_to(project_root, sp))
                continue
        return _invalid()

    # Completeness reconciliation. Reasons split by ATTRIBUTABILITY: shared
    # reasons hold for the whole run; path-attributable facts (missing
    # expected files, per-file errors/skips) are carried as PATH SETS and
    # derived per project — never copied globally. scanned ABSENT is "no
    # completeness evidence" (partial, nothing claimed unscanned); scanned
    # PRESENT AND EMPTY is positive evidence that zero files were scanned.
    scanned_absent = scanned_raw is None
    scanned = ({_norm_to(project_root, p) for p in scanned_raw}
               if scanned_raw is not None else set())
    pre_display: list[str] = []
    shared: list[str] = []
    if errors:
        pre_display.append(f"{len(errors)} file errors")
    if global_errors:
        shared.append(f"{global_errors} file errors")
    if skipped_raw:
        pre_display.append(f"{len(skipped_raw)} skipped")
    if scanned_absent:
        pre_display.append("scanned path evidence unavailable")
        shared.append("scanned path evidence unavailable")
    missing: set[str] = set()
    missing_reason: list[str] = []
    if exp_norm and not scanned_absent:
        missing = exp_norm - scanned
        if missing:
            missing_reason.append(
                f"{len(missing)}/{len(exp_norm)} expected files not scanned")
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
        check_id = res.get("check_id")
        if not isinstance(check_id, str) or not check_id.strip():
            # a result with no usable identity must NOT be minted as a fake
            # "S:unknown" rule — it is a malformed result (partial), dropped
            malformed += 1
            continue
        try:
            start = res.get("start")
            line = int(start.get("line", 0)) if isinstance(start, dict) else 0
            message = extra.get("message")
            message = message if isinstance(message, str) else ""
            out.append(Finding(
                rule_id="S:" + check_id.strip(),
                severity=_SEV_MAP.get(extra.get("severity", "WARNING"),
                                      Severity.YELLOW),
                title=(message or "semgrep finding").splitlines()[0][:100],
                file=rel, line=line,
                snippet="", detail=message, language="",
                engine="semgrep", precision=precision))
        except (TypeError, ValueError):
            malformed += 1
            continue
    post: list[str] = []
    if escaped:
        post.append(f"{escaped} result(s) outside scan root dropped")
    if malformed:
        post.append(f"{malformed} malformed result(s) skipped")
    # legacy status order: errors, skipped, [no-evidence], missing, escaped, malformed
    all_reasons = pre_display + missing_reason + post
    state = "success" if not all_reasons else "partial"
    status = "success" if not all_reasons else "partial (" + ", ".join(all_reasons) + ")"
    return SemgrepRun(findings=out, state=state, started=True,
                      scanned_paths=scanned, expected_paths=exp_norm,
                      missing_expected_paths=missing,
                      partial_reasons=all_reasons,
                      shared_partial_reasons=shared + post,
                      error_paths=error_paths, skipped_paths=skipped_paths,
                      exit_code=proc.returncode, status_text=status)


def _norm_to(project_root: Path, p: str) -> str:
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


# ── B2-C: per-project execution recording for the S:* rules ─────────────────
# semgrep language names in descriptors are already mapped to adapter language
# names; SourceFile.language additionally uses "tsx" for .tsx/.jsx files.
_FILE_LANG_TO_RULE_LANG = {"tsx": "typescript"}


def record_semgrep_execution(entries, descriptors, run: SemgrepRun | None = None,
                             *, disabled: bool = False,
                             binary_missing: bool = False) -> None:
    """Distribute ONE engine invocation's structured evidence onto the
    per-project ledgers, per shipped S:* descriptor. Facts only, no status:

    - no files matching the rule's languages  -> not_applicable, attempted=0
    - --no-semgrep                            -> eligible + skipped, attempted=0
    - no usable binary                        -> eligible + unavailable, attempted=0
    - success                                 -> eligible=n files, attempted=1
    - partial                                 -> attempted=1, failures=0,
      structured partial_reasons; THIS project's expected-but-unscanned files
      counted into blocked_inputs (exact membership on the project's own file
      map — never path prefix matching)
    - started=False (process never launched)  -> eligible + unavailable,
      attempted=0 (no failure can be charged to a run that did not begin)
    - failed / timed_out / invalid_output with started=True
                                              -> attempted=1, failures=1, a
      failure reason with no stdout/stderr/machine paths

    attempted counts the RULE's one run over the project's file set (unit =
    invocation), never once per file. S:* attempts deliberately never touch
    Diagnostics.rule_attempted/rule_failures (double confidence penalty).
    `entries` = iterable of (ledger, source_files) pairs, one per project."""
    for ledger, files in entries:
        paths_by_lang: dict[str, list[str]] = {}
        for sf in files:
            lang = _FILE_LANG_TO_RULE_LANG.get(sf.language, sf.language)
            pp = Path(str(sf.path))
            try:
                norm = pp.resolve().as_posix()
            except OSError:
                norm = pp.as_posix()
            paths_by_lang.setdefault(lang, []).append(norm)
        for d in descriptors:
            rid = (d.rule_id,)
            elig = [p for lang in d.languages for p in paths_by_lang.get(lang, [])]
            if not elig:
                ledger.not_applicable(
                    rid, f"no {'/'.join(d.languages)} files in this project")
                continue
            ledger.eligible(rid, len(elig))
            if disabled:
                ledger.skipped(rid, "semgrep engine disabled by --no-semgrep")
                continue
            if binary_missing or run is None:
                ledger.unavailable(rid, "no semgrep/opengrep binary available")
                continue
            if not run.started:
                # the process NEVER launched (e.g. OSError on exec): that is an
                # inability, not an attempt — no failure can be charged to a
                # run that did not begin
                ledger.unavailable(rid, "semgrep/opengrep engine failed to start")
                continue
            if run.state in ("failed", "timed_out", "invalid_output"):
                ledger.attempted_failed(rid)
                reason = f"engine {run.state}"
                if run.exit_code is not None and run.state == "failed":
                    reason += f" (exit {run.exit_code})"
                ledger.failure_reason(rid, reason)
                continue
            ledger.attempted_ok(rid)                 # success OR partial: it RAN
            if run.state == "partial":
                # shared causes hold for the whole run; PATH-attributable
                # causes (missing/error/skipped files) are derived LOCALLY
                # from this project's own eligible files vs the run's path
                # sets (exact membership) — a clean project never inherits
                # another project's gap, and no raw path/reason is echoed
                for r in run.shared_partial_reasons:
                    ledger.partial_reason(rid, r)
                blocked_here = sum(1 for p in elig
                                   if p in run.missing_expected_paths)
                if blocked_here:
                    ledger.blocked(rid, blocked_here)
                    ledger.partial_reason(
                        rid, f"{blocked_here}/{len(elig)} eligible files not scanned")
                err_here = sum(1 for p in elig if p in run.error_paths)
                if err_here:
                    ledger.partial_reason(
                        rid, f"{err_here} file error(s) in this project")
                skip_here = sum(1 for p in elig if p in run.skipped_paths)
                if skip_here:
                    ledger.partial_reason(
                        rid, f"{skip_here} skipped file(s) in this project")


def note_uncataloged_semgrep_rules(findings, descriptors, diag) -> None:
    """A finding from a USER-SUPPLIED external config whose id is not in the
    shipped catalog: the finding stays, but no descriptor/execution capability
    is fabricated and it is never attributed to a shipped rule — only a
    visible diagnostic."""
    known = {d.rule_id for d in descriptors}
    seen: set[str] = set()
    for f in findings:
        rid = getattr(f, "rule_id", "")
        if rid.startswith("S:") and rid not in known and rid not in seen:
            seen.add(rid)
            note = (f"external semgrep rule {rid} is not in the shipped catalog "
                    "(finding kept; no capability or execution recorded)")
            if diag is not None and note not in diag.notes:
                diag.notes.append(note)

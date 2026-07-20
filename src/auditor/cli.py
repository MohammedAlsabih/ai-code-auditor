from __future__ import annotations

import argparse
import sys
from pathlib import Path

from auditor import __version__
from auditor.errors import AuditorError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditor",
                                description="AI Code Auditor — deterministic scanner for "
                                            "AI-generated code (hallucinated deps + risky patterns)")
    p.add_argument("--version", action="version", version=f"ai-code-auditor {__version__}")
    sub = p.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="scan a GitHub URL or local path")
    scan.add_argument("target")
    scan.add_argument("--output", default="auditor-report")
    scan.add_argument("--offline", action="store_true",
                      help="skip all registry lookups (findings become H003/H007)")
    scan.add_argument("--no-semgrep", action="store_true")
    scan.add_argument("--semgrep-bin", default=None)
    scan.add_argument("--semgrep-config", action="append", default=[],
                      help="extra semgrep config (registry packs are YOUR license responsibility)")
    scan.add_argument("--config", default=None,
                      help="path to a .auditor.toml (default: auto-discover at "
                           "the target root)")
    scan.add_argument("--strict", action="store_true",
                      help="exit non-zero on 'review' verdicts too (incomplete analysis never passes)")
    scan.add_argument("--verbose", "-v", action="store_true")

    srv = sub.add_parser("serve",
                         help="open a report.json in a local web explorer (127.0.0.1 only)")
    srv.add_argument("report", help="path to a report.json produced by 'auditor scan'")
    srv.add_argument("--repo", default=None,
                     help="repository root (optional; reserved for the W2 source view)")
    srv.add_argument("--port", type=int, default=8765)
    # NOTE: deliberately NO --host. W1 binds to loopback only; a public bind is
    # not selectable from the CLI.
    return p


def main(argv: list[str] | None = None) -> int:
    # Legacy Windows consoles (cp1256/cp437...) cannot encode the emoji/Arabic
    # in our output and CRASH the whole scan at the final print. Keep the
    # console's own encoding but degrade unencodable characters to '?' instead
    # of raising (found by the live CP-7 run, invisible under pytest capture).
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except OSError:
                pass
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    if args.command != "scan":
        build_parser().print_help()
        return 0
    try:
        return _scan(args)
    except AuditorError as e:
        print(f"error | خطأ: {e}", file=sys.stderr)
        return 2


# W1 binds to loopback only. This is a module constant (not a CLI flag) so a
# public bind cannot be requested; tests assert serve() passes exactly this.
SERVE_HOST = "127.0.0.1"


# the optional web stack (pip install ".[web]"). A missing member of THIS set
# is a "you didn't install the extra" case; any other missing module is a real
# import bug and must not be masked by the friendly message.
_WEB_DEPS = {"fastapi", "uvicorn", "starlette"}


def _serve(args) -> int:
    """Load the report ONCE, then hand a read-only app to uvicorn on
    127.0.0.1. A bad report prints a clear one-line error and exits 2 — the
    server is never started, so the browser never sees a traceback. No scan,
    build, or install of the repository is performed."""
    try:
        import uvicorn

        from auditor.web.app import ReportError, create_app
    except ModuleNotFoundError as e:
        # only the optional web extra is handled here — re-raise anything else so
        # a genuine import bug is not swallowed as a missing-dependency message.
        if (e.name or "").split(".")[0] in _WEB_DEPS:
            print('Web explorer dependencies are not installed.\n'
                  'Install with: pip install "ai-code-auditor[web]"', file=sys.stderr)
            return 2
        raise

    repo = Path(args.repo) if args.repo else None
    try:
        app = create_app(Path(args.report), repo_root=repo)
    except ReportError as e:
        print(f"error | خطأ: {e}", file=sys.stderr)
        return 2

    url = f"http://{SERVE_HOST}:{args.port}"
    print(f"AI Code Auditor Report Explorer | {url}  (report: {args.report})")
    uvicorn.run(app, host=SERVE_HOST, port=args.port, log_level="warning")
    return 0


def _relativize_diag(diag_dict: dict, root) -> dict:
    """Rewrite ONLY the path-valued diagnostics fields for DISPLAY (CP-8b round
    5): manifest_files/manifest_incomplete are whole paths; manifest_errors is
    `<path>: <reason>` (split once on ': '). Everything else — free-text notes,
    rule_errors, URLs — is left untouched (a blanket path regex mangled URLs and
    paths with spaces). In-repo paths become repo-relative; a path OUTSIDE the
    repo is masked to `<outside-repository>/<basename>`. Canonical absolute
    identity is kept in the in-memory ledgers for merge."""
    import re as _re
    prefix = root.resolve().as_posix().rstrip("/") + "/"
    _is_abs = _re.compile(r"^(?:[A-Za-z]:/|/)")

    def _relpath(p: str) -> str:
        p = p.replace("\\", "/")
        if p.startswith(prefix):
            return p[len(prefix):]                 # inside the repo
        if _is_abs.match(p):
            return "<outside-repository>/" + p.rstrip("/").rsplit("/", 1)[-1]
        return p                                   # already relative

    def _relerr(e: str) -> str:
        path, sep, reason = e.partition(": ")      # first ': ' splits path/reason
        return _relpath(path) + sep + reason if sep else _relpath(e)

    out = dict(diag_dict)
    for field in ("manifest_files", "manifest_incomplete"):
        out[field] = [_relpath(p) for p in diag_dict.get(field, [])]
    out["manifest_errors"] = [_relerr(e) for e in diag_dict.get("manifest_errors", [])]
    return out


def _scan(args) -> int:
    from auditor.adapters import default_adapters
    from auditor.core.execution import ExecutionLedger
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import Diagnostics
    from auditor.core.ownership import assign_findings, fs_case_insensitive, norm
    from auditor.core.patterns import dedupe, run_pattern_engine
    from auditor.core.semgrep_runner import (
        find_binary,
        note_uncataloged_semgrep_rules,
        record_semgrep_execution,
        run_semgrep_structured,
    )
    from auditor.core.treesitter import register_adapters
    from auditor.discovery import discover_projects, project_files
    from auditor.fetch import resolve_target
    from auditor.registries.base import CachedRegistry, make_session
    from auditor.registries.cache import Cache
    from auditor.registries.maven import MavenClient
    from auditor.registries.npm import NpmClient
    from auditor.registries.nuget import NuGetClient
    from auditor.registries.pypi import PyPIClient
    from auditor.core.catalog import collect_catalog
    from auditor.report.build import build_report
    from auditor.report.json_out import write_json
    from auditor.report.markdown import write_markdown

    from auditor.config import any_match, is_vendored, load_config

    root, cleanup = resolve_target(args.target)
    try:
        # project configuration (W2-B2.8A): explicit --config or .auditor.toml
        # at the target root; malformed config fails LOUDLY (AuditorError)
        config = load_config(root, args.config)
        adapters = default_adapters()
        for _a in adapters:
            _a.set_repo_root(root)      # npm_roots resolve repo-relatively
            _a.apply_config(config)
        projects = discover_projects(root, adapters)
        limitations: list[str] = []
        if config.loaded_from:
            limitations.append(
                f"project config loaded ({config.loaded_from}): "
                f"{len(config.exclude_paths)} exclude, "
                f"{len(config.dependency_exclude_paths)} dependency-exclude "
                "path pattern(s).")
        registries = None
        if args.offline:
            limitations.append("Offline mode: no registry verification was performed.")
        else:
            session = make_session()
            cache = Cache()
            registries = {c.ecosystem: CachedRegistry(c, cache) for c in (
                PyPIClient(session), NpmClient(session), MavenClient(session),
                NuGetClient(session))}

        register_adapters(adapters)
        global_diag = Diagnostics()

        if args.semgrep_config:
            print("note: extra semgrep configs run under the rule authors' license "
                  "(Semgrep Rules License v1.0 restricts registry packs).")

        # Ownership lives in core/ownership.py (pure + unit-tested): exact
        # full-file map, suffix-gated deepest-root fallback, repo bucket,
        # '..' guard, and FILESYSTEM-probed case normalization.
        sample = None
        if projects:
            sample = next((f for f in projects[0][1].rglob("*") if f.is_file()), None)
        insensitive = fs_case_insensitive(sample)

        results: list[dict] = []
        proj_meta: list[tuple[tuple[str, ...], int]] = []
        prefixes: dict[int, str] = {}
        globs: dict[int, tuple[str, ...]] = {}
        owner: dict[str, int] = {}
        languages_seen: set[str] = set()
        expected_sg_paths: set[str] = set()   # for semgrep completeness reconciliation
        # per-project execution ledgers (B2-A): factual run records, kept in
        # memory only — NOT serialized into report.json in this slice.
        execution_ledgers: list[ExecutionLedger] = []
        project_source_files: list[list] = []   # parallel: for S:* distribution
        for adapter, proot in projects:
            adapter.set_repo_root(root)   # confinement boundary = whole repo (CP-8.2)
            diag = Diagnostics()
            rel_root = proot.relative_to(root).as_posix() or "."   # before engines run
            ledger = ExecutionLedger(language=adapter.name, root=rel_root)
            files = project_files(proot, adapter, projects, diag=diag)
            _pfx = "" if rel_root == "." else rel_root + "/"
            # config exclude_paths: fully out of the scan (repo-relative match)
            if config.exclude_paths:
                files = [sf for sf in files
                         if not any_match(_pfx + sf.rel, config.exclude_paths)]
            expected_sg_paths.update(str(f.path) for f in files)
            declared = adapter.parse_dependencies(proot, diag=diag)
            # dependency-audit OWNERSHIP gate (W2-B2.8A): a file suffix alone
            # never proves registry ownership. When the adapter says the audit
            # does not apply here (e.g. manifestless npm fallback), code rules
            # still run but nothing is sent to the registry — recorded as a
            # not_applicable FACT, never a silent skip.
            dep_reason = adapter.dependency_audit_reason(proot)
            # per-file dependency exclusion: vendored assets (builtin) + config
            dep_files = [sf for sf in files
                         if not is_vendored(_pfx + sf.rel)
                         and not any_match(_pfx + sf.rel,
                                           config.dependency_exclude_paths)]
            if dep_reason is None and not declared and files \
                    and not adapter.detect(proot):
                limitations.append(f"{adapter.name}: source files found but no dependency "
                                   "manifest — every external import is reported as undeclared.")
            adapter.prepare(proot, files)
            fws = adapter.frameworks(proot, declared)
            registry = registries.get(adapter.ecosystem) if registries else None
            if dep_reason is not None:
                from auditor.core.hallucination import DESCRIPTORS as _H_DESCRIPTORS
                ledger.not_applicable(
                    tuple(d.rule_id for d in _H_DESCRIPTORS), dep_reason)
                note = f"{adapter.name} ({rel_root}): {dep_reason}"
                if note not in limitations:
                    limitations.append(note)
                findings = []
            else:
                findings = audit_hallucinations(adapter, proot, dep_files,
                                                declared, registry,
                                                diag=diag, ledger=ledger)
            findings += run_pattern_engine(adapter, proot, files, fws, diag=diag,
                                           ledger=ledger,
                                           complexity_threshold=config.complexity_threshold)
            execution_ledgers.append(ledger)
            project_source_files.append(files)
            idx = len(results)
            prefix = "" if rel_root == "." else rel_root + "/"
            prefixes[idx] = prefix
            globs[idx] = adapter.source_globs
            for sf in files:
                owner[norm(prefix + sf.rel, insensitive)] = idx
            proj_meta.append((tuple() if rel_root == "."
                              else tuple(norm(rel_root, insensitive).split("/")), idx))
            languages_seen.add(adapter.name)
            global_diag.merge(diag)
            results.append({"language": adapter.name, "root": rel_root,
                            "frameworks": fws, "file_count": len(files),
                            "findings": findings})
            if args.verbose:
                print(f"[{adapter.name}] {rel_root}: {len(files)} files, "
                      f"{len(findings)} findings")

        # semgrep runs ONCE over the whole root, reconciled against the source
        # files we expect it to cover (completeness signal)
        sg = None if args.no_semgrep else find_binary(args.semgrep_bin)
        sg_findings: list = []
        sg_run = None
        if args.no_semgrep:
            # user CHOICE, distinct from an engine we could not find
            global_diag.semgrep_status = "disabled by --no-semgrep (builtin rules only)"
        elif sg:
            sg_run = run_semgrep_structured(sg[0], root, args.semgrep_config,
                                            expected_paths=expected_sg_paths)
            sg_findings = sg_run.findings
            global_diag.semgrep_status = f"{sg[1]}: {sg_run.status_text}"
        else:
            global_diag.semgrep_status = "not available (builtin rules only)"
        # B2-C: distribute the ONE invocation's structured evidence onto the
        # per-project ledgers (S:* descriptors from the shipped YAML — the
        # same single source the catalog uses). Never touches Diagnostics
        # rule counters; in-memory only, not serialized.
        try:
            from auditor.core.semgrep_rules_meta import shipped_semgrep_descriptors
            sg_descriptors = shipped_semgrep_descriptors()
        except Exception as e:  # noqa: BLE001 — a broken shipped YAML already
            # fails the catalog loudly; execution recording must not crash scan
            sg_descriptors = []
            global_diag.notes.append(
                f"semgrep execution recording skipped: {e.__class__.__name__}")
        record_semgrep_execution(
            zip(execution_ledgers, project_source_files), sg_descriptors,
            run=sg_run, disabled=args.no_semgrep,
            binary_missing=(not args.no_semgrep and not sg))
        note_uncataloged_semgrep_rules(sg_findings, sg_descriptors, global_diag)

        assigned, repo_bucket, dropped = assign_findings(
            sg_findings, owner, proj_meta, prefixes, globs, insensitive)
        for path in dropped:
            global_diag.notes.append(f"semgrep path escaped scan root, dropped: {path}")
        for idx, extra in assigned.items():
            results[idx]["findings"] += extra
        for r in results:
            r["findings"] = dedupe(r["findings"])
        if repo_bucket:
            results.append({"language": "repository", "root": ".", "frameworks": [],
                            "file_count": 0, "findings": dedupe(repo_bucket)})

        if "java" in languages_seen:
            limitations.append("Maven Central exposes no download counts; Java namespace→"
                               "artifact mapping uses a curated prefix map — unmapped imports "
                               "are reported as H007, never as RED.")
        if "dotnet" in languages_seen:
            limitations.append(".NET usings under System.*/Microsoft.* are treated as BCL "
                               "(not registry-checked).")
        if any(f.rule_id == "H004" for r in results for f in r["findings"]):
            limitations.append("Some registry lookups failed; affected packages are "
                               "marked H004 (unverified).")
        limitations.append(f"semgrep layer: {global_diag.semgrep_status}.")
        limitations.append("Undetectable private-source channels (env vars, ~/.m2/settings.xml "
                           "mirrors, CI config) cannot be ruled out for not-found packages.")
        nuget_reg = registries.get("nuget") if registries else None
        if nuget_reg is not None and getattr(nuget_reg.inner, "degraded", False):
            limitations.append("NuGet service index unreachable — hardcoded endpoint "
                               "fallbacks were used (degraded mode).")
        limitations.append("Private registries are NEVER contacted; packages behind them "
                           "are classified unverified (H010), and the public registry is "
                           "not treated as the source of truth for them.")

        from dataclasses import asdict as dc_asdict

        from auditor.core.scoring import analysis_confidence
        total_files_read = sum(r["file_count"] for r in results)
        confidence = analysis_confidence(global_diag, offline=args.offline,
                                         files_read=total_files_read)
        engines = {
            "ast": "tree-sitter 0.26 (python/java/csharp/typescript/tsx)",
            "registry": "offline" if args.offline else "online (pypi/npm/maven/nuget, cached)",
            "complexity": "lizard",
            "semgrep": global_diag.semgrep_status,
        }
        # canonical absolute paths are kept internally for merge identity, but
        # the REPORT shows repository-relative paths (privacy + reproducibility,
        # CP-8b round 3)
        diag_dict = _relativize_diag(dc_asdict(global_diag), root)
        # catalog collected ONCE; execution serialized AFTER every engine has
        # recorded (builtin file rules, H, project passes, semgrep) — derived
        # from the ledgers only, never recomputed from diagnostics/findings.
        # Scoring/confidence/verdict above are already computed and unaffected.
        from auditor.core.execution import execution_manifest
        catalog = collect_catalog(adapters.values()
                                  if isinstance(adapters, dict) else adapters)
        execution = execution_manifest(execution_ledgers,
                                       {d["rule_id"] for d in catalog})
        # the report's `target` never echoes an ABSOLUTE machine path (privacy,
        # CP-8b round 3 — surfaced by Linux CI where as_posix == str): URLs and
        # relative paths pass through, a local absolute path shows as
        # <local>/<basename> only.
        display_target = args.target
        if "://" not in display_target and not display_target.startswith("git@") \
                and Path(display_target).is_absolute():
            display_target = f"<local>/{Path(display_target).name}"
        data = build_report(display_target, results, engines, limitations,
                            diagnostics=diag_dict, confidence=confidence,
                            catalog=catalog, execution=execution)
        out_dir = Path(args.output)
        write_json(data, out_dir / "report.json")
        write_markdown(data, out_dir / "report.md")

        if not projects:
            print("no supported languages detected | لم تُكتشف لغات مدعومة "
                  "(python/typescript/java/dotnet)")
        s = data["summary"]
        overall = s["overall_score"]
        low = s["lowest_language"]
        low_txt = f", lowest {low['language']}={low['score']}" if low else ""
        print(f"scan complete | اكتمل الفحص: verdict={s['verdict'].upper()}, "
              f"health {overall if overall is not None else 'N/A'}{low_txt}, "
              f"errors={s['counts']['red']}, confidence {confidence}/100 "
              f"— reports in {out_dir / 'report.md'} + report.json")
        if s["verdict"] == "block":
            return 1
        if s["verdict"] == "review" and args.strict:
            return 1   # incomplete/yellow analysis must not read as a pass in strict mode
        return 0
    finally:
        cleanup()

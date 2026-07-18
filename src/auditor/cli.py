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
    scan.add_argument("--strict", action="store_true",
                      help="exit non-zero on 'review' verdicts too (incomplete analysis never passes)")
    scan.add_argument("--verbose", "-v", action="store_true")
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
    if args.command != "scan":
        build_parser().print_help()
        return 0
    try:
        return _scan(args)
    except AuditorError as e:
        print(f"error | خطأ: {e}", file=sys.stderr)
        return 2


def _relativize_diag(diag_dict: dict, root) -> dict:
    """Rewrite diagnostics paths for DISPLAY (CP-8b round 3/4): in-repo paths
    become repo-relative; a path OUTSIDE the repository is reduced to
    `<outside-repository>/<basename>` so no machine path leaks. The in-memory
    ledgers keep their canonical absolute identity for merge."""
    import re as _re
    prefix = root.resolve().as_posix().rstrip("/") + "/"
    # an absolute machine path token: drive-letter (C:/...) or posix root (/...)
    _abs = _re.compile(r"(?:[A-Za-z]:/|/)[^\s:'\"]*")

    def _mask(m):
        p = m.group(0)
        if p.startswith(prefix):
            return p[len(prefix):]                 # inside the repo => relative
        return "<outside-repository>/" + p.rstrip("/").rsplit("/", 1)[-1]

    def rel(v):
        if isinstance(v, str):
            return _abs.sub(_mask, v.replace("\\", "/"))
        if isinstance(v, list):
            return [rel(x) for x in v]
        return v
    return {k: rel(v) for k, v in diag_dict.items()}


def _scan(args) -> int:
    from auditor.adapters import default_adapters
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import Diagnostics
    from auditor.core.ownership import assign_findings, fs_case_insensitive, norm
    from auditor.core.patterns import dedupe, run_pattern_engine
    from auditor.core.semgrep_runner import find_binary, run_semgrep
    from auditor.core.treesitter import register_adapters
    from auditor.discovery import discover_projects, project_files
    from auditor.fetch import resolve_target
    from auditor.registries.base import CachedRegistry, make_session
    from auditor.registries.cache import Cache
    from auditor.registries.maven import MavenClient
    from auditor.registries.npm import NpmClient
    from auditor.registries.nuget import NuGetClient
    from auditor.registries.pypi import PyPIClient
    from auditor.report.build import build_report
    from auditor.report.json_out import write_json
    from auditor.report.markdown import write_markdown

    root, cleanup = resolve_target(args.target)
    try:
        adapters = default_adapters()
        projects = discover_projects(root, adapters)
        limitations: list[str] = []
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
        for adapter, proot in projects:
            adapter.set_repo_root(root)   # confinement boundary = whole repo (CP-8.2)
            diag = Diagnostics()
            files = project_files(proot, adapter, projects, diag=diag)
            expected_sg_paths.update(str(f.path) for f in files)
            declared = adapter.parse_dependencies(proot, diag=diag)
            if not declared and files and not adapter.detect(proot):
                limitations.append(f"{adapter.name}: source files found but no dependency "
                                   "manifest — every external import is reported as undeclared.")
            adapter.prepare(proot, files)
            fws = adapter.frameworks(proot, declared)
            registry = registries.get(adapter.ecosystem) if registries else None
            findings = audit_hallucinations(adapter, proot, files, declared, registry, diag=diag)
            findings += run_pattern_engine(adapter, proot, files, fws, diag=diag)
            rel_root = proot.relative_to(root).as_posix() or "."
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
        if sg:
            sg_findings, sg_status = run_semgrep(sg[0], root, args.semgrep_config,
                                                 expected_paths=expected_sg_paths)
            global_diag.semgrep_status = f"{sg[1]}: {sg_status}"
        else:
            global_diag.semgrep_status = "not available (builtin rules only)"

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
        data = build_report(args.target, results, engines, limitations,
                            diagnostics=diag_dict, confidence=confidence)
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
              f"🔴={s['counts']['red']}, confidence {confidence}/100 "
              f"— reports in {out_dir / 'report.md'} + report.json")
        if s["verdict"] == "block":
            return 1
        if s["verdict"] == "review" and args.strict:
            return 1   # incomplete/yellow analysis must not read as a pass in strict mode
        return 0
    finally:
        cleanup()

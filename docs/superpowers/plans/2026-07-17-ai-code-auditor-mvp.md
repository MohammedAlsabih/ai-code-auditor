# AI Code Auditor MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A deterministic CLI tool `auditor` that scans a GitHub URL or local path (multi-language monorepos included) for AI-generated-code defects: hallucinated/undeclared dependencies verified against PyPI/npm/Maven Central/NuGet, plus dangerous AI-typical code patterns, producing `report.md` + `report.json` with a documented 0-100 confidence score.

**Architecture:** A language-agnostic core (models, tree-sitter utilities, hallucination engine, pattern engine, scoring, reporting) + one adapter per language (python/typescript/java/dotnet) implementing a fixed interface (`detect` / `parse_dependencies` / `extract_imports` / `language_rules` + matching helpers) + registry clients behind one `RegistryClient` interface with a TTL file cache. Engine 2 pattern rules are built-in tree-sitter/regex rules (always available); semgrep/opengrep is an optional additive layer running only our bundled YAML rules.

**Tech Stack:** Python 3.11+ (dev machine: 3.12.4, Windows 11), tree-sitter 0.26 + per-language grammar wheels, requests, platformdirs, lizard (cyclomatic complexity, all 4 languages), pytest + responses (HTTP mocking). No LLM anywhere.

**Reference:** `RESEARCH.md` at repo root records the 2026-07-17 verified research all decisions below are based on (registry endpoints, tree-sitter 0.26 API, Maven solrsearch freeze, semgrep licensing, lizard). Trust this plan over training knowledge — every endpoint/API shape here was live-verified.

## Global Constraints

- Python `>=3.11` (`requires-python`), src layout, `pyproject.toml`, hatchling backend. Package name `ai-code-auditor`, import package `auditor`, CLI `auditor`.
- Windows is the dev machine: every file read/write in tool code uses explicit `encoding="utf-8"`; YAML/fixture files must be written WITHOUT BOM (BOM breaks semgrep, exit 7); subprocess calls use argument lists, never shell strings.
- ALL XML parsing of repo-controlled files (pom.xml, csproj, packages.config, nuget.config, maven-metadata) goes through `defusedxml.ElementTree` (entity attacks neutralized independently of the host's expat build) with the 2 MB `read_text_capped` bound (measured amplification: 2.7 MB XML → 38 MB peak Python objects, ×14). `import defusedxml.ElementTree as ET` is a drop-in for the `ET.fromstring` calls shown in Tasks 15/16/18; catch `(ET.ParseError, defusedxml.DefusedXmlException)` where plain `ET.ParseError` is written.
- tree-sitter 0.26 API ONLY: `Language(mod.language())`, `Parser(lang)`, `Query(lang, src)`, `QueryCursor(query).captures(node)` → `dict[str, list[Node]]`. `Language.query()` / `Query.captures()` DO NOT EXIST anymore and hard-crash.
- Registry endpoints exactly as verified in RESEARCH.md §3. Maven existence via `repo1.maven.org` maven-metadata.xml ONLY — never search.maven.org (its index is severely stale since ~Q2 2025: proven months-to-a-major behind; unfit for existence/recency checks).
- Every registry HTTP call: `User-Agent: ai-code-auditor/<version> (+https://github.com/local/ai-code-auditor)`, timeout `(5, 15)`, graceful failure → `PackageInfo(error=...)`, never an exception escaping to the CLI.
- Registry cache TTLs: exists=7 days, not-exists=24h; network errors never cached. Cache file: `platformdirs.user_cache_dir("ai-code-auditor")/registry-cache.json`.
- No LLM calls, no telemetry, deterministic output ordering (sort findings by (file, line, rule_id)).
- Graceful degradation is a feature requirement: private/unreachable repo → clear Arabic+English error, exit 2; no supported manifests → empty report + note, exit 0; registry down → BLUE "unverified" findings + limitations entry, scan continues.
- Do not bundle or fetch Semgrep-registry rules (`p/...`) by default: the Semgrep Rules License v1.0 text grants use "only for your own internal business purposes" and withholds distribution/service rights (it contains NO "competing tools" clause — verbatim text in evidence/). Only our own bundled YAML (original work, MIT, provenance header) runs by default; user-supplied `--semgrep-config` values are passed through with a printed note that license compliance for those rules is the user's own responsibility — never described as simply "allowed".
- CORE NEUTRALITY (v2, enforced by test): no module under `src/auditor/core/` may import from `auditor.adapters` or contain language-name string branches; language knowledge reaches core only via `grammars()` / `SyntaxProfile` / `language_rules()` / `project_rules()`.
- NO SILENT FAILURES (v2): every skipped file, manifest parse error, rule exception, partial AST, registry failure and semgrep status is recorded in `Diagnostics` and surfaces in report.json + limitations; `analysis_confidence` is computed from it and reported separately from risk.
- TDD per task: write failing test → run → implement → run → commit. Run tests with `.venv\Scripts\python -m pytest <file> -v` from `<repo>`.
- Commit after every task. ALL commit messages end with the trailer line: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` (shown fully in Task 1, implied in later tasks' commit steps).
- After each PHASE CHECKPOINT block: STOP and present the phase results to the user (in Arabic) before starting the next phase. This is a user requirement, not optional.

## Canonical Rule ID Catalog

Single source of truth — engines, tests, and reports use these exact IDs/severities.

| ID | Sev | Title (report string) |
|---|---|---|
| H001 | red | Declared dependency not found in the public registry (fact; hallucination is the likely cause — name claimable: slopsquatting exposure) |
| H002 | yellow | Undeclared import (package exists in registry) |
| H003 | blue | Dependency not verified (offline mode) |
| H004 | blue | Registry unreachable — dependency unverified |
| H005 | yellow | Brand-new package with near-zero downloads |
| H006 | yellow | Recently published package (< fresh threshold) |
| H007 | yellow | Undeclared import — cannot be mapped to a registry identifier |
| H008 | red | Undeclared import not found in registry (hallucinated import) |
| H009 | red | Package quarantined by registry (PyPI PEP 792) |
| H010 | yellow | Not found in public registry — private/custom source configured or scoped package (unverifiable; dependency-confusion exposure) |
| H012 | blue | Package archived by its owner (PEP 792 status) |
| P001 | yellow | Empty or exception-swallowing catch/except block |
| P002 | red | Hardcoded secret (known token format) |
| P003 | yellow | Suspicious credential assignment |
| P004 | yellow | SQL built via string composition |
| P005 | red | String-composed SQL reaches an execution sink |
| P006 | yellow | Cyclomatic complexity above 10 |
| P007 | blue | AI-style incompleteness comment |
| P008 | blue | stdlib availability mismatch within the project's requires-python range (removed OR not-yet-introduced, backports honored) |
| R001 | red | React hook called conditionally (if/loop/ternary/logical &&‖??/try, or after an early return) |
| R002 | red | React hook called inside a callback argument of another hook |
| R003 | yellow | Hook call in a non-component, non-hook function |
| R004 | yellow | useEffect without dependency array |
| R005 | yellow | useEffect with obviously missing dependencies |
| R006 | yellow | List key uses array index |
| R007 | red | dangerouslySetInnerHTML with non-literal value |
| N001 | red | NEXT_PUBLIC_ variable with secret-like name (exposed to client bundle) |
| N002 | yellow | Non-NEXT_PUBLIC env read in a Client Component (empty at runtime) |
| N003 | red | Client-only API used in a Server Component (missing "use client") |
| N004 | red | Server-only import inside a Client Component |
| N005 | yellow | async Client Component |
| J001 | yellow | String compared with == |
| J002 | yellow | Resource opened without try-with-resources |
| D001 | yellow | async void method outside event handlers |
| D002 | yellow | Blocking on task (.Result / .Wait() / GetAwaiter().GetResult()) |
| D003 | red | Interpolated/concatenated SQL passed to raw-SQL API |
| N006 | red | Client-only API in a module reachable from a Server Component (import-graph pass; supersedes per-file N003 when active) |

Semgrep-layer findings keep `engine="semgrep"` and `rule_id="S:" + check_id` with severity mapped ERROR→red, WARNING→yellow, INFO→blue.

Every `Rule` also carries `precision`: `"exact"` (fact-level checks) or `"heuristic"` (approximate: P004/P005, R001-early-return, R005, J002, D002, N003, plus Java/.NET namespace mapping). The report prints it per finding so heuristics never read as proofs.

## File Structure

```
<repo>\
├── pyproject.toml
├── .gitignore
├── README.md                          (Task 24, Arabic/English)
├── RESEARCH.md                        (already written)
├── examples\                          (Task 24: real-scan report.md/report.json)
├── src\auditor\
│   ├── __init__.py                    __version__
│   ├── errors.py                      AuditorError
│   ├── cli.py                         argparse CLI (minimal in T1, full in T23)
│   ├── fetch.py                       resolve_target: clone URL / local path
│   ├── discovery.py                   discover_projects, project_files
│   ├── core\
│   │   ├── __init__.py
│   │   ├── models.py                  Severity, Finding, DeclaredDep, ImportRef, SourceFile, PackageInfo
│   │   ├── interfaces.py              LanguageAdapter ABC, Rule ABC
│   │   ├── treesitter.py              get_language/get_parser/parse_source/captures helpers
│   │   ├── walk.py                    collect_source_files + IGNORE_DIRS
│   │   ├── hallucination.py           Engine 1 (language-agnostic)
│   │   ├── patterns.py                Engine 2 orchestrator + dedupe
│   │   ├── rules_common.py            P001-P005, P007 (cross-language)
│   │   ├── complexity.py              P006 via lizard
│   │   ├── scoring.py                 health score + confidence + verdict
│   │   ├── ownership.py               semgrep-finding → project assignment (pure)
│   │   └── semgrep_runner.py          optional opengrep/semgrep layer (status-typed)
│   ├── adapters\
│   │   ├── __init__.py                default_adapters()
│   │   ├── python\{__init__.py, adapter.py, aliases.py}
│   │   ├── typescript\{__init__.py, adapter.py, builtins.py, react_rules.py, next_rules.py, next_graph.py}
│   │   ├── java\{__init__.py, adapter.py, known_artifacts.py, rules.py}
│   │   └── dotnet\{__init__.py, adapter.py, rules.py}
│   ├── registries\
│   │   ├── __init__.py
│   │   ├── base.py                    RegistryClient ABC, CachedRegistry, make_session, date utils
│   │   ├── cache.py                   TTL JSON cache
│   │   ├── pypi.py  npm.py  maven.py  nuget.py
│   ├── report\
│   │   ├── __init__.py
│   │   ├── build.py                   build_report(...) -> dict (single source for both formats)
│   │   ├── json_out.py
│   │   └── markdown.py
│   └── semgrep_rules\auditor-extra.yml
└── tests\
    ├── conftest.py                    fixture paths + FakeRegistry
    ├── fixtures\{python_repo, ts_repo, java_repo, dotnet_repo, monorepo}\
    └── test_*.py                      (one module per task, named in tasks)
```

## Phase Map (user's required phases → tasks)

| User phase | Tasks | Checkpoint |
|---|---|---|
| 1. RESEARCH.md | done (pre-plan) | presented with this plan |
| 2. Core + adapter interface + clone/discovery | T1–T4 | CP-2 |
| 3. Python adapter complete + tests (reference model) | T5–T9 | CP-3 |
| 4. TypeScript adapter + React/Next.js rules | T10–T14 | CP-4 |
| 5. Java + .NET adapters | T15–T18 | CP-5 |
| 6. Engine 2 (patterns + semgrep layer) | T19–T21 | CP-6 |
| 7. Reports (md+json) + full CLI | T22–T23 | CP-7 |
| 8. Real-repo trial + README + examples | T24 | CP-8 (final) |

## Revision Log — v2 (2026-07-17 adversarial review)

Every change below was forced by refutable evidence; full evidence tables live in `2026-07-17-adversarial-review.md`. Task bodies below are already edited — this log is the "what changed and why" index, not a second source of code.

| # | Change | Tasks | Why (evidence) |
|---|---|---|---|
| 1 | Core made language-neutral: adapters now provide `grammars()`, `syntax() -> SyntaxProfile`, `project_rules()`; treesitter becomes a registry; rules_common becomes profile-driven; `core/patterns.py` no longer imports adapters | T2, T3, T7, T11, T14, T16, T18, T19, T21 | Architecture mandate; 1 core→adapter import + 4 language-branch sites found in v1 |
| 2 | Semgrep findings ownership: normalized full-path map to deepest project (never startswith/endswith) | T21, T23 | `'api-old/…'.startswith('api')` and `endswith('/src/index.ts')` collisions both proven |
| 3 | Cross-engine dedupe removed (kept only exact same-rule duplicates) | T21 | Different finding on same line was being silently dropped |
| 4 | `Diagnostics` channel: manifest errors, skipped files, parse errors, rule errors, semgrep status — all surface in report.json + limitations; nothing fails silently | T2, T3, T21, T22, T23 | Review axis 7: every silent `except: continue` hid real failures |
| 5 | Score split: `risk_score` (red/yellow only — BLUE excluded) + `analysis_confidence` (from diagnostics); headline always shows lowest language + red count | T22, T23 | Weighted average provably hid a score-0 project (99/100 scenario); offline BLUEs wrongly lowered "risk" |
| 6 | H001 reworded fact-first; new **H010** (yellow: not found publicly BUT private registry configured / scoped npm — unverifiable, dependency-confusion exposure); new **H012** (blue: package archived by owner, PEP 792) | T2, T5, T8, T11, T16, T18 | PyPI 404 can mean quarantined-then-removed (aiocpa); npm private scopes 404 anonymously; archived status live-verified |
| 7 | npm alias support: `DeclaredDep.registry_name` (`"foo": "npm:bar@^1"` → check `bar`); `#x` import specifiers treated internal | T2, T11 | Official npm/nodejs docs |
| 8 | NODE_BUILTINS: removed bare `test`, `sea`, `sqlite` (node:-scheme-only on ALL versions; npm namesakes exist → masked registry checks) | T11 | node 24 empirical + nodejs.org docs |
| 9 | Python stdlib: union with static REMOVED_STDLIB table (PEP 594/632 + imp/lib2to3); new **P008** (blue) "imports stdlib module removed within target requires-python range" — emitted only when requires-python is parseable | T7 | distutils absent from 3.12 yet EXISTS on PyPI (200) → false H002; telnetlib 404 on PyPI → false RED on 3.13 scanners |
| 10 | javax blanket rule replaced with the 21 verified JDK-21 javax prefixes (+ explicit externals javax.xml.bind/ws/soap); longest-prefix matching | T16 | 18 external javax families verified on repo1 — whole-namespace blind spot |
| 11 | Java map fixed: + `org.junit`→junit:junit (was false-H007 even when declared), + httpclient5, + caffeine (`ben-manes` hyphen), kotlin key fixed to `kotlin`, jackson-core/annotations and spring-context/web refined | T16 | Ground truth 33 imports: 25/33 before, JUnit4 fallthrough confirmed in code |
| 12 | .NET: PACKAGE_DELIVERED_SYSTEM exemptions (CommandLine, Data.SqlClient, Drawing, Management, Data.Entity) always; + Text.Json/Collections.Immutable when TargetFramework includes net4x/netstandard (plural overrides singular); NuGet alias map (`nunit.framework`→NUnit) | T18 | learn.microsoft.com per-TFM matrix; NUnit heuristic resolved to relic package 2.63.0 |
| 13 | Maven `created`: only when versions ≤ 10 AND lastUpdated fresh (versions list is VERSION-sorted, not publish-sorted — proven with log4j backports); never trust `<latest>` for stable | T15 | Last-Modified evidence on 3 artifacts |
| 14 | NuGet registration base resolved from `v3/index.json` per client (docs: "must be dynamically fetched"), hardcoded URL only as fallback | T17 | Official service-index mandate + semver1-hive 404 trap |
| 15 | React rules: R001 adds `&&`/`\|\|`/`??` + early-return sibling heuristic; R003 judges the INNERMOST enclosing function (closes event-handler/map/promise callback FN class); R005 excludes declarators inside the effect callback | T12, T13 | 18-file corpus vs eslint-plugin-react-hooks 7.1.1: FP=3/FN=3 root-caused; zero grammar mismatches |
| 16 | Documented intentional divergences: hook-in-try/catch kept (react.dev forbids; ESLint silent) and R004 kept (spec-mandated; exhaustive-deps ignores by design) | T12, T13 | Corpus evidence + react.dev citation |
| 17 | **N006 APPROVED & IMPLEMENTED (round 4)**: dual-state import-graph pass (`next_graph.py`) — convention-based entries, `(file, state)` visited with server-path violations standing, bidirectional inherited context (N002/N004/N005 in inherited client), type-only edges excluded, cycle/orphan handling; supersedes per-file N003 when active | T14 | nextdemo: per-file analysis blind to a guaranteed Next 16 build error; design hardened by rounds 3–4 |
| 18 | Fetch hardening: clone timeout 300 s, `GIT_LFS_SKIP_SMUDGE=1`, `-c core.symlinks=false`; walker skips symlinks; manifest reads capped at 2 MB (`read_text_capped`) | T3, T4, T6 | Review axis 9; expat 2.6.2 BLAP limits are build-specific amplification guards only (xml_stress.py) |
| 19 | Pipfile `[packages]`/`[dev-packages]` parsed (was detected-but-ignored → undeclared-import FP storm); tsconfig `extends` followed one local level | T6, T11 | Review axis 11 |
| 20 | Every Rule carries `precision: "exact" | "heuristic"`, shown in reports (SQL, R005, D002, J002, early-return, namespace mapping = heuristic) | T2, T19, T22 | Review axis 7: syntactic heuristics must not read as proofs |
| 21 | Checkpoint gates: each CP now lists acceptance criteria, one negative demo, blockers, and deferred decisions | all CP blocks | Review axis 12 |
| 22 | **(round 2)** R003 wrapper exemption (memo/forwardRef/React.memo) + early-return walk stops at function boundaries | T12 | Empirical: 3 FPs without the exemption, 7/7 with; if-wrapped callback-return FP proven and fixed (4/4) |
| 23 | **(round 2)** Maven created = min(Last-Modified over ALL POMs) for young artifacts; "severely stale", not "frozen"; Last-Modified documented as heuristic | T15 | ≤10-versions guard shrinks the versions[0] error but does not remove it |
| 24 | **(round 2)** NuGet resolves flat/registration/search ALL from the service index, visible `degraded` fallback; PyPI tolerates `status`/`state`; H001 phrased as scan-time fact; private registries never contacted; credential redaction in report snippets | T17, T5, T8, T22, T23 | Second-round axes 5–7 |
| 25 | **(round 2)** stdlib availability intervals: ADDED_STDLIB + backport allowlists both directions; P008 broadened | T7 | tomllib-on-3.8 direction was uncovered |
| 26 | **(round 2)** defusedxml + 2MB cap for all repo XML (entity attacks neutralized independently of host expat; measured ×14 memory amplification); semgrep gets `--metrics=off` (verified accepted); auditor-extra.yml provenance header; ownership components casefolded + repository-level bucket + `..` guard; npm self-reference internal | T1 constraints, T11, T21, T22, T23 | Second-round axes 2/4/5/8 |
| 27 | **(round 2)** corpus metrics corrected (accuracy 66.7%; P=R=F1 72.7%) + divergence classification (4 implementation defects fixed / 2 intentional spec divergences / reference-tool gap); corpus re-run added to CP-4 gate | RESEARCH, CP-4 | Metric-presentation error was mine, caught by review |

---

## PHASE 2 — Core, interfaces, fetch & discovery

### Task 1: Project scaffold, git init, packaging, smoke CLI

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `src\auditor\__init__.py`, `src\auditor\errors.py`, `src\auditor\cli.py`, `tests\test_cli_version.py`

**Interfaces:**
- Produces: `auditor.__version__: str`, `auditor.errors.AuditorError(Exception)`, `auditor.cli.main(argv: list[str] | None) -> int`, console script `auditor`.

- [ ] **Step 1: git init + venv**

```powershell
git init -b main
python -m venv .venv
```

- [ ] **Step 2: Write packaging + skeleton files**

`pyproject.toml`:
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "ai-code-auditor"
version = "0.1.0"
description = "Deterministic auditor for AI-generated code: hallucinated dependencies and risky patterns across Python, Java, .NET and TypeScript/React/Next.js"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = [
    "tree-sitter>=0.26,<0.27",
    "tree-sitter-python>=0.25,<0.26",
    "tree-sitter-java>=0.23.5,<0.24",
    "tree-sitter-c-sharp>=0.23.5,<0.24",
    "tree-sitter-typescript>=0.23.2,<0.24",
    "requests>=2.32",
    "platformdirs>=4.0",
    "lizard>=1.23",
    "defusedxml>=0.7",
    "packaging>=24.0",
]

[project.scripts]
auditor = "auditor.cli:main"

[project.optional-dependencies]
dev = ["pytest>=8.0", "responses>=0.25"]

[tool.hatch.build.targets.wheel]
packages = ["src/auditor"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

`.gitignore`:
```
.venv/
__pycache__/
*.egg-info/
dist/
build/
.pytest_cache/
auditor-report/
.cache/
```

`src\auditor\__init__.py`:
```python
__version__ = "0.1.0"
```

`src\auditor\errors.py`:
```python
class AuditorError(Exception):
    """Fatal, user-facing error. CLI prints str(e) and exits 2."""
```

`src\auditor\cli.py` (minimal; replaced by the real CLI in Task 23):
```python
import argparse

from auditor import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditor", description="AI Code Auditor")
    p.add_argument("--version", action="version", version=f"ai-code-auditor {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0
```

Create empty package dirs now so later tasks only add files: `src\auditor\core\__init__.py`, `src\auditor\adapters\__init__.py`, `src\auditor\registries\__init__.py`, `src\auditor\report\__init__.py` (each an empty file).

- [ ] **Step 3: Write the failing test**

`tests\test_cli_version.py`:
```python
import pytest

from auditor.cli import main


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "ai-code-auditor 0.1.0" in capsys.readouterr().out
```

- [ ] **Step 4: Install editable + run test**

```powershell
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest tests\test_cli_version.py -v
```
Expected: PASS (install pulls tree-sitter wheels; all have Windows wheels per RESEARCH.md §2 — no compiler needed).

- [ ] **Step 5: Commit**

```powershell
git add -A
git commit -m "chore: scaffold ai-code-auditor package (src layout, pyproject, smoke CLI)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 2: Core models + adapter/rule interfaces

**Files:**
- Create: `src\auditor\core\models.py`, `src\auditor\core\interfaces.py`
- Test: `tests\test_models.py`

**Interfaces (produced — the whole tool depends on these exact names):**
- `Severity(str, Enum)`: `RED="red"`, `YELLOW="yellow"`, `BLUE="blue"`
- `Finding(rule_id, severity, title, file, line, snippet="", detail="", language="", engine="auditor")` frozen dataclass
- `DeclaredDep(name, ecosystem, source_file, line=0, raw="", skip_registry=False)` frozen
- `ImportRef(module, file, line, top_level="")` frozen
- `SourceFile(path: Path, rel: str, language: str, text: bytes, tree=None)` mutable
- `PackageInfo(exists, created=None, latest=None, downloads=None, downloads_period="weekly", quarantined=False, error=None)`
- `LanguageAdapter` ABC: attrs `name`, `ecosystem`, `source_globs`; abstract `detect(root)`, `parse_dependencies(root)`, `extract_imports(files)`, `match_declared(imp, declared)`, `registry_candidates(imp)`, `is_internal(imp)`; concrete `prepare(root, files)` (no-op default), `frameworks(root, declared)` → `[]`, `language_rules()` → `[]`, `file_language(path)` → `self.name`
- `Rule` ABC: attrs `id`, `severity`, `title`, `frameworks: tuple[str, ...] = ()`; abstract `check(sf: SourceFile) -> list[Finding]`

- [ ] **Step 1: Write the failing test**

`tests\test_models.py`:
```python
from dataclasses import asdict
from pathlib import Path

from auditor.core.models import (DeclaredDep, Finding, ImportRef, PackageInfo,
                                 Severity, SourceFile)


def test_severity_is_json_friendly_string():
    assert Severity.RED.value == "red"
    assert isinstance(Severity.YELLOW, str)


def test_finding_roundtrips_to_dict():
    f = Finding(rule_id="H001", severity=Severity.RED, title="t", file="a.py", line=3)
    d = asdict(f)
    assert d["severity"] == "red" and d["engine"] == "auditor" and d["snippet"] == ""


def test_packageinfo_defaults():
    p = PackageInfo(exists=True)
    assert p.downloads is None and p.downloads_period == "weekly" and not p.quarantined


def test_sourcefile_holds_tree_slot():
    sf = SourceFile(path=Path("x.py"), rel="x.py", language="python", text=b"")
    assert sf.tree is None


def test_declared_and_import_defaults():
    dep = DeclaredDep(name="requests", ecosystem="pypi", source_file="requirements.txt")
    imp = ImportRef(module="yaml", file="a.py", line=1)
    assert not dep.skip_registry and imp.top_level == ""
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv\Scripts\python -m pytest tests\test_models.py -v` — Expected: FAIL `ModuleNotFoundError: auditor.core.models`.

- [ ] **Step 3: Implement**

`src\auditor\core\models.py`:
```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    RED = "red"
    YELLOW = "yellow"
    BLUE = "blue"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    file: str            # repo-relative posix path ("src/app.py")
    line: int            # 1-based; 0 = project-level finding
    snippet: str = ""
    detail: str = ""
    language: str = ""
    engine: str = "auditor"
    precision: str = "exact"     # "exact" | "heuristic" — serialized into reports


@dataclass(frozen=True)
class DeclaredDep:
    name: str            # import-matching identifier: pypi/npm/nuget name, or "group:artifact"
    ecosystem: str       # "pypi" | "npm" | "maven" | "nuget"
    source_file: str
    line: int = 0
    raw: str = ""
    skip_registry: bool = False   # workspace:/file:/git+/unresolved-property deps
    registry_name: str = ""       # npm alias "foo": "npm:bar@^1" => name=foo, registry_name=bar

    @property
    def lookup_name(self) -> str:
        return self.registry_name or self.name


@dataclass(frozen=True)
class ImportRef:
    module: str          # as written: "yaml", "com.foo.bar.Baz", "@scope/pkg/sub"
    file: str
    line: int
    top_level: str = ""  # lookup root: "yaml", "com.foo.bar", "@scope/pkg"


@dataclass
class SourceFile:
    path: Path
    rel: str             # posix, relative to project root
    language: str        # "python" | "java" | "csharp" | "typescript" | "tsx"
    text: bytes
    tree: object | None = None   # tree_sitter.Tree, filled lazily


@dataclass
class PackageInfo:
    exists: bool
    created: str | None = None          # ISO-8601 of first publish
    latest: str | None = None           # ISO-8601 of latest publish
    downloads: int | None = None
    downloads_period: str = "weekly"    # "weekly" | "total"
    quarantined: bool = False           # PEP 792 status == "quarantined"
    archived: bool = False              # PEP 792 status == "archived"
    error: str | None = None            # network failure => existence unknown


@dataclass
class Diagnostics:
    """Per-project analysis-completeness ledger. Everything here surfaces in
    report.json (`diagnostics`) and the limitations section — no silent failures."""
    manifest_errors: list[str] = field(default_factory=list)   # "pom.xml: ParseError ..." (unique per file)
    manifest_files: list[str] = field(default_factory=list)    # UNIQUE manifest paths read (denominator)
    skipped_files: list[str] = field(default_factory=list)     # "big.py: exceeds 1.5MB"
    parse_error_files: list[str] = field(default_factory=list)
    rule_errors: list[str] = field(default_factory=list)       # "R005 on x.tsx: KeyError"
    rule_attempted: int = 0                                    # rule.check invocations
    rule_failures: int = 0                                     # invocations that raised
    registry_attempted: int = 0                                # unique lookups issued
    registry_failures: int = 0                                 # lookups ending in H004
    semgrep_status: str = "not attempted"
    notes: list[str] = field(default_factory=list)

    def merge(self, other: "Diagnostics") -> None:
        self.manifest_errors += [e for e in other.manifest_errors
                                 if e not in self.manifest_errors]
        self.manifest_files += [f for f in other.manifest_files
                                if f not in self.manifest_files]
        self.skipped_files += other.skipped_files
        self.parse_error_files += other.parse_error_files
        self.rule_errors += other.rule_errors
        self.rule_attempted += other.rule_attempted
        self.rule_failures += other.rule_failures
        self.registry_attempted += other.registry_attempted
        self.registry_failures += other.registry_failures
        self.notes += other.notes
```
(`field` comes from `dataclasses` — extend the import line accordingly.)

`src\auditor\core\interfaces.py`:
```python
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from auditor.core.models import DeclaredDep, Finding, ImportRef, Severity, SourceFile


class Rule(ABC):
    id: str
    severity: Severity
    title: str
    frameworks: tuple[str, ...] = ()   # () = applies regardless of framework
    precision: str = "exact"           # "exact" | "heuristic" — printed in reports

    @abstractmethod
    def check(self, sf: SourceFile) -> list[Finding]: ...


@dataclass(frozen=True)
class SyntaxProfile:
    """Language-specific syntax knowledge, supplied BY the adapter TO core rules.
    Core never branches on language names — it consumes this profile."""
    catch_query: str = ""                       # e.g. "(catch_clause) @c" / "(except_clause) @c"
    catch_body_types: tuple[str, ...] = ("block", "statement_block")
    comment_types: tuple[str, ...] = ("comment", "line_comment", "block_comment")
    # a statement that swallows silently even though the body is non-empty (python: pass/...)
    is_swallow_stmt: Callable[[object], bool] = staticmethod(lambda node: False)
    sql_concat_query: str = ""                  # binary/concat node query, "" = skip
    sql_interp_query: str = ""                  # interpolated/template string query, "" = skip
    sql_dynamic_types: tuple[str, ...] = ()     # node types proving dynamic content
    sql_sink_call_types: tuple[str, ...] = (
        "call", "call_expression", "invocation_expression",
        "method_invocation", "object_creation_expression")


class LanguageAdapter(ABC):
    name: str                          # "python" | "typescript" | "java" | "dotnet"
    ecosystem: str                     # "pypi" | "npm" | "maven" | "nuget"
    source_globs: tuple[str, ...]      # file suffixes, e.g. (".py",)

    _diag = None   # set by parse_dependencies(diag=...); manifest helpers report into it

    @abstractmethod
    def detect(self, root: Path) -> bool: ...

    @abstractmethod
    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        """Adapters MUST: set `self._diag = diag` first, read every manifest via
        `self._read(path)` (capped + unreadable-safe), and report parse failures
        via `self._manifest_error(path, err)` — a corrupt manifest yields [] PLUS
        a diagnostics entry, never a silent []."""

    def _read(self, path: Path) -> str:
        from auditor.core.walk import read_text_capped
        if self._diag is not None:
            key = str(path)
            if key not in self._diag.manifest_files:   # UNIQUE files, not read ops
                self._diag.manifest_files.append(key)
        return read_text_capped(path, self._diag)

    def _manifest_error(self, path: Path, err: Exception) -> None:
        if self._diag is not None:
            # FULL path, not path.name: two broken pyproject.toml in different
            # monorepo roots must be TWO errors over TWO files (=> manifest
            # coverage 0), not collapsed to one by name (fifth-round)
            msg = f"{path.as_posix()}: {err.__class__.__name__}"
            if msg not in self._diag.manifest_errors:   # one entry per broken file
                self._diag.manifest_errors.append(msg)

    @abstractmethod
    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]: ...

    @abstractmethod
    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None: ...

    @abstractmethod
    def registry_candidates(self, imp: ImportRef) -> list[str]: ...

    @abstractmethod
    def is_internal(self, imp: ImportRef) -> bool:
        """True for stdlib/builtin/local-to-repo imports. Uses state built in prepare()."""

    @abstractmethod
    def grammars(self) -> dict[str, object]:
        """language-name -> grammar pointer (wheel .language() PyCapsule).
        The adapter OWNS its grammar imports; core/treesitter just registers them."""

    @abstractmethod
    def syntax(self) -> SyntaxProfile:
        """Syntax knowledge consumed by core common rules."""

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        """Build per-project state (local modules, aliases, own namespaces)."""

    def frameworks(self, root: Path, declared: list[DeclaredDep]) -> list[str]:
        return []

    def language_rules(self) -> list[Rule]:
        return []

    def project_rules(self, root: Path, frameworks: list[str]) -> list[Finding]:
        """Project-level checks that need the root, not a single source file
        (e.g. .env scanning). Core calls this; core never imports adapter modules."""
        return []

    def private_registry_reason(self, root: Path) -> str | None:
        """Non-None when the project configures a custom/private package source
        (=> missing packages become H010, not H001/H008)."""
        return None

    def ensure_grammars(self) -> None:
        """Idempotent: registers this adapter's grammars with core/treesitter.
        Adapters call it at the top of prepare()/extract_imports() so direct
        adapter usage (tests, library callers) never hits an unregistered grammar."""
        from auditor.core import treesitter
        treesitter.register_adapters([self])

    def file_language(self, path: Path) -> str:
        return self.name

    # "exact" when import names ARE registry identifiers (python via canonical
    # names, npm literally); "heuristic" when curated prefix/namespace maps are
    # involved (java, dotnet) — stamped onto H002/H007/H008/H010 findings.
    mapping_precision: str = "exact"
```
(`JavaAdapter` and `DotnetAdapter` set `mapping_precision = "heuristic"` as a class attribute in their tasks. Fourth-round verification: the precision plumbing is now IN the code blocks themselves — every `_finding` helper (react/java/dotnet) passes `precision=rule.precision`, `_mk_finding` carries a `precision` parameter forwarded by `SqlStringBuild`, and `J002`/`D002`/`D003`/`N003` declare `precision = "heuristic"` explicitly. Regression tests below prove heuristic findings never default back to "exact".)

- [ ] **Step 4: Run test — PASS.** `.venv\Scripts\python -m pytest tests\test_models.py -v`

- [ ] **Step 5: Commit** — `git add -A ; git commit -m "feat(core): models and adapter/rule interfaces"` (+trailer)

### Task 3: tree-sitter utilities + source-file walker

**Files:**
- Create: `src\auditor\core\treesitter.py`, `src\auditor\core\walk.py`, `tests\conftest.py`
- Test: `tests\test_treesitter_env.py`, `tests\test_walk.py`

`tests\conftest.py` (created HERE so every later test file can parse without
per-file registration; Task 8 appends FakeRegistry to this same file):
```python
import pytest

import tree_sitter_c_sharp
import tree_sitter_java
import tree_sitter_python
import tree_sitter_typescript

from auditor.core import treesitter as _ts

_ts.register_language("python", tree_sitter_python.language())
_ts.register_language("java", tree_sitter_java.language())
_ts.register_language("csharp", tree_sitter_c_sharp.language())
_ts.register_language("typescript", tree_sitter_typescript.language_typescript())
_ts.register_language("tsx", tree_sitter_typescript.language_tsx())
```

**Interfaces:**
- Consumes: `SourceFile` (T2)
- Produces: `treesitter.get_language(name)`, `get_parser(name)`, `parse_source(sf) -> None` (sets `sf.tree`), `captures(lang_name, node, query_src) -> dict[str, list[Node]]`, `node_text(node) -> str`, `line_of(node) -> int`; `walk.IGNORE_DIRS: frozenset[str]`, `walk.collect_source_files(root: Path, adapter, exclude_roots: tuple[Path, ...] = (), diag=None) -> list[SourceFile]` (skips/unreadables recorded into `diag`), `walk.read_text_capped(path, diag=None)`. Valid language names: `python`, `java`, `csharp`, `typescript`, `tsx`.

- [ ] **Step 1: Write the failing tests**

`tests\test_treesitter_env.py` (registers grammars straight from the wheels — this test gates the environment without depending on adapters, which don't exist yet):
```python
from pathlib import Path

import tree_sitter_c_sharp
import tree_sitter_java
import tree_sitter_python
import tree_sitter_typescript

from auditor.core import treesitter as ts
from auditor.core.models import SourceFile

ts.register_language("python", tree_sitter_python.language())
ts.register_language("java", tree_sitter_java.language())
ts.register_language("csharp", tree_sitter_c_sharp.language())
ts.register_language("typescript", tree_sitter_typescript.language_typescript())
ts.register_language("tsx", tree_sitter_typescript.language_tsx())

SNIPPETS = {
    "python": (b"import os\nfrom x import y\n", "[(import_statement) (import_from_statement)] @imp", 2),
    "java": (b"import com.foo.Bar;\nclass A {}\n", "(import_declaration) @imp", 1),
    "csharp": (b"using System.Text;\nclass A {}\n", "(using_directive) @imp", 1),
    "typescript": (b"import {x} from 'lodash';\n", "(import_statement) @imp", 1),
    "tsx": (b"import React from 'react';\nexport const C = () => <div>hi</div>;\n", "(import_statement) @imp", 1),
}


def test_all_five_grammars_parse_and_query():
    for lang, (src, query, expected) in SNIPPETS.items():
        sf = SourceFile(path=Path(f"x.{lang}"), rel=f"x.{lang}", language=lang, text=src)
        ts.parse_source(sf)
        assert sf.tree is not None and not sf.tree.root_node.has_error, lang
        caps = ts.captures(lang, sf.tree.root_node, query)
        assert len(caps.get("imp", [])) == expected, lang


def test_node_text_and_line():
    sf = SourceFile(path=Path("a.py"), rel="a.py", language="python", text=b"import os\n")
    ts.parse_source(sf)
    node = ts.captures("python", sf.tree.root_node, "(import_statement) @i")["i"][0]
    assert ts.node_text(node) == "import os"
    assert ts.line_of(node) == 1


def test_registry_is_idempotent_and_unknown_name_raises():
    ts.register_language("python", tree_sitter_python.language())  # re-register: no-op
    assert ts.get_language("python") is ts.get_language("python")
    import pytest as _pytest
    with _pytest.raises(ValueError):
        ts.get_language("cobol")
```

`tests\test_walk.py` (uses a stub adapter — real adapters arrive in later tasks):
```python
from pathlib import Path

from auditor.core.walk import IGNORE_DIRS, collect_source_files


class StubAdapter:
    name = "python"
    source_globs = (".py",)

    def file_language(self, path: Path) -> str:
        return "python"


def _mk(tmp_path: Path, rel: str, content: str = "x = 1\n") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_walker_collects_and_ignores(tmp_path):
    _mk(tmp_path, "app.py")
    _mk(tmp_path, "pkg/mod.py")
    _mk(tmp_path, "node_modules/junk.py")
    _mk(tmp_path, ".venv/lib.py")
    _mk(tmp_path, "notes.txt")
    files = collect_source_files(tmp_path, StubAdapter())
    rels = sorted(f.rel for f in files)
    assert rels == ["app.py", "pkg/mod.py"]
    assert all(f.text for f in files) and files[0].language == "python"


def test_walker_excludes_nested_project_roots(tmp_path):
    _mk(tmp_path, "main.py")
    _mk(tmp_path, "sub/inner.py")
    files = collect_source_files(tmp_path, StubAdapter(), exclude_roots=(tmp_path / "sub",))
    assert [f.rel for f in files] == ["main.py"]


def test_ignore_dirs_contains_the_usual_suspects():
    for d in ("node_modules", ".git", "__pycache__", "dist", "target", "obj", ".next"):
        assert d in IGNORE_DIRS
```

- [ ] **Step 2: Run to verify both fail** with `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

`src\auditor\core\treesitter.py` (v2: a REGISTRY — core knows no grammar package names; adapters register their own via `grammars()`):
```python
from __future__ import annotations

from tree_sitter import Language, Parser, Query, QueryCursor

from auditor.core.models import SourceFile

_LANGS: dict[str, Language] = {}


def register_language(name: str, grammar_ptr: object) -> None:
    """Append-only + idempotent by design: first registration of a name wins,
    re-registering the same name is a silent no-op (adapters may be constructed
    many times). Language names are coordinated in the adapters — one owner per
    name. The registry is module-level CACHED state, never mutated after set;
    tests that need isolation call reset_registry()."""
    if name not in _LANGS:
        _LANGS[name] = Language(grammar_ptr)


def reset_registry() -> None:
    _LANGS.clear()


def register_adapters(adapters) -> None:
    for adapter in adapters:
        for name, ptr in adapter.grammars().items():
            register_language(name, ptr)


def get_language(name: str) -> Language:
    if name not in _LANGS:
        raise ValueError(
            f"tree-sitter language '{name}' is not registered — "
            "call register_adapters(default_adapters()) first")
    return _LANGS[name]


def get_parser(name: str) -> Parser:
    return Parser(get_language(name))


def parse_source(sf: SourceFile) -> None:
    if sf.tree is None:
        sf.tree = get_parser(sf.language).parse(sf.text)


def captures(lang_name: str, node, query_src: str) -> dict[str, list]:
    query = Query(get_language(lang_name), query_src)
    return QueryCursor(query).captures(node)


def node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def line_of(node) -> int:
    return node.start_point[0] + 1
```

`src\auditor\core\walk.py`:
```python
from __future__ import annotations

import os
from pathlib import Path

from auditor.core.models import SourceFile

IGNORE_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", ".tox", "__pycache__",
    "dist", "build", "target", "bin", "obj", ".next", "out", ".output",
    "coverage", ".idea", ".vs", ".vscode", "site-packages", ".mypy_cache",
    ".pytest_cache", ".gradle", ".dart_tool", ".terraform",
})
MAX_FILE_BYTES = 1_500_000


def collect_source_files(root: Path, adapter, exclude_roots: tuple[Path, ...] = (),
                         diag=None) -> list[SourceFile]:
    root = root.resolve()
    excluded = tuple(p.resolve() for p in exclude_roots)
    out: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS)
        here = Path(dirpath).resolve()
        if any(here == ex or ex in here.parents for ex in excluded):
            dirnames[:] = []
            continue
        for fn in sorted(filenames):
            p = here / fn
            if p.suffix.lower() not in adapter.source_globs:
                continue
            rel = p.relative_to(root).as_posix()
            try:
                if p.is_symlink():
                    _note(diag, "skipped_files", f"{rel}: symlink (not followed)")
                    continue
                if p.stat().st_size > MAX_FILE_BYTES:
                    _note(diag, "skipped_files", f"{rel}: exceeds {MAX_FILE_BYTES} bytes")
                    continue
                data = p.read_bytes()
            except OSError as e:
                _note(diag, "skipped_files", f"{rel}: unreadable ({e.__class__.__name__})")
                continue
            out.append(SourceFile(path=p, rel=rel, language=adapter.file_language(p), text=data))
    return out


def _note(diag, field_name: str, message: str) -> None:
    if diag is not None:
        getattr(diag, field_name).append(message)


MAX_MANIFEST_BYTES = 2_000_000


def read_text_capped(path: Path, diag=None) -> str:
    """Bounded manifest read: adversarial XML/JSON size is capped BEFORE parsing
    (expat's amplification limits are build-specific; the cap is the real defense)."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            _note(diag, "manifest_errors", f"{path.name}: exceeds {MAX_MANIFEST_BYTES} bytes, skipped")
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        _note(diag, "manifest_errors", f"{path.name}: unreadable ({e.__class__.__name__})")
        return ""
```

- [ ] **Step 4: Run both test files — PASS.** This test doubles as the environment gate: it proves all five grammar wheels import and the 0.26 Query API works on this machine.

- [ ] **Step 5: Commit** — `feat(core): tree-sitter 0.26 helpers and source walker`

### Task 4: Fetch (clone/local) + project discovery

**Files:**
- Create: `src\auditor\fetch.py`, `src\auditor\discovery.py`
- Test: `tests\test_fetch.py`, `tests\test_discovery.py`

**Interfaces:**
- Produces: `fetch.resolve_target(target: str) -> tuple[Path, Callable[[], None]]` (path + cleanup; cleanup is a no-op for local paths); raises `AuditorError` with bilingual message on failure; git runs with `GIT_TERMINAL_PROMPT=0` so private/nonexistent repos fail fast instead of prompting. `discovery.discover_projects(root: Path, adapters: list[LanguageAdapter]) -> list[tuple[LanguageAdapter, Path]]` sorted by (path, adapter.name); when a language has source files but NO manifest anywhere, the repo root is returned as a manifest-less project for that adapter (spec requirement: missing dependency files must not stop the scan — imports then surface as undeclared and the CLI notes the gap). `discovery.project_files(project_root, adapter, all_projects, diag=None) -> list[SourceFile]` excludes nested project roots of the same adapter (monorepo) and forwards `diag` to the walker.

- [ ] **Step 1: Write the failing tests**

`tests\test_fetch.py`:
```python
import subprocess
from pathlib import Path

import pytest

from auditor.errors import AuditorError
from auditor.fetch import resolve_target


def test_local_path_passthrough(tmp_path):
    path, cleanup = resolve_target(str(tmp_path))
    assert path == tmp_path.resolve()
    cleanup()
    assert tmp_path.exists()


def test_missing_local_path_raises():
    with pytest.raises(AuditorError):
        resolve_target(r"C:\definitely\not\here_xyz")


def test_clone_from_local_git_url(tmp_path):
    src = tmp_path / "srcrepo"
    src.mkdir()
    (src / "a.txt").write_text("hi", encoding="utf-8")
    for cmd in (["git", "init", "-b", "main"], ["git", "add", "."],
                ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"]):
        subprocess.run(cmd, cwd=src, check=True, capture_output=True)
    path, cleanup = resolve_target(src.as_uri())  # file:// URL exercises the clone path
    try:
        assert (path / "a.txt").exists() and path != src
    finally:
        cleanup()
    assert not path.exists()


def test_clone_failure_is_friendly():
    with pytest.raises(AuditorError) as exc:
        resolve_target("https://github.com/this-org-does-not-exist-xyz9/this-repo-neither-xyz9")
    assert "clone" in str(exc.value).lower()
```
(The last test needs network for git to fail fast; it still passes offline because git errors immediately on DNS failure — either way `AuditorError` is raised.)

`tests\test_discovery.py`:
```python
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
```

- [ ] **Step 2: Run — both fail** (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

`src\auditor\fetch.py`:
```python
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from auditor.errors import AuditorError

_URL_PREFIXES = ("http://", "https://", "git@", "ssh://", "file://")


def _force_remove(path: Path) -> None:
    """rmtree that survives Windows read-only .git objects."""
    def _onerr(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: _onerr(f, p, e))
    else:
        shutil.rmtree(path, onerror=_onerr)


def resolve_target(target: str) -> tuple[Path, Callable[[], None]]:
    if target.startswith(_URL_PREFIXES):
        tmp = Path(tempfile.mkdtemp(prefix="auditor-"))
        # GIT_TERMINAL_PROMPT=0: fail fast, never prompt; LFS smudge and symlink
        # creation are disabled — we scan text, we never materialize repo tricks
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
               "GIT_LFS_SKIP_SMUDGE": "1"}
        try:
            proc = subprocess.run(
                ["git", "-c", "core.symlinks=false", "clone", "--depth", "1",
                 target, str(tmp / "repo")],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                env=env, timeout=300,
            )
        except subprocess.TimeoutExpired:
            _force_remove(tmp)
            raise AuditorError("git clone timed out after 300s | انتهت مهلة الاستنساخ")
        if proc.returncode != 0:
            _force_remove(tmp)
            tail = (proc.stderr or "").strip().splitlines()[-3:]
            hint = ""
            low = (proc.stderr or "").lower()
            if "authentication" in low or "could not read username" in low or "repository not found" in low:
                hint = " (private or nonexistent repository? | مستودع خاص أو غير موجود؟)"
            raise AuditorError(
                "git clone failed" + hint + " | فشل الاستنساخ:\n" + "\n".join(tail)
            )
        return tmp / "repo", lambda: _force_remove(tmp)
    path = Path(target).expanduser().resolve()
    if not path.is_dir():
        raise AuditorError(f"path not found or not a directory | المسار غير موجود: {target}")
    return path, lambda: None
```

`src\auditor\discovery.py`:
```python
from __future__ import annotations

import os
from pathlib import Path

from auditor.core.interfaces import LanguageAdapter
from auditor.core.models import SourceFile
from auditor.core.walk import IGNORE_DIRS, collect_source_files


def discover_projects(root: Path, adapters: list[LanguageAdapter]) -> list[tuple[LanguageAdapter, Path]]:
    root = root.resolve()
    found: list[tuple[LanguageAdapter, Path]] = []
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS)
        here = Path(dirpath)
        for adapter in adapters:
            if adapter.detect(here):
                found.append((adapter, here))
    detected = {a.name for a, _ in found}
    for adapter in adapters:
        # spec: a missing dependency manifest must not stop the scan
        if adapter.name not in detected and _has_source_files(root, adapter):
            found.append((adapter, root))
    found.sort(key=lambda t: (str(t[1]).lower(), t[0].name))
    return found


def _has_source_files(root: Path, adapter: LanguageAdapter) -> bool:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        if any(Path(f).suffix.lower() in adapter.source_globs for f in filenames):
            return True
    return False


def project_files(project_root: Path, adapter: LanguageAdapter,
                  all_projects: list[tuple[LanguageAdapter, Path]],
                  diag=None) -> list[SourceFile]:
    nested = tuple(
        p for a, p in all_projects
        if a.name == adapter.name and p != project_root and project_root in p.parents
    )
    return collect_source_files(project_root, adapter, exclude_roots=nested, diag=diag)
```

- [ ] **Step 4: Run both test files — PASS.**

- [ ] **Step 5: Commit** — `feat: target fetching (clone/local) and monorepo project discovery`

**PHASE CHECKPOINT CP-2 — STOP.** Present to the user (Arabic): scaffold installed and importable on Windows, all 5 grammars verified by tests, clone+discovery working with monorepo semantics. Show `pytest` summary (`.venv\Scripts\python -m pytest -q`).
**Gate:** all T1–T4 tests green on CPython 3.12 AND a `--dry-run` wheel-resolution check for 3.11; negative demos shown: clone of a nonexistent repo exits with the bilingual error (no prompt hang), walker ignores `node_modules`. **Blockers:** any grammar wheel failing to import; clone prompting for credentials. **Deferred decisions to present:** none expected.

---

## PHASE 3 — Python adapter + registry + Engine 1 (reference model)

### Task 5: TTL cache + registry base + PyPI client

**Files:**
- Create: `src\auditor\registries\cache.py`, `src\auditor\registries\base.py`, `src\auditor\registries\pypi.py`
- Test: `tests\test_cache.py`, `tests\test_registry_pypi.py`

**Interfaces:**
- Consumes: `PackageInfo` (T2)
- Produces: `cache.Cache(path: Path | None = None)` with `.get(key) -> dict | None`, `.set(key, value: dict, ttl_seconds: int)`; `base.make_session() -> requests.Session`; `base.RegistryClient` ABC (`ecosystem: str`, `__init__(self, session=None)`, abstract `lookup(name) -> PackageInfo`, helper `_get(url, **kw)`); `base.CachedRegistry(inner, cache)` with `.ecosystem`, `.lookup(name)`; `base.age_days(iso: str) -> int`; `base.FRESH_DAYS = 90`; `base.LOW_DOWNLOADS = {"weekly": 500, "total": 1500}`; `pypi.canonical(name) -> str` (PEP 503); `pypi.PyPIClient(session=None)`.

- [ ] **Step 1: Write the failing tests**

`tests\test_cache.py`:
```python
import time

from auditor.registries.cache import Cache


def test_set_get_roundtrip(tmp_path):
    c = Cache(tmp_path / "c.json")
    c.set("pypi:requests", {"exists": True}, ttl_seconds=60)
    assert c.get("pypi:requests") == {"exists": True}


def test_expiry(tmp_path):
    c = Cache(tmp_path / "c.json")
    c.set("k", {"v": 1}, ttl_seconds=-1)
    assert c.get("k") is None


def test_persists_across_instances(tmp_path):
    Cache(tmp_path / "c.json").set("k", {"v": 2}, ttl_seconds=60)
    assert Cache(tmp_path / "c.json").get("k") == {"v": 2}
```

`tests\test_registry_pypi.py` (shapes below mirror the live-verified responses in RESEARCH.md §3):
```python
import responses

from auditor.registries.base import CachedRegistry, age_days
from auditor.registries.cache import Cache
from auditor.registries.pypi import PyPIClient, canonical

SIMPLE = "https://pypi.org/simple/{}/"


def test_canonical_pep503():
    assert canonical("Typing_Extensions") == "typing-extensions"
    assert canonical("zope.interface") == "zope-interface"


@responses.activate
def test_existing_package_with_dates():
    responses.get(SIMPLE.format("requests"), json={
        "files": [
            {"filename": "requests-0.1.tar.gz", "upload-time": "2011-02-14T08:49:42.641660Z"},
            {"filename": "requests-2.32.3.tar.gz", "upload-time": "2026-05-14T00:00:00Z"},
        ],
        "project-status": {"status": "active"},
    })
    info = PyPIClient().lookup("Requests")
    assert info.exists and info.created.startswith("2011-02-14")
    assert info.downloads is None  # old package => pypistats not called


@responses.activate
def test_missing_package_404():
    responses.get(SIMPLE.format("zzz-nope"), status=404)
    info = PyPIClient().lookup("zzz_nope")
    assert info.exists is False and info.error is None


@responses.activate
def test_fresh_package_triggers_downloads_lookup():
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    responses.get(SIMPLE.format("newpkg"), json={
        "files": [{"filename": "newpkg-0.1.tar.gz", "upload-time": recent}],
    })
    responses.get("https://pypistats.org/api/packages/newpkg/recent",
                  json={"data": {"last_day": 1, "last_week": 7, "last_month": 9}})
    info = PyPIClient().lookup("newpkg")
    assert info.exists and info.downloads == 7 and info.downloads_period == "weekly"
    assert age_days(info.created) < 90


@responses.activate
def test_quarantined_flag():
    responses.get(SIMPLE.format("evilpkg"), json={
        "files": [{"filename": "evilpkg-1.tar.gz", "upload-time": "2026-07-01T00:00:00Z"}],
        "project-status": {"status": "quarantined"},
    })
    responses.get("https://pypistats.org/api/packages/evilpkg/recent", status=404, body="404")
    info = PyPIClient().lookup("evilpkg")
    assert info.quarantined is True and info.downloads is None


@responses.activate
def test_network_error_reports_error_not_crash():
    info = PyPIClient().lookup("whatever")  # no responses registered => ConnectionError
    assert info.error is not None


@responses.activate
def test_cached_registry_hits_network_once(tmp_path):
    responses.get(SIMPLE.format("requests"), json={"files": [
        {"filename": "r-1.tar.gz", "upload-time": "2011-02-14T08:49:42Z"}]})
    reg = CachedRegistry(PyPIClient(), Cache(tmp_path / "c.json"))
    a = reg.lookup("requests")
    b = reg.lookup("requests")
    assert a.exists and b.exists and len(responses.calls) == 1
```

- [ ] **Step 2: Run — fail** (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

`src\auditor\registries\cache.py`:
```python
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

import platformdirs


def default_cache_path() -> Path:
    return Path(platformdirs.user_cache_dir("ai-code-auditor")) / "registry-cache.json"


class Cache:
    def __init__(self, path: Path | None = None):
        self.path = path or default_cache_path()
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        if self.path.is_file():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                now = time.time()
                self._data = {k: v for k, v in raw.items() if v.get("expires", 0) > now}
            except (OSError, json.JSONDecodeError):
                self._data = {}

    def get(self, key: str) -> dict | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None or entry["expires"] <= time.time():
                self._data.pop(key, None)
                return None
            return entry["value"]

    def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        with self._lock:
            self._data[key] = {"expires": time.time() + ttl_seconds, "value": value}
            self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh)
        os.replace(tmp, self.path)
```

`src\auditor\registries\base.py`:
```python
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict
from datetime import datetime, timezone

import requests

from auditor import __version__
from auditor.core.models import PackageInfo
from auditor.registries.cache import Cache

USER_AGENT = f"ai-code-auditor/{__version__} (+https://github.com/local/ai-code-auditor)"
TIMEOUT = (5, 15)
FRESH_DAYS = 90
LOW_DOWNLOADS = {"weekly": 500, "total": 1500}
TTL_EXISTS = 7 * 24 * 3600
TTL_MISSING = 24 * 3600


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def age_days(iso: str) -> int:
    return (datetime.now(timezone.utc) - parse_iso(iso)).days


class RegistryClient(ABC):
    ecosystem: str

    def __init__(self, session: requests.Session | None = None):
        self.session = session or make_session()

    def _get(self, url: str, **kw) -> requests.Response:
        kw.setdefault("timeout", TIMEOUT)
        return self.session.get(url, **kw)

    @abstractmethod
    def lookup(self, name: str) -> PackageInfo: ...


class CachedRegistry:
    def __init__(self, inner: RegistryClient, cache: Cache):
        self.inner = inner
        self.cache = cache

    @property
    def ecosystem(self) -> str:
        return self.inner.ecosystem

    def lookup(self, name: str) -> PackageInfo:
        key = f"{self.ecosystem}:{name.lower()}"
        hit = self.cache.get(key)
        if hit is not None:
            return PackageInfo(**hit)
        info = self.inner.lookup(name)
        if info.error is None:
            ttl = TTL_EXISTS if info.exists else TTL_MISSING
            self.cache.set(key, asdict(info), ttl)
        return info
```

`src\auditor\registries\pypi.py`:
```python
from __future__ import annotations

import re
import threading
import time

import requests

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

SIMPLE_URL = "https://pypi.org/simple/{}/"
STATS_URL = "https://pypistats.org/api/packages/{}/recent"
_ACCEPT = "application/vnd.pypi.simple.v1+json"  # PEP 691
_stats_lock = threading.Lock()                    # pypistats hard-throttles (~0.5 req/s)


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class PyPIClient(RegistryClient):
    ecosystem = "pypi"

    def lookup(self, name: str) -> PackageInfo:
        cname = canonical(name)
        try:
            r = self._get(SIMPLE_URL.format(cname), headers={"Accept": _ACCEPT})
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
            data = r.json()
        except requests.RequestException as e:
            return PackageInfo(exists=False, error=f"pypi: {e.__class__.__name__}")
        times = sorted(f["upload-time"] for f in data.get("files", []) if f.get("upload-time"))
        created = times[0] if times else None
        latest = times[-1] if times else None
        # PEP 792: live PyPI + living spec use `status`, but the PEP prose says
        # `state` — tolerate BOTH (absent => active); PyPI implements
        # active/archived/quarantined today
        ps = data.get("project-status", {}) or {}
        status = ps.get("status") or ps.get("state") or "active"
        downloads = None
        if created and age_days(created) < FRESH_DAYS and status == "active":
            downloads = self._weekly_downloads(cname)
        return PackageInfo(exists=True, created=created, latest=latest,
                           downloads=downloads, quarantined=status == "quarantined",
                           archived=status == "archived")

    def _weekly_downloads(self, cname: str) -> int | None:
        with _stats_lock:
            time.sleep(1.2)  # etiquette: stay far under pypistats 429 threshold
            try:
                r = self._get(STATS_URL.format(cname))
                if r.status_code != 200 or "json" not in r.headers.get("Content-Type", ""):
                    return None
                return int(r.json()["data"]["last_week"])
            except (requests.RequestException, KeyError, ValueError):
                return None
```

- [ ] **Step 4: Run both test files — PASS.**
- [ ] **Step 5: Commit** — `feat(registries): TTL cache, client base, PyPI client (PEP 691 + PEP 792 + pypistats)`

### Task 6: Python adapter — detection + dependency parsing

**Files:**
- Create: `src\auditor\adapters\python\__init__.py`, `src\auditor\adapters\python\adapter.py`, `src\auditor\adapters\python\aliases.py`
- Test: `tests\test_python_adapter.py` (dependency-parsing tests only in this task)

**Interfaces:**
- Consumes: `LanguageAdapter`, `DeclaredDep` (T2), `canonical` (T5)
- Produces: `PythonAdapter()` with `name="python"`, `ecosystem="pypi"`, `source_globs=(".py",)`; `detect()` true if the dir contains `requirements*.txt` / `pyproject.toml` / `setup.py` / `Pipfile`; `parse_dependencies()` reading requirements + `[project.dependencies]` + `[project.optional-dependencies]` + `[tool.poetry.dependencies]` + a regex fallback for `setup.py install_requires`; `aliases.IMPORT_TO_DIST: dict[str, str]`.

- [ ] **Step 1: Write the failing tests** (append to a new `tests\test_python_adapter.py`)

```python
from pathlib import Path

from auditor.adapters.python.adapter import PythonAdapter


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_detect(tmp_path):
    a = PythonAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "requirements.txt", "requests\n")
    assert a.detect(tmp_path)


def test_parse_requirements_variants(tmp_path):
    _mk(tmp_path, "requirements.txt", "\n".join([
        "requests==2.32.3",
        "PyYAML>=6.0 ; python_version >= '3.8'",
        "uvicorn[standard]~=0.30",
        "# comment",
        "-r other.txt",
        "-e .",
        "ghost-pkg @ https://example.com/g.whl",
        "",
    ]))
    deps = PythonAdapter().parse_dependencies(tmp_path)
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"requests", "pyyaml", "uvicorn", "ghost-pkg"}
    assert by_name["requests"].line == 1
    assert by_name["ghost-pkg"].skip_registry is True  # direct URL, not a registry name


def test_parse_pyproject_project_and_poetry(tmp_path):
    _mk(tmp_path, "pyproject.toml", "\n".join([
        "[project]",
        'name = "x"',
        'dependencies = ["httpx>=0.27", "rich"]',
        "[project.optional-dependencies]",
        'dev = ["pytest>=8"]',
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        'flask = "^3.0"',
    ]))
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"httpx", "rich", "pytest", "flask"}  # "python" excluded


def test_parse_setup_py_regex_fallback(tmp_path):
    _mk(tmp_path, "setup.py",
        "from setuptools import setup\n"
        "setup(name='x', install_requires=['numpy>=1.26', \"pandas\"])\n")
    names = {d.name for d in PythonAdapter().parse_dependencies(tmp_path)}
    assert names == {"numpy", "pandas"}
```

- [ ] **Step 2: Run — fail.** `.venv\Scripts\python -m pytest tests\test_python_adapter.py -v`

- [ ] **Step 3: Implement**

`src\auditor\adapters\python\__init__.py`: empty file.

`src\auditor\adapters\python\aliases.py` (curated subset of the pipreqs mapping idea — import name → PyPI dist name):
```python
IMPORT_TO_DIST = {
    "cv2": "opencv-python", "PIL": "pillow", "yaml": "pyyaml", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dotenv": "python-dotenv", "dateutil": "python-dateutil",
    "jwt": "pyjwt", "git": "gitpython", "magic": "python-magic", "Crypto": "pycryptodome",
    "OpenSSL": "pyopenssl", "serial": "pyserial", "docx": "python-docx",
    "pptx": "python-pptx", "fitz": "pymupdf", "nacl": "pynacl", "github": "pygithub",
    "telegram": "python-telegram-bot", "socks": "pysocks", "websocket": "websocket-client",
    "zmq": "pyzmq", "attr": "attrs", "gi": "pygobject", "win32api": "pywin32",
    "win32com": "pywin32", "pythoncom": "pywin32",
}
```

`src\auditor\adapters\python\adapter.py` (this task implements `detect` + `parse_dependencies` only; the import-side methods land in Task 7 — to keep the class instantiable now, implement the T7 methods with real minimal bodies that Task 7 replaces):
```python
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from auditor.adapters.python.aliases import IMPORT_TO_DIST
from auditor.core.interfaces import LanguageAdapter
from auditor.core.models import DeclaredDep, ImportRef, SourceFile
from auditor.registries.pypi import canonical

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SETUP_LIST = re.compile(r"install_requires\s*=\s*\[(.*?)\]", re.S)
_QUOTED = re.compile(r"""["']([^"']+)["']""")
MANIFESTS = ("requirements", "pyproject.toml", "setup.py", "Pipfile")


class PythonAdapter(LanguageAdapter):
    name = "python"
    ecosystem = "pypi"
    source_globs = (".py",)

    def __init__(self) -> None:
        self._internal_roots: set[str] = set()

    def detect(self, root: Path) -> bool:
        if (root / "pyproject.toml").is_file() or (root / "setup.py").is_file() \
                or (root / "Pipfile").is_file():
            return True
        return any(root.glob("requirements*.txt"))

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        deps: list[DeclaredDep] = []
        for req in sorted(root.glob("requirements*.txt")):
            deps += self._parse_requirements(req)
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            deps += self._parse_pyproject(pyproject)
        pipfile = root / "Pipfile"
        if pipfile.is_file():
            deps += self._parse_pipfile(pipfile)
        setup = root / "setup.py"
        if setup.is_file():
            deps += self._parse_setup_py(setup)
        seen: set[str] = set()
        out = []
        for d in deps:
            if d.name not in seen:
                seen.add(d.name)
                out.append(d)
        self._last_declared = out   # cache: project_rules must NOT re-parse
        return out                  # (a bare re-call would reset self._diag)

    def _parse_pipfile(self, path: Path) -> list[DeclaredDep]:
        try:
            data = tomllib.loads(self._read(path))
        except tomllib.TOMLDecodeError as e:
            self._manifest_error(path, e)
            return []
        out = []
        for section in ("packages", "dev-packages"):
            for name, spec in (data.get(section) or {}).items():
                out.append(DeclaredDep(name=canonical(name), ecosystem="pypi",
                                       source_file=path.name, raw=f"{section}: {name} = {spec!r}",
                                       skip_registry=isinstance(spec, dict) and
                                       any(k in spec for k in ("path", "git", "file"))))
        return out

    def _parse_requirements(self, path: Path) -> list[DeclaredDep]:
        out = []
        rel = path.name
        for i, raw in enumerate(self._read(path).splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = _REQ_NAME.match(line)
            if not m:
                continue
            out.append(DeclaredDep(
                name=canonical(m.group(1)), ecosystem="pypi", source_file=rel,
                line=i, raw=line, skip_registry="@" in line.split("#", 1)[0],
            ))
        return out

    def _parse_pyproject(self, path: Path) -> list[DeclaredDep]:
        try:
            data = tomllib.loads(self._read(path))
        except tomllib.TOMLDecodeError as e:
            self._manifest_error(path, e)
            return []
        specs: list[str] = list(data.get("project", {}).get("dependencies", []))
        for group in data.get("project", {}).get("optional-dependencies", {}).values():
            specs += list(group)
        out = [self._from_pep508(s, path.name) for s in specs]
        poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        out += [
            DeclaredDep(name=canonical(k), ecosystem="pypi", source_file=path.name, raw=f"{k} = {v!r}")
            for k, v in poetry.items() if k.lower() != "python"
        ]
        return [d for d in out if d is not None]

    def _from_pep508(self, spec: str, src: str) -> DeclaredDep | None:
        m = _REQ_NAME.match(spec.strip())
        if not m:
            return None
        return DeclaredDep(name=canonical(m.group(1)), ecosystem="pypi",
                           source_file=src, raw=spec, skip_registry="@" in spec)

    def _parse_setup_py(self, path: Path) -> list[DeclaredDep]:
        m = _SETUP_LIST.search(self._read(path))
        if not m:
            return []
        return [d for d in (self._from_pep508(s, path.name) for s in _QUOTED.findall(m.group(1)))
                if d is not None]

    # ---- import side: real implementations in Task 7 ----
    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        return []

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        return None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        return []

    def is_internal(self, imp: ImportRef) -> bool:
        return False
```
Note: `test_parse_requirements_variants` expects `ghost-pkg` (a `name @ url` direct reference) to carry `skip_registry=True`; the `"@" in line` check above covers it.

- [ ] **Step 4: Run — the 4 dependency tests PASS.**
- [ ] **Step 5: Commit** — `feat(python): adapter detection and dependency parsing (requirements/pyproject/poetry/setup.py)`

### Task 7: Python adapter — imports, stdlib, local modules, registry mapping

**Files:**
- Modify: `src\auditor\adapters\python\adapter.py` (replace the four stub methods + add `prepare`)
- Test: append to `tests\test_python_adapter.py`

**Interfaces:**
- Produces (final semantics used by Engine 1): `prepare(root, files)` computes local top-level names (package dirs + `.py` stems + src-layout roots); `extract_imports` via tree-sitter (absolute imports only; relative imports skipped as local); `is_internal` true for `sys.stdlib_module_names`, `__future__`, and local names; `match_declared` compares `canonical(top_level)` and `canonical(IMPORT_TO_DIST.get(top_level))` against declared names; `registry_candidates` returns `[IMPORT_TO_DIST.get(top) or canonical(top)]`.

- [ ] **Step 1: Write the failing tests** (append)

```python
from auditor.core.models import DeclaredDep, ImportRef
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _files(tmp_path, adapter):
    files = collect_source_files(tmp_path, adapter)
    for f in files:
        parse_source(f)
    return files


def test_extract_imports_and_locality(tmp_path):
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "app.py", "\n".join([
        "import os, sys",
        "import requests",
        "import yaml",
        "from . import sibling",
        "from helpers import util",
        "import helpers.util",
        "from pathlib import Path",
    ]) + "\n")
    _mk(tmp_path, "helpers/__init__.py", "")
    _mk(tmp_path, "helpers/util.py", "")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    imps = a.extract_imports(files)
    tops = {i.top_level for i in imps}
    assert {"os", "sys", "requests", "yaml", "helpers", "pathlib"} <= tops
    assert all("sibling" not in i.module for i in imps)  # relative import skipped
    by_top = {i.top_level: i for i in imps}
    assert by_top["requests"].line == 2
    assert a.is_internal(by_top["os"]) and a.is_internal(by_top["pathlib"])
    assert a.is_internal(by_top["helpers"])
    assert not a.is_internal(by_top["yaml"])


def test_match_declared_uses_alias_map():
    a = PythonAdapter()
    declared = [DeclaredDep(name="pyyaml", ecosystem="pypi", source_file="r.txt"),
                DeclaredDep(name="opencv-python", ecosystem="pypi", source_file="r.txt")]
    assert a.match_declared(ImportRef("yaml", "f.py", 1, top_level="yaml"), declared).name == "pyyaml"
    assert a.match_declared(ImportRef("cv2", "f.py", 1, top_level="cv2"), declared).name == "opencv-python"
    assert a.match_declared(ImportRef("numpy", "f.py", 1, top_level="numpy"), declared) is None


def test_registry_candidates_alias_then_canonical():
    a = PythonAdapter()
    assert a.registry_candidates(ImportRef("yaml", "f.py", 1, top_level="yaml")) == ["pyyaml"]
    assert a.registry_candidates(ImportRef("some_pkg", "f.py", 1, top_level="some_pkg")) == ["some-pkg"]


def _p008_repo(tmp_path, requires, code, extra_toml=""):
    _mk(tmp_path, "pyproject.toml",
        f'[project]\nname = "x"\nrequires-python = "{requires}"\n'
        f'dependencies = [{extra_toml}]\n')
    _mk(tmp_path, "m.py", code)
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    return a.project_rules(tmp_path, [])


def test_p008_range_crossing_removal_counterexample(tmp_path):
    # THE third-round counterexample: >=3.11 + distutils (removed 3.12)
    fs = _p008_repo(tmp_path, ">=3.11", "import distutils\n")
    assert len(fs) == 1 and "CROSSES" in fs[0].detail


def test_p008_range_ends_before_removal_is_clean(tmp_path):
    assert _p008_repo(tmp_path, ">=3.8,<3.12", "import distutils\n") == []


def test_p008_entire_range_after_removal(tmp_path):
    fs = _p008_repo(tmp_path, ">=3.13", "import telnetlib\n")
    assert len(fs) == 1 and "at or above the removal" in fs[0].detail


def test_p008_added_module_below_floor_needs_backport(tmp_path):
    fs = _p008_repo(tmp_path, ">=3.8", "import tomllib\n")
    assert len(fs) == 1 and "tomli" in fs[0].detail


def test_p008_declared_backport_silences(tmp_path):
    assert _p008_repo(tmp_path, ">=3.8", "import tomllib\n", extra_toml='"tomli"') == []


def test_p008_pep440_semantics_not_hand_regex(tmp_path):
    # the four measured hand-regex refutations, now judged correctly:
    fs = _p008_repo(tmp_path, "~=3.11", "import distutils\n")
    assert len(fs) == 1 and "CROSSES" in fs[0].detail      # ~=3.11 reaches 3.12+
    assert _p008_repo(tmp_path, "==3.11.*", "import distutils\n") == []  # only 3.11
    fs = _p008_repo(tmp_path, "<3.12.1", "import distutils\n")
    assert len(fs) == 1                                     # 3.12.0 IS allowed
    fs = _p008_repo(tmp_path, ">=3.11,!=3.12.*", "import distutils\n")
    assert len(fs) == 1 and "CROSSES" in fs[0].detail       # 3.13+ still lacks it


def test_p008_patch_level_specifiers_reach_the_minor(tmp_path):
    # fifth-round: minor-only containment (Version('3.12')) returned [] for these
    # even though each admits a 3.12.x patch — must fire P008 for distutils
    for spec in ("==3.12.1", "~=3.12.1", ">=3.12.1,<3.13"):
        fs = _p008_repo(tmp_path, spec, "import distutils\n")
        assert len(fs) == 1, spec   # 3.12 reachable via a patch => at/above removal


def test_corrupt_manifest_counted_once_across_multiple_reads(tmp_path):
    # fourth-round: pyproject is read by parse_dependencies AND project_rules
    # AND the range parser — one broken file must yield ONE unique error and
    # ONE unique manifest_files entry, with diagnostics never detached
    from auditor.core.models import Diagnostics
    _mk(tmp_path, "pyproject.toml", "[project\nbroken = ")
    _mk(tmp_path, "m.py", "import os\n")
    a = PythonAdapter()
    diag = Diagnostics()
    a.parse_dependencies(tmp_path, diag=diag)
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    a.project_rules(tmp_path, [])
    assert len([e for e in diag.manifest_errors if "pyproject" in e]) == 1
    assert diag.manifest_files.count(str(tmp_path / "pyproject.toml")) == 1


def test_p008_unknown_range_makes_no_claim(tmp_path):
    _mk(tmp_path, "requirements.txt", "requests\n")
    _mk(tmp_path, "m.py", "import distutils\n")
    a = PythonAdapter()
    files = _files(tmp_path, a)
    a.prepare(tmp_path, files)
    assert a.project_rules(tmp_path, []) == []
```

- [ ] **Step 2: Run — new tests fail** (stubs return empty).

- [ ] **Step 3: Implement** — replace the four stubs in `PythonAdapter` with:

```python
    _IMPORT_QUERY = "[(import_statement) (import_from_statement)] @imp"

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        self.ensure_grammars()
        self._last_files = files   # reused by project_rules (P008)
        roots: set[str] = set()
        for child in root.iterdir():
            if child.suffix == ".py":
                roots.add(child.stem)
            elif child.is_dir() and (child / "__init__.py").is_file():
                roots.add(child.name)
        for src_dir in (root / "src", root / "lib"):
            if src_dir.is_dir():
                for child in src_dir.iterdir():
                    if child.suffix == ".py":
                        roots.add(child.stem)
                    elif child.is_dir() and (child / "__init__.py").is_file():
                        roots.add(child.name)
        self._internal_roots = roots

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, line_of, parse_source
        out: list[ImportRef] = []
        for sf in files:
            parse_source(sf)
            for node in captures("python", sf.tree.root_node, self._IMPORT_QUERY).get("imp", []):
                out += self._imports_from_node(node, sf.rel)
        return out

    def _imports_from_node(self, node, rel: str) -> list[ImportRef]:
        from auditor.core.treesitter import line_of, node_text
        refs: list[ImportRef] = []
        if node.type == "import_statement":
            for child in node.named_children:
                target = child.child_by_field_name("name") if child.type == "aliased_import" else child
                if target is not None and target.type == "dotted_name":
                    mod = node_text(target)
                    refs.append(ImportRef(module=mod, file=rel, line=line_of(node),
                                          top_level=mod.split(".")[0]))
        else:  # import_from_statement
            mod_node = node.child_by_field_name("module_name")
            if mod_node is None or mod_node.type == "relative_import":
                return []  # relative import => local by definition
            mod = node_text(mod_node)
            refs.append(ImportRef(module=mod, file=rel, line=line_of(node),
                                  top_level=mod.split(".")[0]))
        return refs

    # Removed-from-stdlib names (PEP 594 + PEP 632 + imp/lib2to3), keyed by the
    # version that removed them. Two proven failure modes without this table:
    # scanner-3.12 flags `import distutils` as H002 (a junk "distutils" project
    # EXISTS on PyPI), and scanner-3.13 would flag `import telnetlib` as a RED
    # H008 (telnetlib is 404 on PyPI). Membership is scanner-version-independent.
    REMOVED_STDLIB = {
        "distutils": (3, 12), "imp": (3, 12), "asynchat": (3, 12), "asyncore": (3, 12),
        "smtpd": (3, 12), "telnetlib": (3, 13), "cgi": (3, 13), "cgitb": (3, 13),
        "pipes": (3, 13), "crypt": (3, 13), "nis": (3, 13), "spwd": (3, 13),
        "ossaudiodev": (3, 13), "audioop": (3, 13), "aifc": (3, 13), "sunau": (3, 13),
        "chunk": (3, 13), "mailcap": (3, 13), "msilib": (3, 13), "nntplib": (3, 13),
        "sndhdr": (3, 13), "uu": (3, 13), "xdrlib": (3, 13), "imghdr": (3, 13),
        "lib2to3": (3, 13),
    }
    # Third direction (second-round review): modules ADDED after old floors —
    # a >=3.8 project importing tomllib crashes on 3.8 unless a backport is
    # declared. Minimal availability-intervals model: introduced_in + the
    # backport dist that makes the import legitimate on older floors.
    ADDED_STDLIB = {"zoneinfo": ((3, 9), "backports-zoneinfo"),
                    "graphlib": ((3, 9), "graphlib-backport"),
                    "tomllib": ((3, 11), "tomli")}
    # Removed modules that a declared dist legitimately re-provides:
    REMOVED_BACKPORTS = {"distutils": "setuptools"}

    def is_internal(self, imp: ImportRef) -> bool:
        import sys
        top = imp.top_level
        return top in sys.stdlib_module_names or top == "__future__" \
            or top in self.REMOVED_STDLIB or top in self._internal_roots

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        names = {canonical(imp.top_level)}
        alias = IMPORT_TO_DIST.get(imp.top_level)
        if alias:
            names.add(canonical(alias))
        for dep in declared:
            if canonical(dep.name) in names:
                return dep
        return None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        alias = IMPORT_TO_DIST.get(imp.top_level)
        return [canonical(alias)] if alias else [canonical(imp.top_level)]

    def grammars(self) -> dict[str, object]:
        import tree_sitter_python
        return {"python": tree_sitter_python.language()}

    def syntax(self):
        from auditor.core.interfaces import SyntaxProfile
        return SyntaxProfile(
            catch_query="(except_clause) @c",
            catch_body_types=("block",),
            is_swallow_stmt=lambda s: s.type == "pass_statement" or (
                s.type == "expression_statement" and s.named_children
                and s.named_children[0].type == "ellipsis"),
            sql_concat_query="(binary_operator) @n",
            sql_interp_query="(string) @n",
            sql_dynamic_types=("interpolation",),
        )

    def private_registry_reason(self, root: Path) -> str | None:
        markers = ("--index-url", "-i ", "--extra-index-url", "--no-index", "--find-links")
        for req in root.glob("requirements*.txt"):
            text = self._read(req)
            if any(line.strip().startswith(markers) for line in text.splitlines()):
                return f"custom index configured in {req.name}"
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = tomllib.loads(self._read(pyproject))
            except tomllib.TOMLDecodeError:
                return None
            tool = data.get("tool", {})
            if tool.get("uv", {}).get("index") or tool.get("poetry", {}).get("source"):
                return "custom index configured in pyproject.toml"
        return None

    def project_rules(self, root: Path, frameworks: list[str]) -> list:
        """P008 (blue, availability-intervals model): stdlib drift in BOTH
        directions relative to the project's OWN requires-python floor —
        (a) imports a module removed at/below the floor's reachable versions,
        (b) imports a module introduced ABOVE the floor with no declared
        backport. Emitted ONLY when requires-python is parseable — unknown
        target => no claim. A declared backport (tomli, setuptools, ...)
        silences the finding; ranges that merely CROSS a boundary stay blue
        by construction (informational, never risk)."""
        from auditor.core.models import Finding, Severity
        allowed = self._allowed_minors(root)
        if not allowed:
            return []
        floor = min(allowed)
        cached = getattr(self, "_last_declared", None)
        declared = {d.name for d in (cached if cached is not None
                                     else self.parse_dependencies(root))}
        out = []
        files = getattr(self, "_last_files", [])
        for imp in self.extract_imports(files):
            top = imp.top_level
            removed_in = self.REMOVED_STDLIB.get(top)
            if removed_in and self.REMOVED_BACKPORTS.get(top) not in declared:
                msg = self._judge_removed(allowed, removed_in, top)
                if msg:
                    out.append(self._p008(imp, msg))
            added = self.ADDED_STDLIB.get(top)
            if added and added[1] not in declared:
                msg = self._judge_added(allowed, added[0], top, added[1])
                if msg:
                    out.append(self._p008(imp, msg))
        return out

    # Judged over the PEP 440-faithful set of allowed minors (fourth round:
    # the hand regex was refuted 4/4 — ~=3.11 actually allows up to <4.0,
    # <3.12.1 still admits 3.12, ==3.11.* had no ceiling, != was ignored).
    @staticmethod
    def _judge_removed(allowed, removed, top) -> str | None:
        if all(v < removed for v in allowed):
            return None                      # range ends before the removal
        if all(v >= removed for v in allowed):
            return (f"{top} was removed in Python {removed[0]}.{removed[1]} and every "
                    "version this project allows is at or above the removal.")
        return (f"{top} was removed in Python {removed[0]}.{removed[1]}; the allowed "
                "version range CROSSES the removal — ambiguous, breaks on the newer "
                "interpreters the project claims to support.")

    @staticmethod
    def _judge_added(allowed, introduced, top, backport) -> str | None:
        if all(v >= introduced for v in allowed):
            return None                      # always available in range
        if all(v < introduced for v in allowed):
            return (f"{top} exists only since Python {introduced[0]}.{introduced[1]} "
                    "and is NEVER available in this project's declared range; declare "
                    f"the '{backport}' backport or raise requires-python.")
        return (f"{top} exists only since Python {introduced[0]}.{introduced[1]} but the "
                f"allowed range includes older versions without the '{backport}' backport "
                "— breaks on the older interpreters the project claims to support.")

    @staticmethod
    def _p008(imp, detail: str):
        from auditor.core.models import Finding, Severity
        return Finding(rule_id="P008", severity=Severity.BLUE,
                       title="stdlib availability mismatch within the project's requires-python range",
                       file=imp.file, line=imp.line, snippet=imp.module,
                       detail=detail, language="python", engine="auditor")

    _MAX_MINOR = 20    # evaluation horizon for open-ended ranges
    _MAX_PATCH = 25    # patch horizon per minor

    def _allowed_minors(self, root: Path):
        """PEP 440-faithful requires-python evaluation via `packaging`. A minor
        counts as reachable if ANY patch release within it satisfies the spec —
        fifth-round counterexample: ==3.12.1 / ~=3.12.1 / >=3.12.1,<3.13 all
        exclude 3.12.0, so testing only Version('3.12') returned [] and dropped
        the whole claim (measured). Returns sorted allowed (3, minor) tuples, or
        None when unspecified/invalid => no P008 claims. prerelease=True so a
        prerelease-only floor (>=3.13.0rc1) still reveals 3.13 as reachable."""
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        from packaging.version import Version
        pyproject = root / "pyproject.toml"
        if not pyproject.is_file():
            return None
        try:
            data = tomllib.loads(self._read(pyproject))
        except tomllib.TOMLDecodeError:
            return None
        spec = (data.get("project", {}).get("requires-python") or "").strip()
        if not spec:
            return None
        try:
            sset = SpecifierSet(spec)
        except InvalidSpecifier:
            return None
        allowed = [(3, m) for m in range(0, self._MAX_MINOR + 1)
                   if any(sset.contains(Version(f"3.{m}.{p}"), prereleases=True)
                          for p in range(0, self._MAX_PATCH + 1))]
        return allowed or None
```
(Treesitter helper imports stay local to the methods so module import remains cheap; `prepare()` already stores `self._last_files` for `project_rules`.)

- [ ] **Step 4: Run full `tests\test_python_adapter.py` — PASS (7 tests).**
- [ ] **Step 5: Commit** — `feat(python): tree-sitter import extraction, stdlib/local detection, PyPI name mapping`

### Task 8: Engine 1 — hallucination auditor (language-agnostic)

**Files:**
- Create: `src\auditor\core\hallucination.py`
- Create: `tests\conftest.py` (FakeRegistry + fixture path helper)
- Test: `tests\test_hallucination.py`

**Interfaces:**
- Consumes: adapter protocol (T2/T7), `PackageInfo`, `FRESH_DAYS`, `LOW_DOWNLOADS`, `age_days` (T5)
- Produces: `audit_hallucinations(adapter, root: Path, files: list[SourceFile], declared: list[DeclaredDep], registry, diag=None) -> list[Finding]` where `registry` is `CachedRegistry | FakeRegistry | None` (None ⇒ offline: emit H003 per unique declared dep once, H007 for undeclared imports) and `diag` receives `registry_attempted`/`registry_failures` counters. Emits per the Rule ID Catalog. Registry lookups for unique names run through `ThreadPoolExecutor(max_workers=8)` with per-name exception isolation.

- [ ] **Step 1: Extend conftest + write failing tests**

APPEND to the existing `tests\conftest.py` (created in Task 3 — keep its grammar registration block at the top):
```python
from pathlib import Path

from auditor.core.models import PackageInfo

FIXTURES = Path(__file__).parent / "fixtures"


class FakeRegistry:
    """Deterministic in-memory registry for engine/E2E tests."""

    def __init__(self, ecosystem: str, known: dict[str, PackageInfo]):
        self.ecosystem = ecosystem
        self.known = {k.lower(): v for k, v in known.items()}
        self.calls: list[str] = []

    def lookup(self, name: str) -> PackageInfo:
        self.calls.append(name.lower())
        return self.known.get(name.lower(), PackageInfo(exists=False))


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
```

`tests\test_hallucination.py`:
```python
from datetime import datetime, timedelta, timezone
from pathlib import Path

from auditor.core.hallucination import audit_hallucinations
from auditor.core.models import (DeclaredDep, ImportRef, PackageInfo, Severity,
                                 SourceFile)
from tests.conftest import FakeRegistry


class MiniAdapter:
    """Adapter stub: everything is external; declared-matching by exact name."""
    name = "python"
    ecosystem = "pypi"

    def __init__(self, internal=(), private_reason=None):
        self._internal = set(internal)
        self._private_reason = private_reason

    def prepare(self, root, files): ...
    def is_internal(self, imp):
        return imp.top_level in self._internal
    def match_declared(self, imp, declared):
        return next((d for d in declared if d.name == imp.top_level), None)
    def registry_candidates(self, imp):
        return [imp.top_level]
    def extract_imports(self, files):
        return self._imports
    def parse_dependencies(self, root):
        return []
    def private_registry_reason(self, root):
        return self._private_reason


def run(declared, imports, registry, internal=(), private_reason=None):
    a = MiniAdapter(internal, private_reason)
    a._imports = imports
    return audit_hallucinations(a, Path("."), [], declared, registry)


def _dep(name, **kw):
    return DeclaredDep(name=name, ecosystem="pypi", source_file="requirements.txt", **kw)


def _imp(name, line=1):
    return ImportRef(module=name, file="app.py", line=line, top_level=name)


OLD = "2019-01-01T00:00:00Z"
FRESH = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()


def test_declared_hallucination_is_red_h001():
    reg = FakeRegistry("pypi", {"requests": PackageInfo(True, created=OLD)})
    fs = run([_dep("requests"), _dep("ghost-ai-utils")], [], reg)
    ids = {(f.rule_id, f.severity) for f in fs}
    assert ("H001", Severity.RED) in ids
    assert all(f.rule_id != "H001" or "ghost-ai-utils" in f.detail for f in fs)


def test_undeclared_existing_import_is_yellow_h002():
    reg = FakeRegistry("pypi", {"yaml": PackageInfo(True, created=OLD)})
    fs = run([], [_imp("yaml", 3)], reg)
    assert [(f.rule_id, f.line) for f in fs] == [("H002", 3)]


def test_undeclared_missing_import_is_red_h008():
    reg = FakeRegistry("pypi", {})
    fs = run([], [_imp("superjsonify")], reg)
    assert [f.rule_id for f in fs] == ["H008"]


def test_fresh_package_yellow_h005_h006():
    reg = FakeRegistry("pypi", {
        "newlow": PackageInfo(True, created=FRESH, downloads=3),
        "newok": PackageInfo(True, created=FRESH, downloads=99999),
    })
    fs = run([_dep("newlow"), _dep("newok")], [], reg)
    got = {f.detail.split()[0]: f.rule_id for f in fs}  # detail starts with the name
    assert got["newlow"] == "H005" and got["newok"] == "H006"


def test_quarantined_is_red_h009():
    reg = FakeRegistry("pypi", {"evil": PackageInfo(True, created=OLD, quarantined=True)})
    assert [f.rule_id for f in run([_dep("evil")], [], reg)] == ["H009"]


def test_archived_is_blue_h012():
    reg = FakeRegistry("pypi", {"oldie": PackageInfo(True, created=OLD, archived=True)})
    fs = run([_dep("oldie")], [], reg)
    assert [(f.rule_id, f.severity) for f in fs] == [("H012", Severity.BLUE)]


def test_private_registry_downgrades_h001_to_h010():
    reg = FakeRegistry("pypi", {})
    fs = run([_dep("internal-corp-lib")], [], reg,
             private_reason="custom index configured in requirements.txt")
    assert [(f.rule_id, f.severity) for f in fs] == [("H010", Severity.YELLOW)]


def test_scoped_missing_is_h010_not_red():
    reg = FakeRegistry("npm", {})
    fs = run([DeclaredDep(name="@corp/secret-lib", ecosystem="npm",
                          source_file="package.json")], [], reg)
    assert [f.rule_id for f in fs] == ["H010"]


def test_npm_alias_checks_registry_name():
    reg = FakeRegistry("npm", {"react": PackageInfo(True, created=OLD)})
    dep = DeclaredDep(name="my-react", ecosystem="npm", source_file="package.json",
                      registry_name="react")
    assert run([dep], [], reg) == [] and reg.calls == ["react"]


def test_offline_mode_blue_h003_and_h007():
    fs = run([_dep("requests")], [_imp("yaml")], registry=None)
    assert {f.rule_id for f in fs} == {"H003", "H007"}
    assert all(f.severity == Severity.BLUE or f.rule_id == "H007" for f in fs)


def test_registry_error_is_blue_h004():
    class ErrReg:
        ecosystem = "pypi"
        def lookup(self, name):
            return PackageInfo(exists=False, error="pypi: ConnectionError")
    fs = run([_dep("requests")], [], ErrReg())
    assert [f.rule_id for f in fs] == ["H004"]


def test_lookup_exception_is_isolated_per_name():
    # fourth-round: a RuntimeError on ONE name must not kill the audit
    class Flaky:
        ecosystem = "pypi"
        def lookup(self, name):
            if name == "bomb":
                raise RuntimeError("driver exploded")
            return PackageInfo(True, created=OLD)
    fs = run([_dep("requests"), _dep("bomb")], [], Flaky())
    assert [f.rule_id for f in fs] == ["H004"]          # bomb => unverified, not a crash
    assert "lookup crashed: RuntimeError" in fs[0].detail
    assert all("requests" not in f.detail for f in fs)   # the healthy name sailed through


def test_skip_registry_and_internal_produce_nothing():
    reg = FakeRegistry("pypi", {})
    fs = run([_dep("local-lib", skip_registry=True)], [_imp("os")], reg, internal={"os"})
    assert fs == [] and reg.calls == []


def test_each_package_reported_once():
    reg = FakeRegistry("pypi", {})
    fs = run([], [_imp("ghost", 1), _imp("ghost", 9)], reg)
    assert len(fs) == 1 and fs[0].line == 1
```

- [ ] **Step 2: Run — fail** (`ModuleNotFoundError: auditor.core.hallucination`).

- [ ] **Step 3: Implement**

`src\auditor\core\hallucination.py`:
```python
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from auditor.core.models import (DeclaredDep, Finding, ImportRef, PackageInfo,
                                 Severity, SourceFile)
from auditor.registries.base import FRESH_DAYS, LOW_DOWNLOADS, age_days

_TITLES = {
    "H001": "Declared dependency not found in the public registry",
    "H002": "Undeclared import (package exists in registry)",
    "H003": "Dependency not verified (offline mode)",
    "H004": "Registry unreachable — dependency unverified",
    "H005": "Brand-new package with near-zero downloads",
    "H006": "Recently published package (< fresh threshold)",
    "H007": "Undeclared import — cannot be mapped to a registry identifier",
    "H008": "Undeclared import not found in the public registry",
    "H009": "Package quarantined by registry (PyPI PEP 792)",
    "H010": "Not found in public registry — private source configured or scoped (unverifiable)",
    "H012": "Package archived by its owner (PEP 792 status)",
}
_SEV = {"H001": Severity.RED, "H002": Severity.YELLOW, "H003": Severity.BLUE,
        "H004": Severity.BLUE, "H005": Severity.YELLOW, "H006": Severity.YELLOW,
        "H007": Severity.YELLOW, "H008": Severity.RED, "H009": Severity.RED,
        "H010": Severity.YELLOW, "H012": Severity.BLUE}


_MAPPING_RULES = {"H002", "H007", "H008", "H010"}   # import→identifier mapping involved


def _finding(rule_id: str, adapter, file: str, line: int, detail: str, snippet: str = "") -> Finding:
    precision = getattr(adapter, "mapping_precision", "exact") \
        if rule_id in _MAPPING_RULES else "exact"
    return Finding(rule_id=rule_id, severity=_SEV[rule_id], title=_TITLES[rule_id],
                   file=file, line=line, snippet=snippet, detail=detail,
                   language=adapter.name, engine="auditor", precision=precision)


def _bulk_lookup(registry, names: list[str]) -> dict[str, PackageInfo]:
    unique = sorted(set(names))
    if not unique:
        return {}

    def _safe(name: str) -> PackageInfo:
        try:
            return registry.lookup(name)
        except Exception as e:
            # one misbehaving client/name must never kill the whole audit —
            # it degrades to an unverified H004 with a visible reason
            return PackageInfo(exists=False,
                               error=f"lookup crashed: {e.__class__.__name__}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        infos = list(pool.map(_safe, unique))
    return dict(zip(unique, infos))


def audit_hallucinations(adapter, root: Path, files: list[SourceFile],
                         declared: list[DeclaredDep], registry,
                         diag=None) -> list[Finding]:
    findings: list[Finding] = []
    imports = adapter.extract_imports(files)

    checkable = []
    seen_declared: set[str] = set()
    for dep in declared:
        key = dep.name.lower()
        if key in seen_declared or dep.skip_registry:
            continue
        seen_declared.add(key)
        checkable.append(dep)

    externals: list[ImportRef] = []
    seen_imports: set[str] = set()
    for imp in imports:
        if adapter.is_internal(imp) or adapter.match_declared(imp, declared):
            continue
        key = (imp.top_level or imp.module).lower()
        if key in seen_imports:
            continue
        seen_imports.add(key)
        externals.append(imp)

    if registry is None:
        for dep in checkable:
            findings.append(_finding("H003", adapter, dep.source_file, dep.line,
                                     f"{dep.name}: registry check skipped (--offline)", dep.raw))
        for imp in externals:
            findings.append(_finding("H007", adapter, imp.file, imp.line,
                                     f"{imp.top_level or imp.module}: imported but not declared; "
                                     "registry check skipped (--offline)", imp.module))
        return _sorted(findings)

    private_reason = adapter.private_registry_reason(root)

    dep_infos = _bulk_lookup(registry, [d.lookup_name for d in checkable])
    for dep in checkable:
        info = dep_infos[dep.lookup_name]
        findings += _judge_declared(adapter, dep, info, private_reason)

    cand_names = sorted({c for imp in externals for c in adapter.registry_candidates(imp)})
    cand_infos = _bulk_lookup(registry, cand_names)
    for imp in externals:
        findings += _judge_import(adapter, imp, cand_infos, private_reason)
    if diag is not None:
        diag.registry_attempted += len(dep_infos) + len(cand_infos)
        diag.registry_failures += sum(1 for f in findings if f.rule_id == "H004")
    return _sorted(findings)


def _ambiguity(dep_or_name: str, private_reason: str | None, scoped: bool) -> str | None:
    if private_reason:
        return private_reason
    if scoped:
        return "scoped npm package (private scopes return 404 without auth)"
    return None


def _judge_declared(adapter, dep: DeclaredDep, info: PackageInfo,
                    private_reason: str | None) -> list[Finding]:
    name = dep.lookup_name
    if info.error:
        return [_finding("H004", adapter, dep.source_file, dep.line,
                         f"{name}: {info.error}", dep.raw)]
    if not info.exists:
        reason = _ambiguity(name, private_reason, name.startswith("@"))
        if reason:
            return [_finding("H010", adapter, dep.source_file, dep.line,
                             f"{name} was not found in the public {adapter.ecosystem} registry, "
                             f"but {reason} — cannot verify; if this name is NOT served by your "
                             "private source, it is dependency-confusion exposure.", dep.raw)]
        return [_finding("H001", adapter, dep.source_file, dep.line,
                         f"{name} is declared in {dep.source_file} but was NOT found in the "
                         f"public {adapter.ecosystem} registry queried at scan time (fact). "
                         "Likely causes: AI-hallucinated name (unregistered names are "
                         "claimable — slopsquatting), a registry-removed/quarantined package, "
                         "or a source this scan cannot see.", dep.raw)]
    if info.quarantined:
        return [_finding("H009", adapter, dep.source_file, dep.line,
                         f"{name} is quarantined by the registry (suspected malware).", dep.raw)]
    if info.archived:
        return [_finding("H012", adapter, dep.source_file, dep.line,
                         f"{name} is archived by its owner (no future updates expected).", dep.raw)]
    if info.created and age_days(info.created) < FRESH_DAYS:
        threshold = LOW_DOWNLOADS.get(info.downloads_period, 500)
        if info.downloads is not None and info.downloads < threshold:
            return [_finding("H005", adapter, dep.source_file, dep.line,
                             f"{name} first published {info.created[:10]} with only "
                             f"{info.downloads} {info.downloads_period} downloads.", dep.raw)]
        return [_finding("H006", adapter, dep.source_file, dep.line,
                         f"{name} first published {info.created[:10]} "
                         f"(younger than {FRESH_DAYS} days).", dep.raw)]
    return []


def _judge_import(adapter, imp: ImportRef, cand_infos: dict[str, PackageInfo],
                  private_reason: str | None) -> list[Finding]:
    label = imp.top_level or imp.module
    cands = adapter.registry_candidates(imp)
    if not cands:
        return [_finding("H007", adapter, imp.file, imp.line,
                         f"{label}: imported but not declared; no reliable mapping to a "
                         f"{adapter.ecosystem} identifier (accuracy limit — verify manually).",
                         imp.module)]
    infos = [cand_infos[c] for c in cands if c in cand_infos]
    if any(i.exists for i in infos):
        exists_name = cands[[i.exists for i in infos].index(True)]
        return [_finding("H002", adapter, imp.file, imp.line,
                         f"{label}: imported but not declared in the manifest "
                         f"(exists in registry as '{exists_name}').", imp.module)]
    if any(i.error for i in infos):
        return [_finding("H004", adapter, imp.file, imp.line,
                         f"{label}: {next(i.error for i in infos if i.error)}", imp.module)]
    reason = _ambiguity(label, private_reason, label.startswith("@"))
    if reason:
        return [_finding("H010", adapter, imp.file, imp.line,
                         f"{label}: imported but not declared, and not found in the public "
                         f"registry — {reason}; cannot verify.", imp.module)]
    return [_finding("H008", adapter, imp.file, imp.line,
                     f"{label}: imported but not declared AND not found in the public "
                     f"{adapter.ecosystem} registry (candidates tried: {', '.join(cands)}). "
                     "Likely an AI-hallucinated import; the unregistered name is claimable "
                     "(slopsquatting).", imp.module)]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.file, f.line, f.rule_id))
```
Note the lookup key detail: `_bulk_lookup` keys results by the exact candidate string; `_judge_declared` first tries the lowercase key then the raw name — keep candidate/declared names already-normalized by adapters so both hit.

- [ ] **Step 4: Run `tests\test_hallucination.py` — PASS (9 tests).**
- [ ] **Step 5: Commit** — `feat(engine1): language-agnostic hallucinated-dependency auditor`

### Task 9: Python fixture repo + reference E2E test

**Files:**
- Create: `tests\fixtures\python_repo\requirements.txt`, `tests\fixtures\python_repo\app.py`, `tests\fixtures\python_repo\localmod.py`
- Test: `tests\test_python_e2e.py`

**Interfaces:**
- Consumes: everything from T2–T8. This is the reference-model proof: discovery → walk → adapter → engine 1, offline-deterministic via FakeRegistry.

- [ ] **Step 1: Create the planted-bugs fixture**

`tests\fixtures\python_repo\requirements.txt`:
```
requests==2.32.3
ghost-ai-utils==9.9.9
```

`tests\fixtures\python_repo\app.py` (plants: undeclared-real `yaml`, hallucinated `superjsonify`, stdlib `os`/`json`, local `localmod`, plus Engine-2 bait used later — empty except, secret, SQL concat, smell comment, complex function):
```python
import os
import json
import requests
import yaml
import superjsonify
import localmod

API_KEY = "AKIAIOSFODNN7EXAMPLE"  # planted AWS-style key for Engine 2


def fetch(url):
    try:
        return requests.get(url).text
    except Exception:
        pass  # TODO: implement error handling


def find_user(cursor, name):
    # In a real application, use parameterized queries
    return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def classify(n):
    if n < 0:
        return "neg"
    elif n == 0:
        return "zero"
    elif n < 2:
        return "one"
    elif n < 5:
        return "few"
    elif n < 10:
        return "some"
    elif n < 50:
        return "many"
    elif n < 100:
        return "lots"
    elif n < 1000:
        return "heaps"
    elif n < 10000:
        return "tons"
    elif n < 100000:
        return "loads"
    else:
        return "huge"
```

`tests\fixtures\python_repo\localmod.py`:
```python
VALUE = 1
```

- [ ] **Step 2: Write the failing E2E test**

`tests\test_python_e2e.py`:
```python
from auditor.adapters.python.adapter import PythonAdapter
from auditor.core.hallucination import audit_hallucinations
from auditor.core.models import PackageInfo, Severity
from auditor.discovery import discover_projects, project_files
from tests.conftest import FakeRegistry

OLD = "2019-01-01T00:00:00Z"


def test_python_reference_pipeline(fixtures_dir):
    root = fixtures_dir / "python_repo"
    adapter = PythonAdapter()
    projects = discover_projects(root, [adapter])
    assert [(a.name, p) for a, p in projects] == [("python", root)]

    files = project_files(root, adapter, projects)
    assert {f.rel for f in files} == {"app.py", "localmod.py"}

    declared = adapter.parse_dependencies(root)
    assert {d.name for d in declared} == {"requests", "ghost-ai-utils"}

    adapter.prepare(root, files)
    reg = FakeRegistry("pypi", {
        "requests": PackageInfo(True, created=OLD),
        "pyyaml": PackageInfo(True, created=OLD),
    })
    findings = audit_hallucinations(adapter, root, files, declared, reg)
    got = {(f.rule_id, f.severity, f.file) for f in findings}
    assert got == {
        ("H001", Severity.RED, "requirements.txt"),      # ghost-ai-utils
        ("H002", Severity.YELLOW, "app.py"),             # yaml -> pyyaml exists
        ("H008", Severity.RED, "app.py"),                # superjsonify
    }
    h001 = next(f for f in findings if f.rule_id == "H001")
    assert "ghost-ai-utils" in f"{h001.detail}{h001.snippet}" and h001.line == 2
```

- [ ] **Step 3: Run — expect PASS immediately** (all parts exist). If it fails, the failure is a real integration bug: fix the component, not the test. Typical trap: `localmod` must be internal via `prepare()` scanning top-level `.py` stems.

- [ ] **Step 4: Run the whole suite** `.venv\Scripts\python -m pytest -q` — all green.

- [ ] **Step 5: Commit** — `test(python): planted-bug fixture repo and reference E2E for Engine 1`

**PHASE CHECKPOINT CP-3 — STOP.** Present to the user: the Python reference model works end-to-end (show the E2E test + a live `audit_hallucinations` run over the fixture with real PyPI if they want). Confirm the finding semantics (H001/H002/H008/H010/H012) before replicating the pattern in 3 more languages.
**Gate:** engine unit tests cover ALL H-rule outcomes including the negative ones (offline, registry error, skip_registry, private-registry downgrade, alias lookup); cache proves single network call on repeat. **Blockers:** any false RED on the fixture; pypistats throttling ignored. **Deferred decisions:** freshness thresholds (90d/500-weekly) — confirm or tune.

---

## PHASE 4 — TypeScript adapter + React/Next.js rules

### Task 10: npm registry client

**Files:**
- Create: `src\auditor\registries\npm.py`
- Test: `tests\test_registry_npm.py`

**Interfaces:**
- Produces: `NpmClient(session=None)`, `ecosystem="npm"`. Existence via `GET https://registry.npmjs.org/{name}` with the body read streamed and capped at 2 MB (cap hit ⇒ `PackageInfo(exists=True)` — giant doc means long-established). `created` from `time.created`. Downloads (only when fresh) via `GET https://api.npmjs.org/downloads/point/last-week/{name}`. Scoped names URL-encode the slash (`quote(name, safe="@")`) for the registry URL; the downloads URL takes the literal name.

- [ ] **Step 1: Write the failing tests**

`tests\test_registry_npm.py`:
```python
from datetime import datetime, timedelta, timezone

import responses

from auditor.registries.npm import NpmClient

REG = "https://registry.npmjs.org/"
DL = "https://api.npmjs.org/downloads/point/last-week/"
FRESH = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()


@responses.activate
def test_existing_package():
    responses.get(REG + "lodash", json={
        "name": "lodash", "dist-tags": {"latest": "4.17.21"},
        "time": {"created": "2012-04-23T16:37:11.912Z", "modified": "2024-01-01T00:00:00Z"},
    })
    info = NpmClient().lookup("lodash")
    assert info.exists and info.created.startswith("2012-04-23") and info.downloads is None


@responses.activate
def test_missing_package_404():
    responses.get(REG + "nope-xyz", json={"error": "Not found"}, status=404)
    assert NpmClient().lookup("nope-xyz").exists is False


@responses.activate
def test_scoped_name_is_slash_encoded():
    responses.get(REG + "@types%2Fnode", json={
        "name": "@types/node", "time": {"created": "2016-03-01T00:00:00Z"}})
    info = NpmClient().lookup("@types/node")
    assert info.exists


@responses.activate
def test_fresh_package_downloads():
    responses.get(REG + "shiny-new", json={"name": "shiny-new", "time": {"created": FRESH}})
    responses.get(DL + "shiny-new", json={"downloads": 12, "start": "x", "end": "y",
                                          "package": "shiny-new"})
    info = NpmClient().lookup("shiny-new")
    assert info.downloads == 12 and info.downloads_period == "weekly"


@responses.activate
def test_network_error():
    assert NpmClient().lookup("anything").error is not None
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\registries\npm.py`:
```python
from __future__ import annotations

import json
from urllib.parse import quote

import requests

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

REGISTRY_URL = "https://registry.npmjs.org/{}"
DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week/{}"
MAX_DOC_BYTES = 2_000_000


class NpmClient(RegistryClient):
    ecosystem = "npm"

    def lookup(self, name: str) -> PackageInfo:
        url = REGISTRY_URL.format(quote(name, safe="@"))
        try:
            r = self._get(url, stream=True)
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
            raw = b""
            for chunk in r.iter_content(65536):
                raw += chunk
                if len(raw) > MAX_DOC_BYTES:
                    r.close()
                    return PackageInfo(exists=True)  # huge doc == long-established
            data = json.loads(raw)
        except (requests.RequestException, json.JSONDecodeError) as e:
            return PackageInfo(exists=False, error=f"npm: {e.__class__.__name__}")
        created = data.get("time", {}).get("created")
        latest = data.get("time", {}).get("modified")
        downloads = None
        if created and age_days(created) < FRESH_DAYS:
            downloads = self._weekly_downloads(name)
        return PackageInfo(exists=True, created=created, latest=latest, downloads=downloads)

    def _weekly_downloads(self, name: str) -> int | None:
        try:
            r = self._get(DOWNLOADS_URL.format(name))
            if r.status_code != 200:
                return None
            return int(r.json().get("downloads", 0))
        except (requests.RequestException, ValueError):
            return None
```

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `feat(registries): npm client (size-capped metadata + downloads API)`

### Task 11: TypeScript adapter (deps, imports, builtins, frameworks)

**Files:**
- Create: `src\auditor\adapters\typescript\__init__.py` (empty), `src\auditor\adapters\typescript\builtins.py`, `src\auditor\adapters\typescript\adapter.py`
- Test: `tests\test_ts_adapter.py`

**Interfaces:**
- Produces: `TypeScriptAdapter()` with `name="typescript"`, `ecosystem="npm"`, `source_globs=(".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")`; `file_language`: `.tsx`/`.jsx` → `"tsx"`, else `"typescript"`; `detect` = `package.json` present; `parse_dependencies` from dependencies/devDependencies/peerDependencies/optionalDependencies (`workspace:`/`file:`/`link:`/`git+`/URL specs ⇒ `skip_registry=True`); `extract_imports` covering `import ... from 'x'`, `export ... from 'x'`, side-effect `import 'x'`, `require('x')`, dynamic `import('x')`; `top_level` = first segment, or first two for `@scope/...`; `is_internal` for relative/absolute paths (extracted as none), node builtins (`builtins.NODE_BUILTINS` + `node:` prefix), tsconfig path aliases; `frameworks` → `["react"]` when react declared, plus `["next"]` when next declared and `app/` or `pages/` exists. `builtins.NODE_BUILTINS: frozenset[str]`.

- [ ] **Step 1: Write the failing tests**

`tests\test_ts_adapter.py`:
```python
import json
from pathlib import Path

from auditor.adapters.typescript.adapter import TypeScriptAdapter
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _prep(tmp_path, adapter):
    files = collect_source_files(tmp_path, adapter)
    for f in files:
        parse_source(f)
    adapter.prepare(tmp_path, files)
    return files


def test_detect_and_deps(tmp_path):
    a = TypeScriptAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "package.json", json.dumps({
        "dependencies": {"react": "^19.0.0", "next": "^16.0.0", "internal-lib": "workspace:*"},
        "devDependencies": {"@types/node": "^24.0.0"},
    }))
    assert a.detect(tmp_path)
    deps = a.parse_dependencies(tmp_path)
    by = {d.name: d for d in deps}
    assert set(by) == {"react", "next", "internal-lib", "@types/node"}
    assert by["internal-lib"].skip_registry is True
    assert by["@types/node"].skip_registry is False


def test_import_extraction_and_locality(tmp_path):
    _mk(tmp_path, "package.json", json.dumps({"dependencies": {"react": "*"}}))
    _mk(tmp_path, "tsconfig.json",
        '{\n  // jsonc comment\n  "compilerOptions": {"paths": {"@app/*": ["./src/*"]},},\n}')
    _mk(tmp_path, "src/main.ts", "\n".join([
        "import fs from 'fs';",
        "import path from 'node:path';",
        "import {x} from 'lodash';",
        "import type {T} from '@types/thing';",
        "import sub from '@scope/pkg/deep';",
        "import local from './util';",
        "import aliased from '@app/other';",
        "export {y} from 'exported-pkg';",
        "const z = require('required-pkg');",
        "const w = import('dynamic-pkg');",
        "import 'side-effect-pkg';",
    ]) + "\n")
    a = TypeScriptAdapter()
    files = _prep(tmp_path, a)
    imps = a.extract_imports(files)
    tops = {i.top_level for i in imps}
    assert {"fs", "node:path", "lodash", "@scope/pkg", "exported-pkg",
            "required-pkg", "dynamic-pkg", "side-effect-pkg"} <= tops
    assert not any(i.top_level in ("./util", "@app/other") for i in imps)  # locals excluded
    by = {i.top_level: i for i in imps}
    assert a.is_internal(by["fs"]) and a.is_internal(by["node:path"])
    assert not a.is_internal(by["lodash"])


def test_scoped_top_level_and_candidates(tmp_path):
    _mk(tmp_path, "package.json", "{}")
    a = TypeScriptAdapter()
    _prep(tmp_path, a)
    from auditor.core.models import ImportRef
    imp = ImportRef(module="@scope/pkg/deep", file="a.ts", line=1, top_level="@scope/pkg")
    assert a.registry_candidates(imp) == ["@scope/pkg"]


def test_frameworks_detection(tmp_path):
    _mk(tmp_path, "package.json", json.dumps({"dependencies": {"react": "*", "next": "*"}}))
    _mk(tmp_path, "app/page.tsx", "export default function Page(){return null}")
    a = TypeScriptAdapter()
    deps = a.parse_dependencies(tmp_path)
    assert set(a.frameworks(tmp_path, deps)) == {"react", "next"}


def test_file_language(tmp_path):
    a = TypeScriptAdapter()
    assert a.file_language(Path("x.tsx")) == "tsx"
    assert a.file_language(Path("x.jsx")) == "tsx"
    assert a.file_language(Path("x.ts")) == "typescript"
    assert a.file_language(Path("x.js")) == "typescript"
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\adapters\typescript\builtins.py`:
```python
# Bare-specifier builtins only. `test`/`sea`/`sqlite` are deliberately ABSENT:
# they are node:-scheme-only on every Node version (nodejs.org docs), and npm
# packages named test/sea/sqlite exist — listing them here masked real registry
# checks. `sys`/`constants` ARE real (deprecated) builtins on node <= 24.
NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads",
    "zlib",
})
```

`src\auditor\adapters\typescript\adapter.py`:
```python
from __future__ import annotations

import json
import re
from pathlib import Path

from auditor.adapters.typescript.builtins import NODE_BUILTINS
from auditor.core.interfaces import LanguageAdapter
from auditor.core.models import DeclaredDep, ImportRef, SourceFile

_SKIP_SPEC = ("workspace:", "file:", "link:", "portal:", "git+", "git:", "github:",
              "http://", "https://")
_IMPORT_QUERY = """
(import_statement source: (string) @src)
(export_statement source: (string) @src)
(call_expression function: (identifier) @fn arguments: (arguments (string) @arg))
(call_expression function: (import) arguments: (arguments (string) @dynarg))
"""


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


class TypeScriptAdapter(LanguageAdapter):
    name = "typescript"
    ecosystem = "npm"
    source_globs = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

    def __init__(self) -> None:
        self._alias_prefixes: tuple[str, ...] = ()
        self._alias_map: tuple[tuple[str, str], ...] = ()   # (import-prefix, project-relative target base)

    def file_language(self, path: Path) -> str:
        return "tsx" if path.suffix.lower() in (".tsx", ".jsx") else "typescript"

    def detect(self, root: Path) -> bool:
        return (root / "package.json").is_file()

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        pkg = root / "package.json"
        try:
            data = json.loads(self._read(pkg))
        except json.JSONDecodeError as e:
            self._manifest_error(pkg, e)
            return []
        out: list[DeclaredDep] = []
        seen: set[str] = set()
        for group in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, spec in (data.get(group) or {}).items():
                if name in seen:
                    continue
                seen.add(name)
                skip = isinstance(spec, str) and spec.startswith(_SKIP_SPEC)
                registry_name = ""
                if isinstance(spec, str) and spec.startswith("npm:"):
                    # alias: "foo": "npm:bar@^1" => import name foo, registry package bar
                    target = spec[4:]
                    cut = target.rfind("@")
                    registry_name = target[:cut] if cut > 0 else target
                out.append(DeclaredDep(name=name, ecosystem="npm", source_file="package.json",
                                       raw=f"{group}: {name}@{spec}", skip_registry=skip,
                                       registry_name=registry_name))
        self._last_declared = out   # cache for prepare()'s framework/graph decisions
        return out

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        self.ensure_grammars()
        self._self_name = ""
        try:
            self._self_name = json.loads(self._read(root / "package.json")).get("name", "")
        except json.JSONDecodeError:
            pass
        paths: dict = {}
        cfg = root / "tsconfig.json"
        for _ in range(2):  # follow local `extends` one level only (documented limit)
            if not cfg.is_file():
                break
            try:
                data = json.loads(_strip_jsonc(self._read(cfg)))
            except json.JSONDecodeError:
                break
            opts = data.get("compilerOptions") or {}
            paths = {**(opts.get("paths") or {}), **paths}
            if "baseUrl" in opts and "__baseUrl__" not in paths:
                paths["__baseUrl__"] = opts["baseUrl"]
            ext = data.get("extends")
            if isinstance(ext, str) and ext.startswith("."):
                cfg = (cfg.parent / ext).with_suffix(".json") \
                    if not ext.endswith(".json") else cfg.parent / ext
            else:
                break
        base_url = paths.pop("__baseUrl__", ".")
        self._alias_prefixes = tuple(
            p for p in (key.removesuffix("*").rstrip("/") for key in paths) if p)
        # Keep the full pattern->target mapping (not just prefixes): "@/*":
        # ["./src/*"] must resolve @/components/Hooky to src/components/Hooky,
        # NOT components/Hooky (fifth-round counterexample). baseUrl prefixes
        # the target. First target of each pattern wins.
        amap: list[tuple[str, str]] = []
        for key, targets in paths.items():
            prefix = key.removesuffix("*").rstrip("/")
            if not prefix or not targets:
                continue
            target = targets[0] if isinstance(targets, list) else targets
            target_base = target.removesuffix("*").lstrip("./").rstrip("/")
            if base_url not in (".", "", None):
                target_base = f"{base_url.strip('./').rstrip('/')}/{target_base}".strip("/")
            amap.append((prefix, target_base))
        self._alias_map = tuple(amap)

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, line_of, node_text, parse_source
        out: list[ImportRef] = []
        for sf in files:
            parse_source(sf)
            caps = captures(sf.language, sf.tree.root_node, _IMPORT_QUERY)
            for key in ("src", "dynarg"):
                for node in caps.get(key, []):
                    out.append(self._ref(node, sf.rel))
            for node in caps.get("arg", []):
                call = node.parent.parent  # string -> arguments -> call_expression
                fn = call.child_by_field_name("function")
                if fn is not None and fn.type == "identifier" and node_text(fn) == "require":
                    out.append(self._ref(node, sf.rel))
        return [r for r in out if r is not None]

    def _ref(self, string_node, rel: str) -> ImportRef | None:
        from auditor.core.treesitter import line_of, node_text
        spec = node_text(string_node).strip("'\"`")
        if not spec or spec.startswith((".", "/", "#")):
            return None  # relative, absolute, or package-private "#x" subpath import
        parts = spec.split("/")
        top = "/".join(parts[:2]) if spec.startswith("@") and len(parts) >= 2 else parts[0]
        return ImportRef(module=spec, file=rel, line=line_of(string_node), top_level=top)

    def is_internal(self, imp: ImportRef) -> bool:
        top = imp.top_level
        if top.startswith("node:") or top in NODE_BUILTINS:
            return True
        if self._self_name and top == self._self_name:
            return True   # package self-reference (imports its own name)
        return any(imp.module == p or imp.module.startswith(p + "/") or top == p
                   for p in self._alias_prefixes)

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        return next((d for d in declared if d.name == imp.top_level), None)

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        return [imp.top_level]

    def frameworks(self, root: Path, declared: list[DeclaredDep]) -> list[str]:
        names = {d.name for d in declared}
        fws: list[str] = []
        if "react" in names:
            fws.append("react")
        if "next" in names and ((root / "app").is_dir() or (root / "pages").is_dir()):
            fws.append("next")
        return fws

    def grammars(self) -> dict[str, object]:
        import tree_sitter_typescript
        return {"typescript": tree_sitter_typescript.language_typescript(),
                "tsx": tree_sitter_typescript.language_tsx()}

    def syntax(self):
        from auditor.core.interfaces import SyntaxProfile
        return SyntaxProfile(
            catch_query="(catch_clause) @c",
            sql_concat_query="(binary_expression) @n",
            sql_interp_query="(template_string) @n",
            sql_dynamic_types=("template_substitution",),
        )

    def private_registry_reason(self, root: Path) -> str | None:
        npmrc = root / ".npmrc"
        if npmrc.is_file():
            text = self._read(npmrc)
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("registry=") or \
                        (stripped.startswith("@") and ":registry=" in stripped):
                    return "custom registry configured in .npmrc"
        return None
```

- [ ] **Step 4: Run — PASS.** Note the `require`-detection detail: the query captures every `identifier(...)` call with a string argument; the code then re-reads the call's `function` field and keeps only `require` (never compare tree-sitter Node objects by `id()` — wrappers are not identity-stable).
- [ ] **Step 5: Commit** — `feat(typescript): adapter with tsx/jsx handling, node builtins, tsconfig aliases, framework detection`

### Task 12: React rules — hooks placement (R001, R002, R003)

**Files:**
- Create: `src\auditor\adapters\typescript\react_rules.py` (helpers + first three rules)
- Test: `tests\test_react_rules.py`

**Interfaces:**
- Consumes: `Rule`, `SourceFile`, treesitter helpers
- Produces: module-level helpers reused by T13/T14: `is_hook_name(name) -> bool` (`^use[A-Z]`), `enclosing_functions(node) -> list[Node]` (innermost-first chain of `function_declaration|function_expression|arrow_function|method_definition|generator_function|generator_function_declaration`), `function_name(fn_node) -> str` (name field, or variable_declarator/property parent, else `""`), `hook_calls(sf) -> list[tuple[Node, str]]` (call nodes whose callee is a bare `use[A-Z]...` identifier); rule classes `HookInConditional` (R001), `HookInNestedCallback` (R002), `HookOutsideComponent` (R003); `REACT_RULES: list[Rule]` accumulating this task's rules (T13 extends it). All three rules have `frameworks=("react",)`.

- [ ] **Step 1: Write the failing tests**

`tests\test_react_rules.py`:
```python
from pathlib import Path

from auditor.adapters.typescript.react_rules import (HookInConditional,
                                                     HookInNestedCallback,
                                                     HookOutsideComponent)
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(code: str) -> SourceFile:
    sf = SourceFile(path=Path("C.tsx"), rel="C.tsx", language="tsx",
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


GOOD = """
import {useState, useEffect} from 'react';
export function Widget({q}: {q: string}) {
  const [v, setV] = useState(0);
  useEffect(() => { console.log(q); }, [q]);
  return <div>{v}</div>;
}
"""

def test_clean_component_no_findings():
    sf = _sf(GOOD)
    for rule in (HookInConditional(), HookInNestedCallback(), HookOutsideComponent()):
        assert rule.check(sf) == [], rule.id


def test_r001_hook_in_if_and_loop_and_ternary():
    sf = _sf("""
export function Bad({flag}: {flag: boolean}) {
  if (flag) { const [a] = useState(1); }
  for (let i = 0; i < 2; i++) { useEffect(() => {}); }
  const v = flag ? useMemo(() => 1, []) : 0;
  return <p>{v}</p>;
}
""")
    fs = HookInConditional().check(sf)
    assert len(fs) == 3 and all(f.rule_id == "R001" for f in fs)


def test_r002_hook_inside_hook_callback():
    sf = _sf("""
export function Bad() {
  useEffect(() => { const [x] = useState(0); }, []);
  return null;
}
""")
    fs = HookInNestedCallback().check(sf)
    assert [f.rule_id for f in fs] == ["R002"]
    assert "useState" in fs[0].snippet


def test_r003_hook_in_plain_function():
    sf = _sf("""
function loadData() {
  const [d] = useState(null);
  return d;
}
""")
    fs = HookOutsideComponent().check(sf)
    assert [f.rule_id for f in fs] == ["R003"]


def test_r003_hook_in_event_handler_arrow():
    sf = _sf("""
export function Btn() {
  return <button onClick={() => { const [v] = useState(0); }}>x</button>;
}
""")
    fs = HookOutsideComponent().check(sf)
    assert [f.rule_id for f in fs] == ["R003"]
    assert "anonymous callback" in fs[0].detail


def test_r003_memo_and_forwardref_wrapped_components_are_legal():
    for code in (
        "const Btn = memo(() => { const [v] = useState(0); return <b>{v}</b>; });",
        "const In = forwardRef((props, ref) => { const [v] = useState(0); return <input/>; });",
        "const B = React.memo(() => { const [v] = useState(0); return null; });",
    ):
        assert HookOutsideComponent().check(_sf(code)) == [], code


def test_r001_early_return_ignores_returns_inside_prior_callbacks():
    sf = _sf("""
export function C({x}: {x: boolean}) {
  if (x) { run(() => { return 1; }); }
  const items = list.filter(i => { return i > 1; });
  const [v] = useState(0);
  return <p>{v}</p>;
}
""")
    assert HookInConditional().check(sf) == []


def test_r001_logical_and_short_circuit():
    sf = _sf("""
export function C({flag}: {flag: boolean}) {
  const v = flag && useMemo(() => 1, []);
  return <p>{v}</p>;
}
""")
    assert [f.rule_id for f in HookInConditional().check(sf)] == ["R001"]


def test_r001_hook_after_early_return():
    sf = _sf("""
export function C({x}: {x: boolean}) {
  if (x) return null;
  const [v] = useState(0);
  return <p>{v}</p>;
}
""")
    fs = HookInConditional().check(sf)
    assert [f.rule_id for f in fs] == ["R001"]
    assert "early return" in fs[0].detail


def test_r003_allows_custom_hooks():
    sf = _sf("""
function useThing() {
  const [d] = useState(null);
  return d;
}
""")
    assert HookOutsideComponent().check(sf) == []
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\adapters\typescript\react_rules.py`:
```python
from __future__ import annotations

import re

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_HOOK_RE = re.compile(r"^use[A-Z]")
_FUNC_TYPES = frozenset({
    "function_declaration", "function_expression", "arrow_function",
    "method_definition", "generator_function", "generator_function_declaration",
})
_CONTROL_TYPES = frozenset({
    "if_statement", "for_statement", "for_in_statement", "while_statement",
    "do_statement", "switch_statement", "ternary_expression", "try_statement",
    "catch_clause",
})
_LOGICAL_OPS = frozenset({"&&", "||", "??"})
_CALL_QUERY = "(call_expression function: (identifier) @callee)"


def _is_conditional_ancestor(node) -> bool:
    """Control-flow node, including short-circuit logic (`cond && useX()`),
    which the TSX grammar represents as binary_expression."""
    if node.type in _CONTROL_TYPES:
        return True
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        return op is not None and node_text(op) in _LOGICAL_OPS
    return False


def _has_earlier_return(call, boundary) -> bool:
    """Heuristic (corpus-proven FN otherwise): does any statement BEFORE the
    hook call, at any block level inside the enclosing function, contain a
    return? Catches `if (x) return null; ... useState()`. The walk NEVER
    descends into nested functions — second-round review proved that a
    `return` inside a prior callback (`if (x) { run(() => { return 1; }) }`)
    is otherwise falsely flagged (4/4 cases pass with this boundary)."""
    cur = call
    while cur is not None and cur is not boundary:
        parent = cur.parent
        if parent is not None and parent.type == "statement_block":
            for sibling in parent.named_children:
                if sibling == cur:
                    break
                if sibling.type == "return_statement":
                    return True
                if sibling.type == "if_statement" and any(
                        n.type == "return_statement"
                        for n in _walk_no_functions(sibling)):
                    return True
        cur = parent
    return False


def _walk_no_functions(node):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(c for c in cur.named_children if c.type not in _FUNC_TYPES)


def is_hook_name(name: str) -> bool:
    return bool(_HOOK_RE.match(name))


def enclosing_functions(node) -> list:
    chain = []
    cur = node.parent
    while cur is not None:
        if cur.type in _FUNC_TYPES:
            chain.append(cur)
        cur = cur.parent
    return chain


def function_name(fn_node) -> str:
    name = fn_node.child_by_field_name("name")
    if name is not None:
        return node_text(name)
    parent = fn_node.parent
    if parent is not None and parent.type == "variable_declarator":
        ident = parent.child_by_field_name("name")
        if ident is not None:
            return node_text(ident)
    if parent is not None and parent.type == "pair":
        key = parent.child_by_field_name("key")
        if key is not None:
            return node_text(key)
    return ""


def hook_calls(sf: SourceFile) -> list[tuple[object, str]]:
    out = []
    for callee in captures(sf.language, sf.tree.root_node, _CALL_QUERY).get("callee", []):
        name = node_text(callee)
        if is_hook_name(name):
            out.append((callee.parent, name))  # call_expression node
    return out


def _finding(rule: Rule, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule.id, severity=rule.severity, title=rule.title,
                   file=sf.rel, line=line_of(node), snippet=node_text(node)[:120],
                   detail=detail, language=sf.language, engine="auditor",
                   precision=rule.precision)


class HookInConditional(Rule):
    id = "R001"
    severity = Severity.RED
    title = "React hook called conditionally (if/loop/ternary/logical/try, or after early return)"
    frameworks = ("react",)
    precision = "heuristic"   # the early-return part is sibling-scan, not CFG
    # Intentional divergence, documented: hooks inside try/catch ARE flagged here.
    # eslint-plugin-react-hooks 7.1.1 stays silent on try/catch (corpus-verified),
    # but react.dev/reference/rules/rules-of-hooks explicitly forbids it.

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            boundary = fns[0] if fns else None
            cur = call.parent
            flagged = False
            while cur is not None and cur is not boundary:
                if _is_conditional_ancestor(cur):
                    out.append(_finding(self, sf, call,
                                        f"{name} is called inside a {cur.type.replace('_', ' ')}; "
                                        "hooks must run unconditionally at the top level."))
                    flagged = True
                    break
                cur = cur.parent
            if not flagged and boundary is not None and _has_earlier_return(call, boundary):
                out.append(_finding(self, sf, call,
                                    f"{name} is called after a possible early return; hooks "
                                    "must run on every render (heuristic sibling-scan)."))
        return out


class HookInNestedCallback(Rule):
    id = "R002"
    severity = Severity.RED
    title = "React hook called inside a callback argument of another hook"
    frameworks = ("react",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            if not fns:
                continue
            inner = fns[0]
            args = inner.parent  # arrow passed directly as an argument?
            if args is not None and args.type == "arguments":
                outer_call = args.parent
                callee = outer_call.child_by_field_name("function")
                if callee is not None and callee.type == "identifier" \
                        and is_hook_name(node_text(callee)):
                    out.append(_finding(self, sf, call,
                                        f"{name} runs inside the callback of "
                                        f"{node_text(callee)}; move it to component top level."))
        return out


class HookOutsideComponent(Rule):
    id = "R003"
    severity = Severity.YELLOW
    title = "Hook call in a non-component, non-hook function"
    frameworks = ("react",)
    # v2: judge the INNERMOST enclosing function (corpus FN class: hooks inside
    # event-handler arrows, .map callbacks, promise callbacks were invisible when
    # we skipped anonymous functions and accepted the outer Capitalized component).

    # Second-round review, empirically verified (7/7): an arrow passed to
    # memo/forwardRef IS the component body — without this exemption the rule
    # false-flags every `const Btn = memo(() => ...)`.
    _COMPONENT_WRAPPERS = frozenset({"memo", "forwardRef", "React.memo", "React.forwardRef"})

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            fns = enclosing_functions(call)
            if not fns:
                continue
            inner = fns[0]
            inner_name = function_name(inner)
            if inner_name and (inner_name[0].isupper() or is_hook_name(inner_name)):
                continue  # component body or custom hook — legal
            wrapper = self._wrapping_callee(inner)
            if wrapper is not None and is_hook_name(wrapper):
                continue  # `useEffect(() => useX())` — R002 owns that case
            if wrapper in self._COMPONENT_WRAPPERS:
                continue  # memo/forwardRef-wrapped component body — legal
            where = f"'{inner_name}'" if inner_name else "an anonymous callback"
            out.append(_finding(self, sf, call,
                                f"{name} is called from {where}, which is neither a "
                                "component (Capitalized) nor a custom hook (use*); hooks "
                                "cannot run inside event handlers or nested callbacks."))
        return out

    @staticmethod
    def _wrapping_callee(fn_node) -> str | None:
        """Callee name of the call this function is a DIRECT argument of."""
        args = fn_node.parent
        if args is None or args.type != "arguments":
            return None
        callee = args.parent.child_by_field_name("function")
        return node_text(callee) if callee is not None else None


REACT_RULES: list[Rule] = [HookInConditional(), HookInNestedCallback(), HookOutsideComponent()]
```

- [ ] **Step 4: Run — PASS.** Nuance verified by the tests: R002 only fires when the hook's *innermost* enclosing function is itself a direct argument of a hook call (so `useEffect(() => setV(1))` stays clean, `useEffect(() => useState())` fires).
- [ ] **Step 5: Commit** — `feat(react): rules-of-hooks placement rules R001-R003`

### Task 13: React rules — useEffect deps, key={index}, dangerouslySetInnerHTML (R004–R007)

**Files:**
- Modify: `src\auditor\adapters\typescript\react_rules.py` (append rules, extend `REACT_RULES`)
- Test: append to `tests\test_react_rules.py`

**Interfaces:**
- Consumes: helpers from T12 (`hook_calls`, `enclosing_functions`, `_finding`, `captures`, `node_text`, `line_of`)
- Produces: `EffectDeps` (R004+R005), `IndexAsKey` (R006), `DangerousInnerHtml` (R007); `REACT_RULES` now holds 6 rule instances. R005 heuristic (conservative by spec): only names that are (a) `useState` first-elements or destructured props of the enclosing component and (b) referenced in the callback body and (c) absent from the deps array (compared as root identifiers).

- [ ] **Step 1: Write the failing tests** (append)

```python
from auditor.adapters.typescript.react_rules import (REACT_RULES, DangerousInnerHtml,
                                                     EffectDeps, IndexAsKey)


def test_r004_useeffect_without_deps_array():
    sf = _sf("""
export function C() {
  useEffect(() => { document.title = 'x'; });
  return null;
}
""")
    fs = EffectDeps().check(sf)
    assert [f.rule_id for f in fs] == ["R004"]


def test_r005_obviously_missing_dep():
    sf = _sf("""
export function C({q}: {q: string}) {
  const [n, setN] = useState(0);
  useEffect(() => { console.log(q, n); }, [q]);
  return null;
}
""")
    fs = EffectDeps().check(sf)
    assert [f.rule_id for f in fs] == ["R005"]
    assert "n" in fs[0].detail


def test_r005_complete_deps_are_clean():
    sf = _sf("""
export function C({q}: {q: string}) {
  const [n] = useState(0);
  useEffect(() => { console.log(q, n); }, [q, n]);
  return null;
}
""")
    assert EffectDeps().check(sf) == []


def test_r006_index_key():
    sf = _sf("""
export function L({items}: {items: string[]}) {
  return <ul>{items.map((item, index) => <li key={index}>{item}</li>)}</ul>;
}
""")
    fs = IndexAsKey().check(sf)
    assert [f.rule_id for f in fs] == ["R006"]


def test_r006_stable_key_clean():
    sf = _sf("""
export function L({items}: {items: {id: string}[]}) {
  return <ul>{items.map((item) => <li key={item.id}>x</li>)}</ul>;
}
""")
    assert IndexAsKey().check(sf) == []


def test_r007_dangerous_html():
    sf = _sf("""
export function D({html}: {html: string}) {
  return <div dangerouslySetInnerHTML={{__html: html}} />;
}
""")
    fs = DangerousInnerHtml().check(sf)
    assert [f.rule_id for f in fs] == ["R007"]


def test_r007_literal_html_clean():
    sf = _sf("""
export function D() {
  return <div dangerouslySetInnerHTML={{__html: "<b>hi</b>"}} />;
}
""")
    assert DangerousInnerHtml().check(sf) == []


def test_r005_ignores_state_declared_inside_callback():
    sf = _sf("""
export function C() {
  useEffect(() => { const [x] = useState(0); console.log(x); }, []);
  return null;
}
""")
    assert [f.rule_id for f in EffectDeps().check(sf)] == []


def test_react_rules_registry_has_six():
    assert len(REACT_RULES) == 6
```

- [ ] **Step 2: Run — fail** (ImportError on new names).

- [ ] **Step 3: Implement** (append to `react_rules.py`)

```python
_EFFECT_NAMES = frozenset({"useEffect", "useLayoutEffect"})
_IDENT_QUERY = "(identifier) @id"
_JSX_ATTR_QUERY = "(jsx_attribute (property_identifier) @name)"
_GLOBALS = frozenset({
    "console", "window", "document", "Math", "JSON", "Object", "Array",
    "Promise", "fetch", "localStorage", "setTimeout", "setInterval",
    "clearTimeout", "clearInterval", "undefined", "NaN", "Infinity",
})


def _component_reactive_names(fn_node, lang: str, exclude=None) -> set[str]:
    """useState firsts + destructured props of the component function.
    `exclude`: subtree to ignore (the effect callback itself) — corpus-proven FP:
    a useState declared INSIDE the callback is not a missing dependency."""
    def _inside_exclude(node) -> bool:
        return exclude is not None and \
            node.start_byte >= exclude.start_byte and node.end_byte <= exclude.end_byte

    names: set[str] = set()
    params = fn_node.child_by_field_name("parameters")
    if params is not None:
        for pat in captures(lang, params, "(shorthand_property_identifier_pattern) @p").get("p", []):
            names.add(node_text(pat))
    for decl in captures(lang, fn_node, "(variable_declarator) @d").get("d", []):
        if _inside_exclude(decl):
            continue
        value = decl.child_by_field_name("value")
        name = decl.child_by_field_name("name")
        if value is None or name is None or value.type != "call_expression":
            continue
        callee = value.child_by_field_name("function")
        if callee is not None and node_text(callee) == "useState" and name.type == "array_pattern":
            idents = [c for c in name.named_children if c.type == "identifier"]
            if idents:
                names.add(node_text(idents[0]))
    return names


class EffectDeps(Rule):
    id = "R004"  # emits R004 and R005
    severity = Severity.YELLOW
    title = "useEffect dependency-array problems"
    frameworks = ("react",)
    precision = "heuristic"
    # R004 intentionally diverges from exhaustive-deps (which ignores a missing
    # deps argument BY DESIGN): the project spec explicitly requires flagging
    # useEffect without a dependency array. Yellow, never red.

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call, name in hook_calls(sf):
            if name not in _EFFECT_NAMES:
                continue
            args = call.child_by_field_name("arguments")
            arg_nodes = [] if args is None else args.named_children
            if not arg_nodes:
                continue
            callback = arg_nodes[0]
            if len(arg_nodes) < 2:
                f = _finding(self, sf, call,
                             f"{name} has no dependency array; it re-runs after every render.")
                out.append(Finding(**{**f.__dict__, "rule_id": "R004",
                                      "title": "useEffect without dependency array"}))
                continue
            deps_node = arg_nodes[1]
            if deps_node.type != "array":
                continue
            deps = {node_text(c) for c in deps_node.named_children if c.type == "identifier"}
            fns = enclosing_functions(call)
            component = fns[-1] if fns else None
            if component is None:
                continue
            reactive = _component_reactive_names(component, sf.language, exclude=callback)
            used = {node_text(n) for n in
                    captures(sf.language, callback, _IDENT_QUERY).get("id", [])}
            missing = sorted((used & reactive) - deps - _GLOBALS)
            if missing:
                f = _finding(self, sf, call,
                             f"{name} reads {', '.join(missing)} but its dependency array "
                             f"only lists [{', '.join(sorted(deps))}].")
                out.append(Finding(**{**f.__dict__, "rule_id": "R005",
                                      "title": "useEffect with obviously missing dependencies"}))
        return out


class IndexAsKey(Rule):
    id = "R006"
    severity = Severity.YELLOW
    title = "List key uses array index"
    frameworks = ("react",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for attr_name in captures(sf.language, sf.tree.root_node, _JSX_ATTR_QUERY).get("name", []):
            if node_text(attr_name) != "key":
                continue
            attr = attr_name.parent
            expr = next((c for c in attr.named_children if c.type == "jsx_expression"), None)
            if expr is None or not expr.named_children:
                continue
            value = expr.named_children[0]
            if value.type != "identifier":
                continue
            key_name = node_text(value)
            map_param = self._second_map_param(attr)
            if key_name == map_param or (map_param is None and key_name in ("index", "i", "idx")):
                out.append(_finding(self, sf, attr,
                                    f"key={{{key_name}}} is the .map() index; reordering or "
                                    "deleting items will confuse React reconciliation."))
        return out

    @staticmethod
    def _second_map_param(node) -> str | None:
        cur = node.parent
        while cur is not None:
            if cur.type in ("arrow_function", "function_expression"):
                call = cur.parent
                if call is not None and call.type == "arguments":
                    call = call.parent
                if call is not None and call.type == "call_expression":
                    callee = call.child_by_field_name("function")
                    if callee is not None and callee.type == "member_expression":
                        prop = callee.child_by_field_name("property")
                        if prop is not None and node_text(prop) == "map":
                            params = cur.child_by_field_name("parameters")
                            if params is not None:
                                idents = [c for c in params.named_children
                                          if c.type in ("identifier", "required_parameter")]
                                names = []
                                for p in idents:
                                    names.append(node_text(p.child_by_field_name("pattern"))
                                                 if p.type == "required_parameter" else node_text(p))
                                if len(names) >= 2:
                                    return names[1]
            cur = cur.parent
        return None


class DangerousInnerHtml(Rule):
    id = "R007"
    severity = Severity.RED
    title = "dangerouslySetInnerHTML with non-literal value"
    frameworks = ("react",)

    _LITERAL_TYPES = frozenset({"string", "template_string", "number"})

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for attr_name in captures(sf.language, sf.tree.root_node, _JSX_ATTR_QUERY).get("name", []):
            if node_text(attr_name) != "dangerouslySetInnerHTML":
                continue
            attr = attr_name.parent
            html_value = None
            for pair in captures(sf.language, attr, "(pair) @p").get("p", []):
                key = pair.child_by_field_name("key")
                if key is not None and node_text(key) == "__html":
                    html_value = pair.child_by_field_name("value")
            if html_value is None:
                continue
            if html_value.type in self._LITERAL_TYPES and \
                    not captures(sf.language, html_value, "(template_substitution) @s").get("s"):
                continue  # constant string — not an injection vector
            out.append(_finding(self, sf, attr,
                                "__html receives a non-literal value; any user-influenced "
                                "content here is an XSS vector."))
        return out


REACT_RULES.extend([EffectDeps(), IndexAsKey(), DangerousInnerHtml()])
```
Implementation note: `Finding` is frozen, so re-labeling R004/R005 goes through reconstruction (`Finding(**{**f.__dict__, ...})`) — this is intentional and shown above.

- [ ] **Step 4: Run `tests\test_react_rules.py` — PASS (13 tests).**
- [ ] **Step 5: Commit** — `feat(react): effect-deps, index-key and dangerouslySetInnerHTML rules R004-R007`

### Task 14: Next.js rules (N001–N005) + TS fixture repo + Phase-4 E2E

**Files:**
- Create: `src\auditor\adapters\typescript\next_rules.py`, `src\auditor\adapters\typescript\next_graph.py`
- Create fixtures: `tests\fixtures\ts_repo\package.json`, `tsconfig.json`, `.env.local`, `app\page.tsx`, `components\Widget.tsx`, `lib\db.ts`
- Modify: `src\auditor\adapters\typescript\adapter.py` — `language_rules()` (graph-aware), `project_rules()` (env scan + graph findings), `prepare()` (graph build)
- Test: `tests\test_next_rules.py`, `tests\test_next_graph.py`, append E2E to `tests\test_ts_adapter.py`

**Interfaces:**
- Produces: `NEXT_RULES: list[Rule]` = `[PublicEnvSecret(), PrivateEnvInClient(), ClientApiInServerComponent(), ServerImportInClient(), AsyncClientComponent()]`, all with `frameworks=("next",)` except `PublicEnvSecret` which also scans `.env*` (Engine 2 passes only source files, so `PublicEnvSecret.check` handles code; env-file scanning is a module function `scan_env_files(root) -> list[Finding]` called by the pattern engine in T21 — signature: takes project root, reads `.env*` files itself).
- Semantics (from RESEARCH.md §6): "use client" = first statement is the string `"use client"`. Server-component checks (N003) apply only to files under `app/` WITHOUT the directive; client checks (N004, N005) to files WITH it. Sensitive-name tokens: `SECRET`, `PRIVATE`, `PASSWORD`, `TOKEN`, `SERVICE_ROLE`, `ACCESS_KEY`, `API_KEY`, `APIKEY` — minus names containing `PUBLIC_KEY`/`PUBLISHABLE`.

- [ ] **Step 1: Write the failing tests**

`tests\test_next_rules.py`:
```python
from pathlib import Path

from auditor.adapters.typescript.next_rules import (NEXT_RULES,
                                                    AsyncClientComponent,
                                                    ClientApiInServerComponent,
                                                    PrivateEnvInClient,
                                                    PublicEnvSecret,
                                                    ServerImportInClient,
                                                    scan_env_files)
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(code: str, rel: str = "app/page.tsx") -> SourceFile:
    sf = SourceFile(path=Path(rel), rel=rel, language="tsx", text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def test_n001_public_secret_in_code():
    sf = _sf("const k = process.env.NEXT_PUBLIC_API_SECRET;")
    assert [f.rule_id for f in PublicEnvSecret().check(sf)] == ["N001"]


def test_n001_publishable_key_is_fine():
    sf = _sf("const k = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;")
    assert PublicEnvSecret().check(sf) == []


def test_n001_env_file_scan(tmp_path):
    (tmp_path / ".env.local").write_text(
        "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE=abc123\nNEXT_PUBLIC_APP_NAME=demo\n",
        encoding="utf-8")
    fs = scan_env_files(tmp_path)
    assert [f.rule_id for f in fs] == ["N001"] and ".env.local" in fs[0].file


def test_n002_private_env_in_client_file():
    sf = _sf('"use client";\nconst k = process.env.DATABASE_URL;\n')
    assert [f.rule_id for f in PrivateEnvInClient().check(sf)] == ["N002"]
    server = _sf("const k = process.env.DATABASE_URL;")  # no directive => server, fine
    assert PrivateEnvInClient().check(server) == []


def test_n003_hooks_in_server_component():
    sf = _sf("import {useState} from 'react';\n"
             "export default function Page() {\n"
             "  const [v] = useState(0);\n"
             "  return <button onClick={() => alert(v)}>x</button>;\n"
             "}\n")
    ids = [f.rule_id for f in ClientApiInServerComponent().check(sf)]
    assert ids.count("N003") == 2  # useState + onClick


def test_n003_ignores_files_outside_app_dir():
    sf = _sf("const v = useState(0);", rel="components/Widget.tsx")
    assert ClientApiInServerComponent().check(sf) == []


def test_n004_server_import_in_client():
    sf = _sf('"use client";\nimport fs from "fs";\nimport {cookies} from "next/headers";\n',
             rel="components/W.tsx")
    assert [f.rule_id for f in ServerImportInClient().check(sf)] == ["N004", "N004"]


def test_n005_async_client_component():
    sf = _sf('"use client";\nexport default async function Page() { return <div/>; }\n',
             rel="components/P.tsx")
    assert [f.rule_id for f in AsyncClientComponent().check(sf)] == ["N005"]


def test_next_rules_registry():
    assert len(NEXT_RULES) == 5
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\adapters\typescript\next_rules.py`:
```python
from __future__ import annotations

import re
from pathlib import Path

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text
from auditor.adapters.typescript.react_rules import (_finding, enclosing_functions,
                                                     hook_calls)

_SENSITIVE = re.compile(r"(SECRET|PRIVATE|PASSWORD|TOKEN|SERVICE_ROLE|ACCESS_KEY|API_?KEY)",
                        re.I)
_SAFE = re.compile(r"(PUBLIC_KEY|PUBLISHABLE)", re.I)
_ENV_MEMBER_QUERY = "(member_expression) @m"
_KNOWN_HOOKS = frozenset({
    "useState", "useEffect", "useLayoutEffect", "useReducer", "useRef",
    "useCallback", "useMemo", "useContext", "useTransition", "useDeferredValue",
    "useOptimistic", "useSyncExternalStore", "useImperativeHandle",
    "useInsertionEffect",
})
_SERVER_ONLY_IMPORTS = frozenset({
    "fs", "node:fs", "fs/promises", "child_process", "node:child_process",
    "net", "node:net", "server-only", "next/headers",
})
_SAFE_CLIENT_ENVS = frozenset({"NODE_ENV", "NEXT_RUNTIME"})


def has_use_client(sf: SourceFile) -> bool:
    for child in sf.tree.root_node.named_children[:3]:
        if child.type == "expression_statement" and child.named_children \
                and child.named_children[0].type == "string":
            if node_text(child.named_children[0]).strip("'\"") == "use client":
                return True
    return False


def _env_reads(sf: SourceFile) -> list[tuple[object, str]]:
    out = []
    for m in captures(sf.language, sf.tree.root_node, _ENV_MEMBER_QUERY).get("m", []):
        text = node_text(m)
        if text.startswith("process.env.") and text.count(".") == 2:
            out.append((m, text.rsplit(".", 1)[1]))
    return out


class PublicEnvSecret(Rule):
    id = "N001"
    severity = Severity.RED
    title = "NEXT_PUBLIC_ variable with secret-like name (exposed to client bundle)"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for node, var in _env_reads(sf):
            if var.startswith("NEXT_PUBLIC_") and _SENSITIVE.search(var) and not _SAFE.search(var):
                out.append(_finding(self, sf, node,
                                    f"{var} is inlined into the public client bundle at build "
                                    "time; a secret here is exposed to every visitor."))
        return out


def scan_env_files(root: Path) -> list[Finding]:
    from auditor.core.walk import read_text_capped
    rule = PublicEnvSecret()
    out: list[Finding] = []
    for env in sorted(root.glob(".env*")):
        if not env.is_file():
            continue
        for i, line in enumerate(read_text_capped(env).splitlines(), 1):
            name = line.split("=", 1)[0].strip()
            if "=" in line and name.startswith("NEXT_PUBLIC_") \
                    and _SENSITIVE.search(name) and not _SAFE.search(name):
                out.append(Finding(rule_id="N001", severity=Severity.RED, title=rule.title,
                                   file=env.name, line=i, snippet=name + "=***",
                                   detail=f"{name} in {env.name} ships to the client bundle.",
                                   language="typescript", engine="auditor"))
    return out


class PrivateEnvInClient(Rule):
    id = "N002"
    severity = Severity.YELLOW
    title = "Non-NEXT_PUBLIC env read in a Client Component (empty at runtime)"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        if not has_use_client(sf):
            return []
        out = []
        for node, var in _env_reads(sf):
            if not var.startswith("NEXT_PUBLIC_") and var not in _SAFE_CLIENT_ENVS:
                out.append(_finding(self, sf, node,
                                    f"process.env.{var} is not NEXT_PUBLIC_*; in client code it "
                                    "is replaced by undefined at build time (silent failure)."))
        return out


class ClientApiInServerComponent(Rule):
    id = "N003"
    severity = Severity.RED
    title = "Client-only API used in a Server Component (missing \"use client\")"
    frameworks = ("next",)
    precision = "heuristic"   # per-file fallback; superseded by the N006 graph pass

    _EVENT_ATTR = re.compile(r"^on[A-Z]")

    def check(self, sf: SourceFile) -> list[Finding]:
        # per-file fallback ONLY when the graph pass is inactive; app/ or src/app/
        parts = sf.rel.split("/")
        under_app = parts[0] == "app" or (len(parts) > 1 and parts[0] == "src"
                                          and parts[1] == "app")
        if not under_app or has_use_client(sf):
            return []
        out = []
        for call, name in hook_calls(sf):
            if name in _KNOWN_HOOKS:
                out.append(_finding(self, sf, call,
                                    f"{name} requires a Client Component; add \"use client\" "
                                    "or move this logic into a client child."))
        for attr in captures(sf.language, sf.tree.root_node,
                             "(jsx_attribute (property_identifier) @n)").get("n", []):
            if self._EVENT_ATTR.match(node_text(attr)):
                out.append(_finding(self, sf, attr.parent,
                                    f"{node_text(attr)} event handlers only work in Client "
                                    "Components; this file has no \"use client\" directive."))
        return out


class ServerImportInClient(Rule):
    id = "N004"
    severity = Severity.RED
    title = "Server-only import inside a Client Component"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        if not has_use_client(sf):
            return []
        out = []
        for src in captures(sf.language, sf.tree.root_node,
                            "(import_statement source: (string) @s)").get("s", []):
            spec = node_text(src).strip("'\"")
            if spec in _SERVER_ONLY_IMPORTS:
                out.append(_finding(self, sf, src.parent,
                                    f"'{spec}' cannot run in the browser; importing it in a "
                                    "\"use client\" file breaks the build or leaks server code."))
        return out


class AsyncClientComponent(Rule):
    id = "N005"
    severity = Severity.YELLOW
    title = "async Client Component"
    frameworks = ("next",)

    def check(self, sf: SourceFile) -> list[Finding]:
        if not has_use_client(sf):
            return []
        out = []
        for fn in captures(sf.language, sf.tree.root_node, "(function_declaration) @f").get("f", []):
            name_node = fn.child_by_field_name("name")
            is_async = any(c.type == "async" for c in fn.children)
            if is_async and name_node is not None and node_text(name_node)[:1].isupper():
                out.append(_finding(self, sf, fn,
                                    f"{node_text(name_node)} is an async Client Component — "
                                    "not supported by React; fetch in a Server Component instead."))
        return out


NEXT_RULES: list[Rule] = [PublicEnvSecret(), PrivateEnvInClient(),
                          ClientApiInServerComponent(), ServerImportInClient(),
                          AsyncClientComponent()]
```

Adapter wiring (env scanning + the N006 graph both flow through `project_rules`, so `core/patterns.py` never imports adapter modules): the SINGLE canonical `language_rules`/`project_rules`/`prepare` additions are in the **N006 integration block below** — do not implement an env-only intermediate version.

**N006 — APPROVED (fourth round): implemented HERE as part of Task 14, no further sign-off gate.**

Create `src\auditor\adapters\typescript\next_graph.py`:
```python
from __future__ import annotations

from pathlib import Path
from posixpath import dirname, join, normpath

from auditor.adapters.typescript.next_rules import (_KNOWN_HOOKS,
                                                    _SAFE_CLIENT_ENVS,
                                                    _SERVER_ONLY_IMPORTS,
                                                    _env_reads, has_use_client)
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

# Official app-router module conventions (nextjs.org/docs/app/api-reference/
# file-conventions, Next 15/16). SUPPORTED render/segment entries (each a graph
# root): page, layout, template, error, global-error, global-not-found, loading,
# not-found, forbidden, unauthorized, default (parallel routes), route (handlers).
# EXCLUDED (documented in report limitations, lowers confidence coverage nothing
# — they are not part of the render module graph): middleware/proxy and
# instrumentation (edge/runtime hooks) and the metadata file conventions
# (sitemap/opengraph-image/icon/robots/manifest — separate code-metadata routes).
_ENTRY_STEMS = frozenset({"page", "layout", "template", "error", "global-error",
                          "global-not-found", "loading", "not-found", "forbidden",
                          "unauthorized", "default", "route"})
_EXTS = (".tsx", ".ts", ".jsx", ".js")


def _under_app(rel: str) -> bool:
    """Next allows both app/ and src/app/ (documented dual layout)."""
    parts = rel.split("/")
    return parts[0] == "app" or (len(parts) > 1 and parts[0] == "src" and parts[1] == "app")


def _is_entry(rel: str) -> bool:
    return _under_app(rel) and Path(rel).stem in _ENTRY_STEMS and Path(rel).suffix in _EXTS
_EDGE_QUERY = """
(import_statement source: (string) @src)
(export_statement source: (string) @src)
(call_expression function: (import) arguments: (arguments (string) @src))
(call_expression function: (identifier) @fn arguments: (arguments (string) @req))
"""
_BROWSER_GLOBALS = frozenset({"window", "document", "localStorage", "navigator"})


def _is_type_only(stmt) -> bool:
    # `import type {X} from` / `export type {X} from` — erased at runtime,
    # never a client/server boundary edge
    return any(c.type == "type" for c in stmt.children)


def _edges(sf: SourceFile) -> list[str]:
    caps = captures(sf.language, sf.tree.root_node, _EDGE_QUERY)
    out: list[str] = []
    for node in caps.get("src", []):
        stmt = node.parent
        while stmt is not None and stmt.type not in ("import_statement",
                                                     "export_statement",
                                                     "call_expression"):
            stmt = stmt.parent
        if stmt is not None and stmt.type in ("import_statement", "export_statement") \
                and _is_type_only(stmt):
            continue
        out.append(node_text(node).strip("'\"`"))
    for node in caps.get("req", []):
        fn = node.parent.parent.child_by_field_name("function")
        if fn is not None and fn.type == "identifier" and node_text(fn) == "require":
            out.append(node_text(node).strip("'\"`"))
    return out


def _resolve(spec: str, from_rel: str, files_by_rel: dict,
             alias_map: tuple[tuple[str, str], ...]) -> str | None:
    if spec.startswith("."):
        base = normpath(join(dirname(from_rel), spec))
    else:
        base = None
        # longest matching alias prefix wins; rebase onto its TARGET, not just
        # strip the prefix — "@/*":["./src/*"] maps @/components/x to
        # src/components/x (fifth-round counterexample)
        for prefix, target_base in sorted(alias_map, key=lambda t: -len(t[0])):
            if spec == prefix or spec.startswith(prefix + "/"):
                rest = spec[len(prefix):].lstrip("/")
                base = f"{target_base}/{rest}".strip("/") if target_base else rest
                break
        if base is None:
            return None          # external package — hallucination engine's job
    if base.split("/")[0] == "..":
        return None              # escapes the project root
    for cand in [base] + [base + e for e in _EXTS] \
            + [join(base, "index" + e) for e in _EXTS]:
        if cand in files_by_rel:
            return cand
    return None                  # unresolved — reported via notes, never guessed


def _n(rule_id: str, sev: Severity, title: str, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule_id, severity=sev, title=title, file=sf.rel,
                   line=line_of(node), snippet=node_text(node)[:120], detail=detail,
                   language=sf.language, engine="auditor", precision="heuristic")


def _server_violations(sf: SourceFile) -> list[Finding]:
    out = []
    for callee in captures(sf.language, sf.tree.root_node,
                           "(call_expression function: (identifier) @c)").get("c", []):
        if node_text(callee) in _KNOWN_HOOKS:
            out.append(_n("N006", Severity.RED,
                          "Client-only API in a module reachable from a Server Component",
                          sf, callee.parent,
                          f"{node_text(callee)} runs in a SERVER import path (module-graph); "
                          "add \"use client\" at the boundary that should own this file."))
    for attr in captures(sf.language, sf.tree.root_node,
                         "(jsx_attribute (property_identifier) @n)").get("n", []):
        name = node_text(attr)
        if len(name) > 2 and name.startswith("on") and name[2].isupper():
            out.append(_n("N006", Severity.RED,
                          "Client-only API in a module reachable from a Server Component",
                          sf, attr.parent,
                          f"{name} event handler in a SERVER import path (module-graph)."))
    for ident in captures(sf.language, sf.tree.root_node, "(identifier) @i").get("i", []):
        if node_text(ident) in _BROWSER_GLOBALS and _is_global_use(ident):
            out.append(_n("N006", Severity.RED,
                          "Client-only API in a module reachable from a Server Component",
                          sf, ident, f"browser global '{node_text(ident)}' in a SERVER path."))
    return out


def _is_global_use(ident) -> bool:
    """A browser global is a real usage as the OBJECT of a member access
    (window.location, document.cookie) or standalone — but NOT a local binding.
    Fifth-round counterexample: the old `parent != member_expression` guard
    excluded exactly `window.location`, the commonest browser-only call."""
    parent = ident.parent
    if parent is None:
        return True
    if parent.type == "member_expression":
        obj = parent.child_by_field_name("object")
        return obj is not None and obj.start_byte == ident.start_byte \
            and obj.end_byte == ident.end_byte      # object side, not the property
    # exclude declarations/params/import bindings named like a global
    return parent.type not in ("variable_declarator", "required_parameter",
                               "formal_parameters", "import_specifier",
                               "shorthand_property_identifier_pattern")


def _client_context_findings(sf: SourceFile) -> list[Finding]:
    """N002/N004/N005 for files that INHERIT client context (no directive of
    their own) — the per-file rules gate on has_use_client and cannot see them."""
    out = []
    for node, var in _env_reads(sf):
        if not var.startswith("NEXT_PUBLIC_") and var not in _SAFE_CLIENT_ENVS:
            out.append(_n("N002", Severity.YELLOW,
                          "Non-NEXT_PUBLIC env read in inherited client context",
                          sf, node,
                          f"process.env.{var} is undefined in the client bundle; this file "
                          "inherits client context through its importer (module-graph)."))
    for src in captures(sf.language, sf.tree.root_node,
                        "(import_statement source: (string) @s)").get("s", []):
        spec = node_text(src).strip("'\"`")
        if spec in _SERVER_ONLY_IMPORTS:
            out.append(_n("N004", Severity.RED,
                          "Server-only import in inherited client context", sf, src.parent,
                          f"'{spec}' cannot run in the browser; this file is pulled into the "
                          "client bundle through its importer."))
    for fn in captures(sf.language, sf.tree.root_node,
                       "(function_declaration) @f").get("f", []):
        name = fn.child_by_field_name("name")
        if name is not None and node_text(name)[:1].isupper() \
                and any(c.type == "async" for c in fn.children):
            out.append(_n("N005", Severity.YELLOW,
                          "async component in inherited client context", sf, fn,
                          f"{node_text(name)} is async in a client-context import path."))
    return out


def analyze(files: list[SourceFile],
            alias_map: tuple[tuple[str, str], ...]) -> tuple[list[Finding], list[str]]:
    """Dual-state BFS over the import graph. BOTH (file, server) and
    (file, client) contexts are explored and reported — a server-path violation
    stands even when a client path also reaches the same file.

    Coverage guarantee (fifth-round): EVERY app/ file is analyzed, so the
    global removal of per-file N003 loses nothing. Files reached from an entry
    inherit their path's context; app/ files NOT reached from any entry (orphans)
    are analyzed as standalone SERVER roots — a Next app/ module renders as a
    Server Component by default unless it declares "use client"."""
    files_by_rel = {sf.rel: sf for sf in files}
    entries = sorted(sf.rel for sf in files if _is_entry(sf.rel))
    notes: list[str] = []
    findings: list[Finding] = []
    visited: set[tuple[str, str]] = set()
    unresolved: list[str] = []

    def _bfs(roots):
        stack = [(r, "server") for r in roots]
        while stack:
            rel, state = stack.pop()
            if (rel, state) in visited:
                continue          # cycle/diamond termination
            visited.add((rel, state))
            sf = files_by_rel[rel]
            out_state = "client" if (state == "client" or has_use_client(sf)) else "server"
            if out_state == "server":
                findings.extend(_server_violations(sf))
            elif not has_use_client(sf):
                findings.extend(_client_context_findings(sf))
            # (files WITH the directive keep their per-file N002/N004/N005 rules)
            for spec in _edges(sf):
                target = _resolve(spec, rel, files_by_rel, alias_map)
                if target is not None:
                    stack.append((target, out_state))
                elif spec.startswith("."):
                    unresolved.append(f"{rel} -> {spec}")

    _bfs(entries)
    reached = {r for r, _ in visited}
    orphans = sorted(sf.rel for sf in files
                     if _under_app(sf.rel) and sf.rel not in reached)
    if orphans:
        _bfs(orphans)            # analyze standalone (server default) — NOT excluded
        notes.append(f"next-graph: {len(orphans)} orphan app/ file(s) not reachable from "
                     f"an entry (first: {orphans[0]}) — analyzed standalone as server default")
    if unresolved:
        notes.append(f"next-graph: {len(unresolved)} unresolved relative edge(s) "
                     f"(first: {unresolved[0]}) — not guessed")
    return findings, notes
```

Integrate in `adapter.py` — append to `prepare()` (AFTER alias/self-name setup) and adjust `language_rules`/`project_rules`:
```python
        # N006 module-graph pass (approved round 4): built here because prepare
        # has files + cached declared deps; per-file N003 is superseded when active
        self._graph_findings, self._graph_notes, self._graph_active = [], [], False
        names = {d.name for d in getattr(self, "_last_declared", []) or []}
        if "next" in names and ((root / "app").is_dir() or (root / "src" / "app").is_dir()):
            from auditor.adapters.typescript.next_graph import analyze
            from auditor.core.treesitter import parse_source
            for sf in files:
                parse_source(sf)
            self._graph_findings, self._graph_notes = analyze(files, self._alias_map)
            self._graph_active = True
            if self._diag is not None:
                self._diag.notes.extend(self._graph_notes)
```
```python
    def language_rules(self):
        from auditor.adapters.typescript.next_rules import NEXT_RULES
        from auditor.adapters.typescript.react_rules import REACT_RULES
        rules = [*REACT_RULES, *NEXT_RULES]
        if getattr(self, "_graph_active", False):
            rules = [r for r in rules if r.id != "N003"]   # graph classification supersedes
        return rules

    def project_rules(self, root: Path, frameworks: list[str]) -> list:
        out = list(getattr(self, "_graph_findings", []))
        if "next" in frameworks:
            from auditor.adapters.typescript.next_rules import scan_env_files
            out += scan_env_files(root)
        return out
```

`tests\test_next_graph.py`:
```python
from pathlib import Path

from auditor.adapters.typescript.next_graph import analyze
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(rel: str, code: str) -> SourceFile:
    sf = SourceFile(path=Path(rel), rel=rel, language="tsx", text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def _run(*files, alias_map=()):
    return analyze(list(files), alias_map=alias_map)


def test_hooky_via_server_path_is_flagged_outside_app():
    page = _sf("app/page.tsx", "import Hooky from '../components/Hooky';\n"
               "export default function Page(){ return <Hooky/>; }")
    hooky = _sf("components/Hooky.tsx",
                "import {useState} from 'react';\n"
                "export default function Hooky(){ const [v] = useState(0); return <b>{v}</b>; }")
    findings, _ = _run(page, hooky)
    assert any(f.rule_id == "N006" and f.file == "components/Hooky.tsx" for f in findings)


def test_leaf_inherited_client_is_clean_but_gets_client_checks():
    page = _sf("app/page.tsx", "import P from '../components/ClientParent';\n"
               "export default function Page(){ return <P/>; }")
    parent = _sf("components/ClientParent.tsx", '"use client";\n'
                 "import Leaf from './Leaf';\n"
                 "export default function P(){ return <Leaf/>; }")
    leaf = _sf("components/Leaf.tsx",
               "import {useState} from 'react';\n"
               "const k = process.env.DATABASE_URL;\n"
               "export default function Leaf(){ const [v] = useState(0); return <i>{v}</i>; }")
    findings, _ = _run(page, parent, leaf)
    leaf_rules = {f.rule_id for f in findings if f.file == "components/Leaf.tsx"}
    assert "N006" not in leaf_rules        # inherited client => hooks are LEGAL
    assert "N002" in leaf_rules            # but private env read is not


def test_inheritance_inside_app_dir_not_the_old_prefix_shortcut():
    page = _sf("app/page.tsx", "import P from './parent';\n"
               "export default function Page(){ return <P/>; }")
    parent = _sf("app/parent.tsx", '"use client";\n'
                 "import Inner from './inner';\n"
                 "export default function P(){ return <Inner/>; }")
    inner = _sf("app/inner.tsx",
                "import {useState} from 'react';\n"
                "export default function I(){ const [v] = useState(0); return <s>{v}</s>; }")
    findings, _ = _run(page, parent, inner)
    assert not any(f.rule_id == "N006" and f.file == "app/inner.tsx" for f in findings)


def test_shared_file_server_violation_stands_despite_client_path():
    p1 = _sf("app/page.tsx", "import S from '../components/Shared';\n"
             "export default function A(){ return <S/>; }")
    p2 = _sf("app/layout.tsx", "import C from '../components/ClientSide';\n"
             "export default function L(){ return <C/>; }")
    client = _sf("components/ClientSide.tsx", '"use client";\n'
                 "import S from './Shared';\n"
                 "export default function C(){ return <S/>; }")
    shared = _sf("components/Shared.tsx",
                 "import {useState} from 'react';\n"
                 "export default function S(){ const [v] = useState(0); return <u>{v}</u>; }")
    findings, _ = _run(p1, p2, client, shared)
    assert any(f.rule_id == "N006" and f.file == "components/Shared.tsx" for f in findings)


def test_type_only_edges_are_not_boundary_edges():
    page = _sf("app/page.tsx", "import type {T} from '../components/Types';\n"
               "export default function Page(){ return null; }")
    types = _sf("components/Types.tsx",
                "import {useState} from 'react';\n"
                "export function useT(){ return useState(0); }\nexport type T = number;")
    findings, _ = _run(page, types)
    assert not any(f.file == "components/Types.tsx" for f in findings)


def test_cycle_terminates_and_orphan_is_noted():
    a = _sf("app/page.tsx", "import B from './b';\nexport default function A(){ return <B/>; }")
    b = _sf("app/b.tsx", "import A from './page';\nexport default function B(){ return null; }")
    orphan = _sf("app/orphan.tsx", "export default function O(){ return null; }")
    findings, notes = _run(a, b, orphan)
    assert any("orphan" in n for n in notes)


def test_src_app_layout_and_alias_target_resolution():
    # fifth-round: src/app entries + "@/*":["./src/*"] must resolve
    # @/components/Hooky to src/components/Hooky (NOT components/Hooky)
    page = _sf("src/app/page.tsx", "import Hooky from '@/components/Hooky';\n"
               "export default function Page(){ return <Hooky/>; }")
    hooky = _sf("src/components/Hooky.tsx",
                "import {useState} from 'react';\n"
                "export default function Hooky(){ const [v] = useState(0); return <b>{v}</b>; }")
    findings, _ = _run(page, hooky, alias_map=(("@", "src"),))
    assert any(f.rule_id == "N006" and f.file == "src/components/Hooky.tsx" for f in findings)


def test_orphan_with_hook_is_flagged_not_dropped():
    # fifth-round: orphan app/ file with a hook and no directive must still be
    # caught — the graph analyzes it standalone as server default (N003 removal
    # would otherwise silently drop it)
    entry = _sf("app/page.tsx", "export default function P(){ return null; }")
    orphan = _sf("app/widget.tsx", "import {useState} from 'react';\n"
                 "export function W(){ const [v] = useState(0); return <i>{v}</i>; }")
    findings, notes = _run(entry, orphan)
    assert any(f.rule_id == "N006" and f.file == "app/widget.tsx" for f in findings)
    assert any("orphan" in n for n in notes)


def test_window_location_in_server_path_is_flagged():
    # fifth-round: window.location is a member_expression; the old
    # parent!=member_expression guard excluded exactly this common case
    page = _sf("app/page.tsx", "import S from '../components/Srv';\n"
               "export default function P(){ return <S/>; }")
    srv = _sf("components/Srv.tsx",
              "export function S(){ const u = window.location.href; return <a>{u}</a>; }")
    findings, _ = _run(page, srv)
    assert any(f.rule_id == "N006" and f.file == "components/Srv.tsx"
               and "window" in f.detail for f in findings)


def test_new_conventions_are_entries():
    from auditor.adapters.typescript.next_graph import _is_entry
    for stem in ("global-not-found", "forbidden", "unauthorized"):
        assert _is_entry(f"app/{stem}.tsx"), stem
    assert _is_entry("src/app/page.tsx")
    assert not _is_entry("app/middleware.ts")   # documented exclusion
```

- [ ] **Step 3b: Run `tests\test_next_graph.py` — PASS (6 tests).** Commit folds into this task's commit.

- [ ] **Step 4: Create the TS fixture repo** (planted bugs referenced by later phases too)

`tests\fixtures\ts_repo\package.json`:
```json
{
  "name": "ts-fixture",
  "dependencies": {
    "react": "^19.0.0",
    "next": "^16.0.0",
    "left-pad-ai-super": "^1.0.0"
  },
  "devDependencies": {
    "@types/node": "^24.0.0"
  }
}
```

`tests\fixtures\ts_repo\tsconfig.json`:
```json
{
  "compilerOptions": {
    "jsx": "preserve",
    "paths": { "@/*": ["./*"] }
  }
}
```

`tests\fixtures\ts_repo\.env.local`:
```
NEXT_PUBLIC_API_SECRET=sk-fixture-not-real
NEXT_PUBLIC_APP_NAME=demo
```

`tests\fixtures\ts_repo\app\page.tsx` (server component misusing client APIs):
```tsx
import { useState } from 'react';

export default function Page() {
  const [count, setCount] = useState(0);
  return <button onClick={() => setCount(count + 1)}>{count}</button>;
}
```

`tests\fixtures\ts_repo\components\Widget.tsx` (client component with hook misuse):
```tsx
"use client";
import { useEffect, useState } from 'react';

export function Widget({ items, html }: { items: string[]; html: string }) {
  const [visible, setVisible] = useState(false);
  if (visible) {
    const [extra] = useState('');
  }
  useEffect(() => {
    setVisible(true);
  });
  return (
    <div dangerouslySetInnerHTML={{ __html: html }}>
      {items.map((item, index) => (
        <span key={index}>{item}</span>
      ))}
    </div>
  );
}
```

`tests\fixtures\ts_repo\lib\db.ts` (import-side plants):
```ts
import fs from 'fs';
import { join } from 'node:path';
import pg from 'pg';
import retryMagic from 'axios-retry-ai';
import { helper } from '@/lib/helper';
import { local } from './local';

export function q(userId: string) {
  return `SELECT * FROM users WHERE id = ${userId}`;
}
```
(Also create `tests\fixtures\ts_repo\lib\helper.ts` and `tests\fixtures\ts_repo\lib\local.ts`, each containing `export const helper = 1;` / `export const local = 1;`.)

- [ ] **Step 5: Append the Phase-4 E2E to `tests\test_ts_adapter.py`**

```python
def test_ts_repo_e2e_hallucinations(fixtures_dir):
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import PackageInfo
    from tests.conftest import FakeRegistry

    root = fixtures_dir / "ts_repo"
    a = TypeScriptAdapter()
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    a.prepare(root, files)
    declared = a.parse_dependencies(root)
    reg = FakeRegistry("npm", {
        "react": PackageInfo(True, created="2013-05-24T00:00:00Z"),
        "next": PackageInfo(True, created="2016-10-05T00:00:00Z"),
        "@types/node": PackageInfo(True, created="2016-03-01T00:00:00Z"),
        "pg": PackageInfo(True, created="2010-10-25T00:00:00Z"),
    })
    findings = audit_hallucinations(a, root, files, declared, reg)
    ids = sorted(f.rule_id for f in findings)
    assert ids == ["H001", "H002", "H008"]   # left-pad-ai-super / pg / axios-retry-ai
    files_by_rule = {f.rule_id: f.file for f in findings}
    assert files_by_rule == {"H001": "package.json", "H002": "lib/db.ts", "H008": "lib/db.ts"}
```
(the `fs`, `node:path` builtins and `@/lib/helper`, `./local` locals must produce nothing — that is the point of the fixture).

- [ ] **Step 6: Run all Phase-4 test files — PASS. Commit** — `feat(next): server/client boundary + env rules N001-N005, TS fixture repo, phase-4 E2E`

**PHASE CHECKPOINT CP-4 — STOP.** Present to the user: TS/React/Next coverage (11 rules), fixture with planted bugs, E2E across adapter+engine. Show `pytest -q` totals and one example finding per rule family (R/N/H) from the fixture.
**Gate:** rule tests include the corpus-derived negatives (custom hook OK, complete deps OK, setter-only effect OK, literal `__html` OK, client-boundary leaf OK, memo/forwardRef-wrapped OK, prior-callback-return OK); builtins/alias/#imports/self-reference covered; **all 6 next-graph tests green** (server-path violation, inherited-client cleanliness inside AND outside app/, shared-file dual-state, type-only edges, cycle+orphan); **the 18-file ESLint corpus re-runs against the implemented rules and the divergence table is reproduced (expected: only the 2 intentional divergences remain)**. **Blockers:** any FP on the legal cases above. **Deferred decisions:** none — N006 was approved in round 4 and is implemented in this task.

---

## PHASE 5 — Java + .NET adapters

### Task 15: Maven Central client (repo1 metadata — NOT solrsearch)

**Files:**
- Create: `src\auditor\registries\maven.py`
- Test: `tests\test_registry_maven.py`

**Interfaces:**
- Produces: `MavenClient(session=None)`, `ecosystem="maven"`; `lookup("group:artifact")`. Existence: `GET https://repo1.maven.org/maven2/{group with dots→slashes}/{artifact}/maven-metadata.xml` (200/404). `latest` from `<lastUpdated>` (`yyyyMMddHHmmss` → ISO). `created`: only when `lastUpdated` is younger than `4*FRESH_DAYS` — `HEAD .../{artifact}/{first-version}/{artifact}-{first-version}.pom`, parse the `Last-Modified` header via `email.utils.parsedate_to_datetime`. `downloads` always `None` (Maven exposes none — documented limitation, surfaces in report limitations). Names without `:` → `PackageInfo(exists=False, error="invalid maven coordinates")`.

- [ ] **Step 1: Write the failing tests**

`tests\test_registry_maven.py`:
```python
from datetime import datetime, timedelta, timezone

import responses

from auditor.registries.maven import MavenClient

META = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/maven-metadata.xml"
OLD_XML = """<metadata>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <versioning>
    <latest>2.22.1</latest>
    <versions><version>2.0.0</version><version>2.22.1</version></versions>
    <lastUpdated>20240708002519</lastUpdated>
  </versioning>
</metadata>"""


@responses.activate
def test_existing_artifact_old_skips_pom_head():
    responses.get(META, body=OLD_XML)
    info = MavenClient().lookup("com.fasterxml.jackson.core:jackson-databind")
    assert info.exists and info.latest.startswith("2024-07-08")
    assert info.created is None and info.downloads is None
    assert len(responses.calls) == 1  # no HEAD for old artifacts


@responses.activate
def test_fresh_artifact_heads_all_poms_and_takes_oldest():
    recent = datetime.now(timezone.utc) - timedelta(days=10)
    older = datetime.now(timezone.utc) - timedelta(days=40)
    xml = OLD_XML.replace("20240708002519", recent.strftime("%Y%m%d%H%M%S"))
    responses.get(META, body=xml)
    base = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind"
    # version-sort != publish-sort: the LIST-first version carries the NEWER date
    responses.head(f"{base}/2.0.0/jackson-databind-2.0.0.pom",
                   headers={"Last-Modified": recent.strftime("%a, %d %b %Y %H:%M:%S GMT")})
    responses.head(f"{base}/2.22.1/jackson-databind-2.22.1.pom",
                   headers={"Last-Modified": older.strftime("%a, %d %b %Y %H:%M:%S GMT")})
    info = MavenClient().lookup("com.fasterxml.jackson.core:jackson-databind")
    assert info.exists and info.created is not None
    assert info.created.startswith(older.date().isoformat())  # min across ALL poms
    assert len(responses.calls) == 3  # metadata + 2 HEADs


@responses.activate
def test_missing_artifact():
    responses.get("https://repo1.maven.org/maven2/com/nope/ghost/maven-metadata.xml", status=404)
    assert MavenClient().lookup("com.nope:ghost").exists is False


def test_invalid_coordinates():
    info = MavenClient().lookup("not-coordinates")
    assert info.exists is False and "coordinates" in info.error
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\registries\maven.py`:
```python
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import defusedxml.ElementTree as ET
import requests
from defusedxml import DefusedXmlException

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

META_URL = "https://repo1.maven.org/maven2/{}/{}/maven-metadata.xml"
POM_URL = "https://repo1.maven.org/maven2/{}/{}/{}/{}-{}.pom"


def _ts_to_iso(ts: str) -> str | None:
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


class MavenClient(RegistryClient):
    ecosystem = "maven"

    def lookup(self, name: str) -> PackageInfo:
        if ":" not in name:
            return PackageInfo(exists=False, error="invalid maven coordinates (need group:artifact)")
        group, artifact = name.split(":", 1)
        gpath = group.replace(".", "/")
        try:
            r = self._get(META_URL.format(gpath, artifact))
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
            root = ET.fromstring(r.text)   # defused: repo1 responses are external input too
        except (requests.RequestException, ET.ParseError, DefusedXmlException) as e:
            return PackageInfo(exists=False, error=f"maven: {e.__class__.__name__}")
        latest = _ts_to_iso(root.findtext("./versioning/lastUpdated", default=""))
        versions = [v.text for v in root.findall("./versioning/versions/version") if v.text]
        # Review-refuted TWICE: <versions> is VERSION-sorted, not publish-sorted,
        # and a small count does NOT make the order chronological. So for young
        # artifacts (<=10 versions AND recent lastUpdated) we HEAD *every* POM
        # and take the OLDEST Last-Modified; otherwise created stays unknown and
        # the engine simply emits no freshness finding (H005/H006 need created).
        # Last-Modified itself is a server heuristic, not a canonical publish
        # date — documented in report limitations.
        created = None
        if latest and versions and len(versions) <= 10 and age_days(latest) < 4 * FRESH_DAYS:
            dates = [d for d in (self._pom_date(gpath, artifact, v) for v in versions) if d]
            created = min(dates) if dates else None
        return PackageInfo(exists=True, created=created, latest=latest,
                           downloads=None, downloads_period="weekly")

    def _pom_date(self, gpath: str, artifact: str, version: str) -> str | None:
        try:
            r = self.session.head(POM_URL.format(gpath, artifact, version, artifact, version),
                                  timeout=(5, 15))
            lm = r.headers.get("Last-Modified")
            return parsedate_to_datetime(lm).isoformat() if lm else None
        except (requests.RequestException, TypeError, ValueError):
            return None
```

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `feat(registries): Maven Central client via repo1 metadata (solrsearch severely stale)`

### Task 16: Java adapter + fixture + E2E

**Files:**
- Create: `src\auditor\adapters\java\__init__.py` (empty), `src\auditor\adapters\java\known_artifacts.py`, `src\auditor\adapters\java\adapter.py`
- Create fixtures: `tests\fixtures\java_repo\pom.xml`, `tests\fixtures\java_repo\src\main\java\com\example\Main.java`
- Test: `tests\test_java_adapter.py`

**Interfaces:**
- Produces: `JavaAdapter()` `name="java"`, `ecosystem="maven"`, `source_globs=(".java",)`; `detect` = `pom.xml`/`build.gradle`/`build.gradle.kts`; `parse_dependencies` → names `"group:artifact"` (pom via ElementTree namespace-agnostic; gradle via regex on configuration lines; coordinates containing `${` ⇒ `skip_registry=True`); `extract_imports` via `(import_declaration)` (wildcard + static handled; `top_level` = package prefix up to the first Capitalized segment, exclusive); `prepare` collects the repo's own `package` declarations; `is_internal` = JDK prefixes (`java.` `javax.` `jdk.` `sun.` `com.sun.` `org.w3c.dom` `org.xml.sax` `org.ietf.jgss`) or own-package prefix; `match_declared` = import package starts with a declared groupId, OR the curated `PACKAGE_TO_ARTIFACT` longest-prefix entry maps to a declared `group:artifact`; `registry_candidates` = `[PACKAGE_TO_ARTIFACT[longest matching prefix]]` else `[]` (⇒ engine emits H007 "cannot map" — the documented accuracy limit).

- [ ] **Step 1: Write the failing tests**

`tests\test_java_adapter.py`:
```python
from pathlib import Path

from auditor.adapters.java.adapter import JavaAdapter
from auditor.core.models import DeclaredDep, ImportRef
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.22.1</version>
    </dependency>
    <dependency>
      <groupId>com.ai.magic</groupId>
      <artifactId>super-utils</artifactId>
      <version>1.0</version>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>internal-lib</artifactId>
    </dependency>
  </dependencies>
</project>"""


def test_detect_and_pom_parsing(tmp_path):
    a = JavaAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "pom.xml", POM)
    assert a.detect(tmp_path)
    deps = {d.name: d for d in a.parse_dependencies(tmp_path)}
    assert set(deps) == {"com.fasterxml.jackson.core:jackson-databind",
                         "com.ai.magic:super-utils",
                         "${project.groupId}:internal-lib"}
    assert deps["${project.groupId}:internal-lib"].skip_registry is True


def test_gradle_parsing(tmp_path):
    _mk(tmp_path, "build.gradle", "\n".join([
        "dependencies {",
        "    implementation 'com.google.code.gson:gson:2.11.0'",
        '    testImplementation("org.mockito:mockito-core:5.0.0")',
        "    api 'com.squareup.okhttp3:okhttp:4.12.0'",
        "}",
    ]))
    names = {d.name for d in JavaAdapter().parse_dependencies(tmp_path)}
    assert names == {"com.google.code.gson:gson", "org.mockito:mockito-core",
                     "com.squareup.okhttp3:okhttp"}


def test_imports_top_level_stops_at_class(tmp_path):
    _mk(tmp_path, "pom.xml", POM)
    _mk(tmp_path, "src/main/java/com/example/Main.java", "\n".join([
        "package com.example;",
        "import java.util.List;",
        "import com.fasterxml.jackson.databind.ObjectMapper;",
        "import com.google.gson.Gson;",
        "import com.hallucinated.tools.Helper;",
        "import com.example.util.Other;",
        "import static org.junit.jupiter.api.Assertions.assertTrue;",
        "class Main {}",
    ]))
    a = JavaAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    a.prepare(tmp_path, files)
    imps = {i.top_level: i for i in a.extract_imports(files)}
    assert set(imps) == {"java.util", "com.fasterxml.jackson.databind",
                         "com.google.gson", "com.hallucinated.tools",
                         "com.example.util", "org.junit.jupiter.api"}
    assert a.is_internal(imps["java.util"])
    assert a.is_internal(imps["com.example.util"])       # own package prefix
    assert not a.is_internal(imps["com.google.gson"])


def test_javax_split_jdk_vs_external():
    from auditor.core.models import ImportRef as IR
    a = JavaAdapter()
    jdk = ["javax.swing.JFrame", "javax.crypto.Cipher", "javax.annotation.processing",
           "javax.transaction.xa", "javax.xml.parsers"]
    external = ["javax.servlet.http", "javax.persistence", "javax.annotation",
                "javax.xml.bind", "javax.transaction", "javax.inject"]
    for m in jdk:
        assert a.is_internal(IR(m, "F.java", 1, top_level=m)), m
    for m in external:
        assert not a.is_internal(IR(m, "F.java", 1, top_level=m)), m
    # JUnit4 regression: declared junit:junit must match org.junit.* imports
    from auditor.core.models import DeclaredDep
    declared = [DeclaredDep(name="junit:junit", ecosystem="maven", source_file="pom.xml")]
    assert a.match_declared(IR("org.junit.Test", "T.java", 1, top_level="org.junit"),
                            declared) is not None


def test_match_and_candidates():
    a = JavaAdapter()
    declared = [DeclaredDep(name="com.fasterxml.jackson.core:jackson-databind",
                            ecosystem="maven", source_file="pom.xml")]
    hit = a.match_declared(
        ImportRef("com.fasterxml.jackson.databind.ObjectMapper", "M.java", 1,
                  top_level="com.fasterxml.jackson.databind"), declared)
    assert hit is not None  # groupId prefix com.fasterxml.jackson matches via known map
    gson = ImportRef("com.google.gson.Gson", "M.java", 1, top_level="com.google.gson")
    assert a.match_declared(gson, declared) is None
    assert a.registry_candidates(gson) == ["com.google.code.gson:gson"]
    unknown = ImportRef("com.hallucinated.tools.H", "M.java", 1,
                        top_level="com.hallucinated.tools")
    assert a.registry_candidates(unknown) == []


def test_java_repo_e2e(fixtures_dir):
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import PackageInfo
    from tests.conftest import FakeRegistry

    root = fixtures_dir / "java_repo"
    a = JavaAdapter()
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    a.prepare(root, files)
    declared = a.parse_dependencies(root)
    reg = FakeRegistry("maven", {
        "com.fasterxml.jackson.core:jackson-databind": PackageInfo(True, created="2012-01-01T00:00:00+00:00"),
        "com.google.code.gson:gson": PackageInfo(True, created="2008-09-01T00:00:00+00:00"),
    })
    findings = audit_hallucinations(a, root, files, declared, reg)
    ids = sorted(f.rule_id for f in findings)
    assert ids == ["H001", "H002", "H007"]  # super-utils / gson / hallucinated.tools
    # workflow-caught regression: mapping-based findings must carry heuristic
    assert all(f.precision == "heuristic" for f in findings
               if f.rule_id in ("H002", "H007", "H008", "H010"))
    assert next(f for f in findings if f.rule_id == "H001").precision == "exact"
```

- [ ] **Step 2: Create the fixture** — `tests\fixtures\java_repo\pom.xml` = the `POM` string above WITHOUT the `${project.groupId}` dependency block; `tests\fixtures\java_repo\src\main\java\com\example\Main.java`:
```java
package com.example;

import java.util.List;
import java.io.FileInputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.hallucinated.tools.Helper;

class Main {
    void risky(String user) {
        String q = "SELECT * FROM users WHERE name = '" + user + "'";
        try {
            FileInputStream in = new FileInputStream("data.bin");
        } catch (Exception e) {
        }
        if (user == "admin") {
            System.out.println("hi");
        }
    }
}
```
(The SQL concat / empty catch / `==` / no-try-with-resources plants feed Phase 6 tests.)

- [ ] **Step 3: Run — fail. Then implement**

`src\auditor\adapters\java\known_artifacts.py`:
```python
# Curated package-prefix -> Maven coordinates map (longest prefix wins).
# Accuracy limit by design: anything not listed and not matching a declared
# groupId is reported as H007 "cannot map", never guessed into a RED.
PACKAGE_TO_ARTIFACT = {
    "com.fasterxml.jackson": "com.fasterxml.jackson.core:jackson-databind",
    "com.fasterxml.jackson.core": "com.fasterxml.jackson.core:jackson-core",
    "com.fasterxml.jackson.annotation": "com.fasterxml.jackson.core:jackson-annotations",
    "com.google.common": "com.google.guava:guava",
    "com.google.gson": "com.google.code.gson:gson",
    "org.apache.commons.lang3": "org.apache.commons:commons-lang3",
    "org.apache.commons.io": "commons-io:commons-io",
    "org.apache.commons.collections4": "org.apache.commons:commons-collections4",
    "org.slf4j": "org.slf4j:slf4j-api",
    "ch.qos.logback": "ch.qos.logback:logback-classic",
    "org.junit.jupiter": "org.junit.jupiter:junit-jupiter",
    "org.junit": "junit:junit",   # JUnit4 (org.junit.Test); jupiter's longer prefix wins for JUnit5
    "org.mockito": "org.mockito:mockito-core",
    "org.springframework.boot": "org.springframework.boot:spring-boot",
    "org.springframework.context": "org.springframework:spring-context",
    "org.springframework.web": "org.springframework:spring-web",
    "org.springframework": "org.springframework:spring-core",
    "lombok": "org.projectlombok:lombok",
    "okhttp3": "com.squareup.okhttp3:okhttp",
    "retrofit2": "com.squareup.retrofit2:retrofit",
    "org.hibernate": "org.hibernate.orm:hibernate-core",
    "com.zaxxer.hikari": "com.zaxxer:HikariCP",
    "org.yaml.snakeyaml": "org.yaml:snakeyaml",
    "redis.clients": "redis.clients:jedis",
    "com.mysql": "com.mysql:mysql-connector-j",
    "org.postgresql": "org.postgresql:postgresql",
    "io.netty": "io.netty:netty-all",
    "io.jsonwebtoken": "io.jsonwebtoken:jjwt-api",
    "kotlin": "org.jetbrains.kotlin:kotlin-stdlib",   # stdlib packages are kotlin.*, not org.jetbrains.*
    "org.apache.logging.log4j": "org.apache.logging.log4j:log4j-core",
    "org.apache.hc.client5": "org.apache.httpcomponents.client5:httpclient5",
    "org.apache.hc.core5": "org.apache.httpcomponents.core5:httpcore5",
    "com.github.benmanes.caffeine": "com.github.ben-manes.caffeine:caffeine",  # hyphen not derivable
    "jakarta.persistence": "jakarta.persistence:jakarta.persistence-api",
    "javax.servlet": "javax.servlet:javax.servlet-api",
    "javax.persistence": "javax.persistence:javax.persistence-api",
    "javax.validation": "javax.validation:validation-api",
    "javax.inject": "javax.inject:javax.inject",
    "javax.annotation": "javax.annotation:javax.annotation-api",
    "javax.xml.bind": "javax.xml.bind:jaxb-api",
    "org.testng": "org.testng:testng",
    "org.assertj": "org.assertj:assertj-core",
    "com.opencsv": "com.opencsv:opencsv",
}
```

`src\auditor\adapters\java\adapter.py`:
```python
from __future__ import annotations

import re
from pathlib import Path

import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException

from auditor.adapters.java.known_artifacts import PACKAGE_TO_ARTIFACT
from auditor.core.interfaces import LanguageAdapter
from auditor.core.models import DeclaredDep, ImportRef, SourceFile

_JDK_PREFIXES = ("java.", "jdk.", "sun.", "com.sun.",
                 "org.w3c.dom", "org.xml.sax", "org.ietf.jgss")
# javax is NOT blanket-JDK (review-refuted: servlet/persistence/mail/validation/
# inject/ws.rs/annotation/xml.bind... are external Maven artifacts). These are the
# 21 javax prefixes actually exported by JDK 21 modules (docs.oracle.com, per
# module). Longest-prefix semantics: javax.annotation.processing is JDK while
# javax.annotation.PostConstruct is external and simply won't match this list.
_JDK_JAVAX = (
    "javax.accessibility", "javax.annotation.processing", "javax.crypto",
    "javax.imageio", "javax.lang.model", "javax.management", "javax.naming",
    "javax.net", "javax.print", "javax.rmi.ssl", "javax.script",
    "javax.security.auth", "javax.security.cert", "javax.security.sasl",
    "javax.smartcardio", "javax.sound", "javax.sql", "javax.swing",
    "javax.tools", "javax.transaction.xa", "javax.xml",
)
# JEP 320 removed these from the JDK even though they sit under javax.xml.*
_EXTERNAL_JAVAX_OVERRIDES = ("javax.xml.bind", "javax.xml.ws", "javax.xml.soap")
_GRADLE_DEP = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
    r"testRuntimeOnly|annotationProcessor|kapt|classpath)\s*[\(\s]\s*"
    r"""["']([\w.\-]+):([\w.\-]+)(?::[^"']+)?["']""")
_IMPORT_QUERY = "(import_declaration) @imp"
_PACKAGE_QUERY = "(package_declaration) @pkg"


def _top_level(package_path: str) -> str:
    parts = package_path.split(".")
    keep = []
    for part in parts:
        if part[:1].isupper():
            break
        keep.append(part)
    return ".".join(keep) if keep else package_path


class JavaAdapter(LanguageAdapter):
    name = "java"
    ecosystem = "maven"
    source_globs = (".java",)
    mapping_precision = "heuristic"   # curated prefix map => H002/H007/H008/H010 are heuristic

    def __init__(self) -> None:
        self._own_packages: tuple[str, ...] = ()

    def detect(self, root: Path) -> bool:
        return any((root / f).is_file() for f in ("pom.xml", "build.gradle", "build.gradle.kts"))

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        deps: list[DeclaredDep] = []
        pom = root / "pom.xml"
        if pom.is_file():
            deps += self._parse_pom(pom)
        for gradle in ("build.gradle", "build.gradle.kts"):
            g = root / gradle
            if g.is_file():
                deps += self._parse_gradle(g)
        seen: set[str] = set()
        out = []
        for d in deps:
            if d.name not in seen:
                seen.add(d.name)
                out.append(d)
        return out

    def _parse_pom(self, path: Path) -> list[DeclaredDep]:
        try:
            root = ET.fromstring(self._read(path))   # defused + 2MB-capped
        except (ET.ParseError, DefusedXmlException) as e:
            self._manifest_error(path, e)
            return []
        out = []
        for dep in root.iter():
            if not dep.tag.endswith("}dependency") and dep.tag != "dependency":
                continue
            group = artifact = None
            for child in dep:
                tag = child.tag.rsplit("}", 1)[-1]
                if tag == "groupId":
                    group = (child.text or "").strip()
                elif tag == "artifactId":
                    artifact = (child.text or "").strip()
            if group and artifact:
                out.append(DeclaredDep(
                    name=f"{group}:{artifact}", ecosystem="maven", source_file=path.name,
                    raw=f"{group}:{artifact}", skip_registry="${" in group or "${" in artifact))
        return out

    def _parse_gradle(self, path: Path) -> list[DeclaredDep]:
        text = self._read(path)
        return [DeclaredDep(name=f"{g}:{a}", ecosystem="maven", source_file=path.name,
                            raw=f"{g}:{a}")
                for g, a in _GRADLE_DEP.findall(text)]

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        from auditor.core.treesitter import captures, node_text, parse_source
        self.ensure_grammars()
        pkgs: set[str] = set()
        for sf in files:
            parse_source(sf)
            for node in captures("java", sf.tree.root_node, _PACKAGE_QUERY).get("pkg", []):
                text = node_text(node).removeprefix("package").strip().rstrip(";").strip()
                if text:
                    pkgs.add(text)
        self._own_packages = tuple(sorted(pkgs))

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, line_of, node_text, parse_source
        out: list[ImportRef] = []
        for sf in files:
            parse_source(sf)
            for node in captures("java", sf.tree.root_node, _IMPORT_QUERY).get("imp", []):
                text = node_text(node).removeprefix("import").strip().rstrip(";").strip()
                text = text.removeprefix("static").strip()
                module = text.removesuffix(".*")
                if not module:
                    continue
                out.append(ImportRef(module=module, file=sf.rel, line=line_of(node),
                                     top_level=_top_level(module)))
        return out

    def is_internal(self, imp: ImportRef) -> bool:
        m = imp.module
        if m.startswith(_JDK_PREFIXES):
            return True
        if m.startswith("javax."):
            if any(m == p or m.startswith(p + ".") for p in _EXTERNAL_JAVAX_OVERRIDES):
                return False
            return any(m == p or m.startswith(p + ".") for p in _JDK_JAVAX)
        return any(m == p or m.startswith(p + ".") for p in self._own_packages)

    def _known_map_hit(self, imp: ImportRef) -> str | None:
        best = None
        for prefix, coords in PACKAGE_TO_ARTIFACT.items():
            if imp.module == prefix or imp.module.startswith(prefix + "."):
                if best is None or len(prefix) > best[0]:
                    best = (len(prefix), coords)
        return best[1] if best else None

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        for dep in declared:
            group = dep.name.split(":", 1)[0]
            if group and (imp.module == group or imp.module.startswith(group + ".")):
                return dep
        coords = self._known_map_hit(imp)
        if coords:
            group = coords.split(":", 1)[0]
            for dep in declared:
                if dep.name.split(":", 1)[0] == group:
                    return dep
        return None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        coords = self._known_map_hit(imp)
        return [coords] if coords else []

    def grammars(self) -> dict[str, object]:
        import tree_sitter_java
        return {"java": tree_sitter_java.language()}

    def syntax(self):
        from auditor.core.interfaces import SyntaxProfile
        return SyntaxProfile(
            catch_query="(catch_clause) @c",
            catch_body_types=("block",),
            sql_concat_query="(binary_expression) @n",
            # Java has no string interpolation — concat only (review-verified)
        )

    def private_registry_reason(self, root: Path) -> str | None:
        pom = root / "pom.xml"
        if pom.is_file() and "<repositories>" in self._read(pom):
            return "custom <repositories> configured in pom.xml"
        for gradle in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
            g = root / gradle
            if g.is_file():
                text = self._read(g)
                if re.search(r"maven\s*[{(]\s*(url|setUrl)", text):
                    return f"custom maven repository configured in {gradle}"
        return None
```
Note on `match_declared` for jackson: import group root `com.fasterxml.jackson.databind` does not literally start with declared groupId `com.fasterxml.jackson.core`, but the known-map hit `com.fasterxml.jackson → com.fasterxml.jackson.core:jackson-databind` shares groupId with the declared dep — matched via the second loop. This is exactly the "match namespaces to artifacts as far as possible" requirement; everything unmapped degrades to H007, never a false RED.

- [ ] **Step 4: Run `tests\test_java_adapter.py` — PASS (5 tests).**
- [ ] **Step 5: Commit** — `feat(java): adapter (pom/gradle, imports, JDK+own-package detection, curated artifact map) + fixture`

### Task 17: NuGet registry client

**Files:**
- Create: `src\auditor\registries\nuget.py`
- Test: `tests\test_registry_nuget.py`

**Interfaces:**
- Produces: `NuGetClient(session=None)`, `ecosystem="nuget"`. Existence: `GET https://api.nuget.org/v3-flatcontainer/{lowercase}/index.json` (200/404 — ALWAYS lowercase the id). Dates: `GET https://api.nuget.org/v3/registration5-gz-semver2/{lowercase}/index.json`; leaves either inline (`page["items"]`) or external (fetch `page["@id"]`); collect `catalogEntry.published`, EXCLUDING values starting `"1900"` (unlisted-version quirk); `created=min`, `latest=max`. Downloads only when fresh: `GET https://azuresearch-usnc.nuget.org/query?q=packageid:{id}&prerelease=true&semVerLevel=2.0.0` — `totalHits==0` ⇒ downloads stay None (search lags new packages; never used for existence); else `data[0]["totalDownloads"]` with `downloads_period="total"`.

- [ ] **Step 1: Write the failing tests**

`tests\test_registry_nuget.py`:
```python
from datetime import datetime, timedelta, timezone

import responses

from auditor.registries.nuget import NuGetClient

INDEX = "https://api.nuget.org/v3/index.json"
FLAT = "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
REGN = "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"
SEARCH = "https://azuresearch-usnc.nuget.org/query"


def _mock_index():
    responses.get(INDEX, json={"resources": [
        {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/",
         "@type": "RegistrationsBaseUrl/3.6.0"},
        {"@id": "https://api.nuget.org/v3-flatcontainer/",
         "@type": "PackageBaseAddress/3.0.0"},
        {"@id": "https://azuresearch-usnc.nuget.org/query",
         "@type": "SearchQueryService/3.5.0"}]})


@responses.activate
def test_existing_package_skips_1900_unlisted():
    _mock_index()
    responses.get(FLAT, json={"versions": ["12.0.1", "13.0.4"]})
    responses.get(REGN, json={"count": 1, "items": [{"items": [
        {"catalogEntry": {"published": "1900-01-01T00:00:00+00:00", "listed": False}},
        {"catalogEntry": {"published": "2011-01-08T22:12:57.713+00:00", "listed": True}},
        {"catalogEntry": {"published": "2024-06-01T00:00:00+00:00", "listed": True}},
    ]}]})
    info = NuGetClient().lookup("Newtonsoft.Json")   # note the mixed case input
    assert info.exists and info.created.startswith("2011-01-08")
    assert info.latest.startswith("2024-06-01") and info.downloads is None


@responses.activate
def test_external_registration_pages_are_fetched():
    _mock_index()
    responses.get(FLAT, json={"versions": ["1.0.0"]})
    responses.get(REGN, json={"count": 1, "items": [
        {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/page1.json"}]})
    responses.get("https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/page1.json",
                  json={"items": [{"catalogEntry": {"published": "2020-05-05T00:00:00+00:00"}}]})
    info = NuGetClient().lookup("newtonsoft.json")
    assert info.exists and info.created.startswith("2020-05-05")


@responses.activate
def test_fresh_package_downloads_via_search():
    recent = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    flat = "https://api.nuget.org/v3-flatcontainer/shinynew/index.json"
    regn = "https://api.nuget.org/v3/registration5-gz-semver2/shinynew/index.json"
    _mock_index()
    responses.get(flat, json={"versions": ["0.1.0"]})
    responses.get(regn, json={"count": 1, "items": [{"items": [
        {"catalogEntry": {"published": recent}}]}]})
    responses.get(SEARCH, json={"totalHits": 1, "data": [{"totalDownloads": 42}]})
    info = NuGetClient().lookup("ShinyNew")
    assert info.downloads == 42 and info.downloads_period == "total"


@responses.activate
def test_missing_package():
    _mock_index()
    responses.get("https://api.nuget.org/v3-flatcontainer/ghost.pkg/index.json", status=404)
    assert NuGetClient().lookup("Ghost.Pkg").exists is False


@responses.activate
def test_unreachable_index_falls_back_degraded():
    # no INDEX mock registered => ConnectionError => hardcoded fallbacks + degraded flag
    responses.get("https://api.nuget.org/v3-flatcontainer/dapper/index.json", status=404)
    client = NuGetClient()
    assert client.lookup("Dapper").exists is False
    assert client.degraded is True  # CLI surfaces this in diagnostics/limitations
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\registries\nuget.py`:
```python
from __future__ import annotations

import requests

from auditor.core.models import PackageInfo
from auditor.registries.base import FRESH_DAYS, RegistryClient, age_days

INDEX_URL = "https://api.nuget.org/v3/index.json"
# fallbacks only — the docs REQUIRE resolving endpoints from the service index
# ("The base URL ... must be dynamically fetched from the service index"),
# and the semver1 hives 404 on real SemVer2 packages.
REGN_FALLBACK = "https://api.nuget.org/v3/registration5-gz-semver2/"


class NuGetClient(RegistryClient):
    ecosystem = "nuget"

    def __init__(self, session=None):
        super().__init__(session)
        self._resources: dict[str, str] | None = None
        self.degraded = False   # True => service index unreachable, hardcoded fallbacks in use

    _WANTED = {
        "registration": (("RegistrationsBaseUrl/3.6.0", "RegistrationsBaseUrl/Versioned"),
                         REGN_FALLBACK),
        "flat": (("PackageBaseAddress/3.0.0",), "https://api.nuget.org/v3-flatcontainer/"),
        "search": (("SearchQueryService/3.5.0", "SearchQueryService"),
                   "https://azuresearch-usnc.nuget.org/query"),
    }

    def _resource(self, kind: str) -> str:
        """Resolve ALL used endpoints from the service index (docs mandate),
        highest compatible version first; hardcoded values are a visible
        degraded mode (self.degraded => diagnostics note in the CLI)."""
        if self._resources is None:
            self._resources = {}
            try:
                r = self._get(INDEX_URL)
                resources = r.json().get("resources", []) if r.status_code == 200 else []
            except (requests.RequestException, ValueError):
                resources = []
            if not resources:
                self.degraded = True
            for name, (types, fallback) in self._WANTED.items():
                hit = next((x["@id"] for t in types for x in resources
                            if x.get("@type") == t), None)
                if hit is None:
                    self._resources[name] = fallback
                    self.degraded = self.degraded or bool(resources)
                else:
                    self._resources[name] = hit if name == "search" else \
                        (hit if hit.endswith("/") else hit + "/")
        return self._resources[kind]

    def lookup(self, name: str) -> PackageInfo:
        lid = name.lower()
        try:
            r = self._get(self._resource("flat") + lid + "/index.json")
            if r.status_code == 404:
                return PackageInfo(exists=False)
            r.raise_for_status()
        except requests.RequestException as e:
            return PackageInfo(exists=False, error=f"nuget: {e.__class__.__name__}")
        created, latest = self._published_range(lid)
        downloads = period = None
        if created and age_days(created) < FRESH_DAYS:
            downloads = self._total_downloads(name)
            period = "total"
        return PackageInfo(exists=True, created=created, latest=latest,
                           downloads=downloads, downloads_period=period or "weekly")

    def _published_range(self, lid: str) -> tuple[str | None, str | None]:
        try:
            r = self._get(self._resource("registration") + lid + "/index.json")
            if r.status_code != 200:
                return None, None
            pages = r.json().get("items", [])
            published: list[str] = []
            for page in pages:
                leaves = page.get("items")
                if leaves is None and page.get("@id"):
                    sub = self._get(page["@id"])
                    leaves = sub.json().get("items", []) if sub.status_code == 200 else []
                for leaf in leaves or []:
                    p = (leaf.get("catalogEntry") or {}).get("published")
                    if p and not p.startswith("1900"):
                        published.append(p)
            if not published:
                return None, None
            return min(published), max(published)
        except (requests.RequestException, ValueError):
            return None, None

    def _total_downloads(self, name: str) -> int | None:
        try:
            r = self._get(self._resource("search"), params={"q": f"packageid:{name}",
                                              "prerelease": "true", "semVerLevel": "2.0.0"})
            data = r.json()
            if r.status_code != 200 or not data.get("totalHits"):
                return None
            return int(data["data"][0].get("totalDownloads", 0))
        except (requests.RequestException, ValueError, KeyError, IndexError):
            return None
```

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `feat(registries): NuGet client (flat-container + registration + search, 1900-unlisted quirk)`

### Task 18: .NET adapter + fixture + E2E

**Files:**
- Create: `src\auditor\adapters\dotnet\__init__.py` (empty), `src\auditor\adapters\dotnet\adapter.py`
- Create fixtures: `tests\fixtures\dotnet_repo\App.csproj`, `tests\fixtures\dotnet_repo\Program.cs`
- Test: `tests\test_dotnet_adapter.py`

**Interfaces:**
- Produces: `DotnetAdapter()` `name="dotnet"`, `ecosystem="nuget"`, `source_globs=(".cs",)`; `detect` = any `*.csproj` / `packages.config` / `Directory.Packages.props` in the dir; `parse_dependencies` from `<PackageReference Include|Update>`, `<PackageVersion Include>` (Directory.Packages.props) and `<package id=>` (packages.config); `extract_imports` from `(using_directive)` (handles `global using`, `using static`, alias `using X = Y` takes the right side; `top_level` = full namespace text); `prepare` collects own `namespace` declarations (block + file-scoped); `is_internal` = BCL prefixes (`System` exact/`System.`, `Microsoft.CSharp`, `Microsoft.VisualBasic`, `Microsoft.Win32`, `Windows.`) or own-namespace prefix; `match_declared` = longest declared package id that prefix-matches the using; `registry_candidates` = `[full_namespace, first-two-segments]` (deduped, in that order).

- [ ] **Step 1: Write the failing tests**

`tests\test_dotnet_adapter.py`:
```python
from pathlib import Path

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.core.models import DeclaredDep, ImportRef
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.4" />
    <PackageReference Include="FastJsonAI.Helpers" Version="1.0.0" />
  </ItemGroup>
</Project>"""


def test_detect_and_csproj(tmp_path):
    a = DotnetAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "App.csproj", CSPROJ)
    assert a.detect(tmp_path)
    names = {d.name for d in a.parse_dependencies(tmp_path)}
    assert names == {"Newtonsoft.Json", "FastJsonAI.Helpers"}


def test_packages_config_and_directory_props(tmp_path):
    _mk(tmp_path, "packages.config",
        '<packages><package id="Dapper" version="2.1.0" /></packages>')
    _mk(tmp_path, "Directory.Packages.props",
        '<Project><ItemGroup><PackageVersion Include="Serilog" Version="4.0.0" />'
        "</ItemGroup></Project>")
    names = {d.name for d in DotnetAdapter().parse_dependencies(tmp_path)}
    assert names == {"Dapper", "Serilog"}


def test_usings_and_locality(tmp_path):
    _mk(tmp_path, "App.csproj", CSPROJ)
    _mk(tmp_path, "Program.cs", "\n".join([
        "using System;",
        "using System.Text.Json;",
        "global using System.Collections.Generic;",
        "using static System.Math;",
        "using Newtonsoft.Json;",
        "using Dapper;",
        "using HyperSql.Client;",
        "using MyApp.Services;",
        "namespace MyApp { class P { static void Main() {} } }",
    ]))
    a = DotnetAdapter()
    files = collect_source_files(tmp_path, a)
    for f in files:
        parse_source(f)
    a.prepare(tmp_path, files)
    imps = {i.top_level: i for i in a.extract_imports(files)}
    assert "System.Text.Json" in imps and "Newtonsoft.Json" in imps
    assert a.is_internal(imps["System"]) and a.is_internal(imps["System.Text.Json"])
    assert a.is_internal(imps["MyApp.Services"])   # own namespace
    assert not a.is_internal(imps["Dapper"])


def test_match_and_candidates():
    a = DotnetAdapter()
    declared = [DeclaredDep(name="Newtonsoft.Json", ecosystem="nuget", source_file="App.csproj")]
    linq = ImportRef("Newtonsoft.Json.Linq", "P.cs", 1, top_level="Newtonsoft.Json.Linq")
    assert a.match_declared(linq, declared).name == "Newtonsoft.Json"
    hyper = ImportRef("HyperSql.Client", "P.cs", 1, top_level="HyperSql.Client")
    assert a.match_declared(hyper, declared) is None
    assert a.registry_candidates(hyper) == ["HyperSql.Client"]
    deep = ImportRef("A.B.C.D", "P.cs", 1, top_level="A.B.C.D")
    assert a.registry_candidates(deep) == ["A.B.C.D", "A.B"]


def test_dotnet_repo_e2e(fixtures_dir):
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import PackageInfo
    from tests.conftest import FakeRegistry

    root = fixtures_dir / "dotnet_repo"
    a = DotnetAdapter()
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    a.prepare(root, files)
    declared = a.parse_dependencies(root)
    reg = FakeRegistry("nuget", {
        "newtonsoft.json": PackageInfo(True, created="2011-01-08T00:00:00+00:00"),
        "dapper": PackageInfo(True, created="2011-04-14T00:00:00+00:00"),
    })
    findings = audit_hallucinations(a, root, files, declared, reg)
    ids = sorted(f.rule_id for f in findings)
    assert ids == ["H001", "H002", "H008"]  # FastJsonAI.Helpers / Dapper / HyperSql.Client
    assert all(f.precision == "heuristic" for f in findings
               if f.rule_id in ("H002", "H008"))   # namespace guessing is never "exact"
```

- [ ] **Step 2: Create the fixture** — `tests\fixtures\dotnet_repo\App.csproj` = `CSPROJ` above; `tests\fixtures\dotnet_repo\Program.cs`:
```csharp
using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Dapper;
using HyperSql.Client;

namespace FixtureApp
{
    class Program
    {
        static void Main()
        {
            var data = FetchAsync().Result;
            try
            {
                Console.WriteLine(data);
            }
            catch (Exception)
            {
            }
        }

        static async Task<string> FetchAsync()
        {
            await Task.Delay(1);
            return "ok";
        }

        static async void FireAndForget()
        {
            await Task.Delay(1);
        }

        static string BuildQuery(string userId)
        {
            return $"SELECT * FROM Users WHERE Id = {userId}";
        }
    }
}
```
(Plants for Phase 6: `.Result`, empty catch, `async void`, interpolated SQL.)

- [ ] **Step 3: Implement**

`src\auditor\adapters\dotnet\adapter.py`:
```python
from __future__ import annotations

from pathlib import Path

import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException

from auditor.core.interfaces import LanguageAdapter
from auditor.core.models import DeclaredDep, ImportRef, SourceFile

_BCL_PREFIXES = ("System.", "Microsoft.CSharp", "Microsoft.VisualBasic",
                 "Microsoft.Win32", "Windows.")
# Review-verified (learn.microsoft.com per-TFM matrix): these ship as NuGet
# packages on EVERY modern TFM despite the System.* name — never BCL-filter them.
_PACKAGE_DELIVERED_SYSTEM = ("System.CommandLine", "System.Data.SqlClient",
                             "System.Drawing", "System.Management", "System.Data.Entity")
# Additionally package-delivered when targeting .NET Framework / netstandard:
_OLD_TFM_PACKAGE_SYSTEM = ("System.Text.Json", "System.Collections.Immutable",
                           "System.Text.Encodings.Web", "System.Threading.Channels")
# Known using->package-id fixups where the naive heuristic resolves to the WRONG
# package (NUnit.Framework would hit the relic `nunit.framework 2.63.0`).
_NUGET_ALIASES = {"nunit.framework": "NUnit"}
_USING_QUERY = "(using_directive) @u"
_NS_QUERY = "[(namespace_declaration) (file_scoped_namespace_declaration)] @ns"


def _is_old_tfm(tfm: str) -> bool:
    t = tfm.strip().lower()
    return t.startswith(("net4", "netstandard", "net3", "net2")) and not t.startswith("net10")


class DotnetAdapter(LanguageAdapter):
    name = "dotnet"
    ecosystem = "nuget"
    source_globs = (".cs",)
    mapping_precision = "heuristic"   # namespace->package-id guessing => mapping findings are heuristic

    def __init__(self) -> None:
        self._own_namespaces: tuple[str, ...] = ()
        self._old_tfm = False   # any TargetFramework < netcore3 / netstandard?

    def detect(self, root: Path) -> bool:
        if (root / "packages.config").is_file() or (root / "Directory.Packages.props").is_file():
            return True
        return any(root.glob("*.csproj"))

    def _read_target_frameworks(self, root: Path) -> list[str]:
        tfms: list[str] = []
        for proj in root.glob("*.csproj"):
            try:
                doc = ET.fromstring(self._read(proj))
            except (ET.ParseError, DefusedXmlException) as e:
                self._manifest_error(proj, e)
                continue
            plural = singular = None
            for el in doc.iter():
                tag = el.tag.rsplit("}", 1)[-1]
                if tag == "TargetFrameworks":
                    plural = el.text or ""
                elif tag == "TargetFramework":
                    singular = el.text or ""
            # msbuild-props docs: TargetFrameworks (plural) overrides singular
            if plural:
                tfms += [t for t in plural.split(";") if t.strip()]
            elif singular:
                tfms.append(singular)
        return tfms

    def parse_dependencies(self, root: Path, diag=None) -> list[DeclaredDep]:
        self._diag = diag
        out: list[DeclaredDep] = []
        for proj in sorted(root.glob("*.csproj")) + [root / "Directory.Packages.props"]:
            if proj.is_file():
                out += self._parse_msbuild(proj)
        pkgcfg = root / "packages.config"
        if pkgcfg.is_file():
            out += self._parse_packages_config(pkgcfg)
        seen: set[str] = set()
        deduped = []
        for d in out:
            if d.name.lower() not in seen:
                seen.add(d.name.lower())
                deduped.append(d)
        return deduped

    def _parse_msbuild(self, path: Path) -> list[DeclaredDep]:
        try:
            root = ET.fromstring(self._read(path))   # defused + 2MB-capped
        except (ET.ParseError, DefusedXmlException) as e:
            self._manifest_error(path, e)
            return []
        out = []
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag in ("PackageReference", "PackageVersion"):
                name = el.get("Include") or el.get("Update")
                if name:
                    out.append(DeclaredDep(name=name, ecosystem="nuget",
                                           source_file=path.name, raw=name,
                                           skip_registry="$(" in name))
        return out

    def _parse_packages_config(self, path: Path) -> list[DeclaredDep]:
        try:
            root = ET.fromstring(self._read(path))
        except (ET.ParseError, DefusedXmlException) as e:
            self._manifest_error(path, e)
            return []
        return [DeclaredDep(name=el.get("id"), ecosystem="nuget",
                            source_file=path.name, raw=el.get("id"))
                for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "package" and el.get("id")]

    def prepare(self, root: Path, files: list[SourceFile]) -> None:
        from auditor.core.treesitter import captures, node_text, parse_source
        self.ensure_grammars()
        self._old_tfm = any(_is_old_tfm(t) for t in self._read_target_frameworks(root))
        ns: set[str] = set()
        for sf in files:
            parse_source(sf)
            for node in captures("csharp", sf.tree.root_node, _NS_QUERY).get("ns", []):
                name = node.child_by_field_name("name")
                if name is not None:
                    ns.add(node_text(name))
        self._own_namespaces = tuple(sorted(ns))

    def extract_imports(self, files: list[SourceFile]) -> list[ImportRef]:
        from auditor.core.treesitter import captures, line_of, node_text, parse_source
        out: list[ImportRef] = []
        for sf in files:
            parse_source(sf)
            for node in captures("csharp", sf.tree.root_node, _USING_QUERY).get("u", []):
                text = node_text(node).rstrip(";").strip()
                for kw in ("global ", "using ", "static "):
                    text = text.removeprefix(kw).strip() if text.startswith(kw) else text
                text = text.removeprefix("using").strip()
                text = text.removeprefix("static").strip()
                if "=" in text:                     # alias: using Foo = Bar.Baz
                    text = text.split("=", 1)[1].strip()
                if not text:
                    continue
                out.append(ImportRef(module=text, file=sf.rel, line=line_of(node),
                                     top_level=text))
        return out

    def is_internal(self, imp: ImportRef) -> bool:
        m = imp.module
        exceptions = _PACKAGE_DELIVERED_SYSTEM + (_OLD_TFM_PACKAGE_SYSTEM if self._old_tfm else ())
        if any(m == e or m.startswith(e + ".") for e in exceptions):
            return False   # System.*-named but NuGet-delivered => normal declared/registry path
        if m == "System" or m.startswith(_BCL_PREFIXES):
            return True
        return any(m == ns or m.startswith(ns + ".") or ns.startswith(m + ".")
                   for ns in self._own_namespaces)

    def match_declared(self, imp: ImportRef, declared: list[DeclaredDep]) -> DeclaredDep | None:
        best: tuple[int, DeclaredDep] | None = None
        for dep in declared:
            n = dep.name
            if imp.module == n or imp.module.startswith(n + "."):
                if best is None or len(n) > best[0]:
                    best = (len(n), dep)
        return best[1] if best else None

    def registry_candidates(self, imp: ImportRef) -> list[str]:
        parts = imp.module.split(".")
        cands = [imp.module]
        if len(parts) > 2:
            cands.append(".".join(parts[:2]))
        return [_NUGET_ALIASES.get(c.lower(), c) for c in cands]

    def grammars(self) -> dict[str, object]:
        import tree_sitter_c_sharp
        return {"csharp": tree_sitter_c_sharp.language()}

    def syntax(self):
        from auditor.core.interfaces import SyntaxProfile
        return SyntaxProfile(
            catch_query="(catch_clause) @c",
            catch_body_types=("block",),
            sql_concat_query="(binary_expression) @n",
            sql_interp_query="(interpolated_string_expression) @n",
            sql_dynamic_types=("interpolation",),
        )

    def private_registry_reason(self, root: Path) -> str | None:
        for cfg_name in ("nuget.config", "NuGet.Config", "NuGet.config"):
            cfg = root / cfg_name
            if not cfg.is_file():
                continue
            text = self._read(cfg)
            if "<packageSources>" in text and "nuget.org" not in text.split("<packageSources>")[-1]:
                return f"custom <packageSources> configured in {cfg_name}"
            if "<packageSources>" in text and "<add" in text and \
                    text.count("<add") > text.count("api.nuget.org"):
                return f"additional package sources configured in {cfg_name}"
        return None
```

- [ ] **Step 4: Run `tests\test_dotnet_adapter.py` — PASS (5 tests).**
- [ ] **Step 5: Commit** — `feat(dotnet): adapter (csproj/packages.config/central packages, usings, BCL filter) + fixture`

**PHASE CHECKPOINT CP-5 — STOP.** Present to the user: all four adapters + four registry clients complete; each language has a planted-bug fixture and passing E2E through Engine 1. Explicitly restate the documented Java/.NET accuracy limits (prefix maps, H007 degradation) as required by the spec.
**Gate:** javax split test green (JDK vs external, incl. the 4 trap prefixes); JUnit4-declared regression test green; NuGet service-index resolution mocked+tested; Maven created-guard covered. **Blockers:** any javax.* external family classified internal; NUnit alias unresolved. **Deferred decisions:** old-TFM System.* extra list contents — confirm coverage.

---

## PHASE 6 — Engine 2: dangerous-pattern rules

### Task 19: Cross-language common rules (P001–P005, P007)

**Files:**
- Create: `src\auditor\core\rules_common.py`
- Test: `tests\test_rules_common.py`

**Interfaces:**
- Consumes: `Rule`, `SyntaxProfile` (T2), `SourceFile`, treesitter helpers
- Produces: `common_rules(profile: SyntaxProfile) -> list[Rule]` = `[EmptyCatch(profile), SecretsRule(), SqlStringBuild(profile), SmellComments()]`. **v2 core-neutrality:** `EmptyCatch` (P001) and `SqlStringBuild` (P004/P005, `precision="heuristic"`) read all language-specific queries/node-types from the adapter-supplied `SyntaxProfile` — zero language names or branches inside core. `SecretsRule` (P002 red / P003 yellow, placeholder-filtered, snippet-masked) and `SmellComments` (P007) are pure line-regex, language-free by nature.

- [ ] **Step 1: Write the failing tests**

`tests\test_rules_common.py` (language-specific syntax comes from the ADAPTERS' profiles — the module under test contains no language knowledge):
```python
from pathlib import Path

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.adapters.java.adapter import JavaAdapter
from auditor.adapters.python.adapter import PythonAdapter
from auditor.adapters.typescript.adapter import TypeScriptAdapter
from auditor.core.models import SourceFile
from auditor.core.rules_common import (EmptyCatch, SecretsRule, SmellComments,
                                       SqlStringBuild, common_rules)
from auditor.core.treesitter import parse_source

PROFILES = {
    "python": PythonAdapter().syntax(),
    "java": JavaAdapter().syntax(),
    "csharp": DotnetAdapter().syntax(),
    "typescript": TypeScriptAdapter().syntax(),
    "tsx": TypeScriptAdapter().syntax(),
}


def _sf(code: str, language: str, name: str = "f") -> SourceFile:
    ext = {"python": ".py", "java": ".java", "csharp": ".cs",
           "typescript": ".ts", "tsx": ".tsx"}[language]
    sf = SourceFile(path=Path(name + ext), rel=name + ext, language=language,
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def _catch(lang):
    return EmptyCatch(PROFILES[lang])


def _sql(lang):
    return SqlStringBuild(PROFILES[lang])


def test_p001_empty_except_python():
    sf = _sf("try:\n    x = 1\nexcept Exception:\n    pass\n", "python")
    assert [f.rule_id for f in _catch("python").check(sf)] == ["P001"]


def test_p001_handled_except_is_clean():
    sf = _sf("try:\n    x = 1\nexcept Exception as e:\n    print(e)\n", "python")
    assert _catch("python").check(sf) == []


def test_p001_empty_catch_all_curly_languages():
    cases = [
        ("class A { void f() { try { g(); } catch (Exception e) { } } }", "java"),
        ("class A { void F() { try { G(); } catch (System.Exception) { } } }", "csharp"),
        ("try { f(); } catch (e) { }", "typescript"),
    ]
    for code, lang in cases:
        sf = _sf(code, lang)
        assert [f.rule_id for f in _catch(lang).check(sf)] == ["P001"], lang


def test_p002_known_secret_tokens_masked():
    sf = _sf('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', "python")
    fs = SecretsRule().check(sf)
    assert [f.rule_id for f in fs] == ["P002"]
    assert "AKIAIOSFODNN7EXAMPLE" not in fs[0].snippet  # masked


def test_p003_generic_credential_and_placeholder_filter():
    hot = _sf('password = "hunter2secret99"\n', "python")
    assert [f.rule_id for f in SecretsRule().check(hot)] == ["P003"]
    for benign in ('password = "changeme"\n', 'password = os.environ["PW"]\n',
                   'password = "<YOUR-PASSWORD>"\n'):
        assert SecretsRule().check(_sf(benign, "python")) == [], benign


def test_p004_sql_composition_python_fstring():
    sf = _sf('q = f"SELECT * FROM users WHERE id = {uid}"\n', "python")
    assert [f.rule_id for f in _sql("python").check(sf)] == ["P004"]


def test_p005_sql_reaching_execute_sink():
    sf = _sf('cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n', "python")
    assert [f.rule_id for f in _sql("python").check(sf)] == ["P005"]


def test_p004_ts_template_and_csharp_interpolation():
    ts = _sf("const q = `SELECT * FROM t WHERE id = ${id}`;", "typescript")
    assert [f.rule_id for f in _sql("typescript").check(ts)] == ["P004"]
    cs = _sf('class A { string Q(string i) { return $"SELECT * FROM T WHERE Id = {i}"; } }',
             "csharp")
    assert [f.rule_id for f in _sql("csharp").check(cs)] == ["P004"]


def test_p004_literal_sql_is_clean():
    sf = _sf('q = "SELECT * FROM users WHERE id = 1"\n', "python")
    assert _sql("python").check(sf) == []


def test_p007_smell_comments():
    sf = _sf("# TODO: implement error handling\n"
             "# In a real application, validate input\n"
             "x = 1\n", "python")
    assert [f.rule_id for f in SmellComments().check(sf)] == ["P007", "P007"]


def test_factory_and_precision():
    rules = common_rules(PROFILES["python"])
    assert [r.__class__.__name__ for r in rules] == \
        ["EmptyCatch", "SecretsRule", "SqlStringBuild", "SmellComments"]
    assert next(r for r in rules if r.id == "P004").precision == "heuristic"


def test_no_language_names_in_core_rules_module():
    import inspect

    import auditor.core.rules_common as mod
    src = inspect.getsource(mod)
    for token in ('"python"', '"java"', '"csharp"', '"typescript"', '"tsx"'):
        assert token not in src, f"core neutrality violated: {token} in rules_common"
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\core\rules_common.py`:
```python
from __future__ import annotations

import re

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_SQL_RE = re.compile(r"\b(SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b",
                     re.I | re.S)
_SINK_RE = re.compile(r"(execute|query|raw|command)", re.I)

_TOKEN_PATTERNS = [
    ("AWS access key", re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|github_pat_[A-Za-z0-9_]{22,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("URL with credentials", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"]{1,64}:[^@/\s'\"]{4,}@")),
    ("Connection string password", re.compile(r"(?i)(?=.*\b(?:server|data source|host)\s*=)(?:.*)\b(?:password|pwd)\s*=\s*[^;\s\"']{4,}")),
]
_GENERIC_CRED = re.compile(r"(?i)\b(api_?key|secret|token|passwd|password)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']")
_PLACEHOLDER = re.compile(r"(?i)(changeme|example|placeholder|your[_\-]|xxx+|dummy|sample|"
                          r"<[^>]*>|\{\{|\$\{|process\.env|os\.environ|getenv)")
_SMELLS = re.compile(r"(?i)(in a real (?:app|application|project|system)|TODO:?\s*implement|"
                     r"not implemented|placeholder|for demo purposes|in production,? you (?:would|should)|"
                     r"simplified (?:for|version)|replace (?:this )?with (?:your|actual|real)|"
                     r"left as an exercise|mock implementation)")


def _mk_finding(rule_id: str, severity: Severity, title: str, sf: SourceFile,
                line: int, snippet: str, detail: str,
                precision: str = "exact") -> Finding:
    return Finding(rule_id=rule_id, severity=severity, title=title, file=sf.rel,
                   line=line, snippet=snippet[:120], detail=detail,
                   language=sf.language, engine="auditor", precision=precision)


class EmptyCatch(Rule):
    id = "P001"
    severity = Severity.YELLOW
    title = "Empty or exception-swallowing catch/except block"

    def __init__(self, profile):
        self.profile = profile   # SyntaxProfile from the adapter — core stays language-free

    def check(self, sf: SourceFile) -> list[Finding]:
        if not self.profile.catch_query:
            return []
        out = []
        for clause in captures(sf.language, sf.tree.root_node, self.profile.catch_query).get("c", []):
            body = clause.child_by_field_name("body") \
                or next((c for c in clause.named_children
                         if c.type in self.profile.catch_body_types), None)
            if body is None:
                continue
            stmts = [c for c in body.named_children
                     if c.type not in self.profile.comment_types]
            swallows = not stmts or all(self.profile.is_swallow_stmt(s) for s in stmts)
            if swallows:
                out.append(_mk_finding(self.id, self.severity, self.title, sf,
                                       line_of(clause), node_text(clause).splitlines()[0],
                                       "Exception is silently swallowed — failures become invisible."))
        return out


class SecretsRule(Rule):
    id = "P002"  # emits P002 and P003
    severity = Severity.RED
    title = "Hardcoded secret (known token format)"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for i, line in enumerate(sf.text.decode("utf-8", errors="replace").splitlines(), 1):
            hit = next(((label, m) for label, rx in _TOKEN_PATTERNS
                        for m in [rx.search(line)] if m), None)
            if hit:
                label, m = hit
                masked = line.replace(m.group(0), m.group(0)[:4] + "***")
                out.append(_mk_finding("P002", Severity.RED, self.title, sf, i,
                                       masked.strip(), f"{label} committed in source."))
                continue
            gm = _GENERIC_CRED.search(line)
            if gm and not _PLACEHOLDER.search(line):
                masked = line.replace(gm.group(2), gm.group(2)[:2] + "***")
                out.append(_mk_finding("P003", Severity.YELLOW,
                                       "Suspicious credential assignment", sf, i,
                                       masked.strip(),
                                       "Literal credential-like value assigned in code."))
        return out


class SqlStringBuild(Rule):
    id = "P004"  # emits P004 and P005
    severity = Severity.YELLOW
    title = "SQL built via string composition"
    precision = "heuristic"   # syntactic — no data-flow; documented in reports

    def __init__(self, profile):
        self.profile = profile

    def check(self, sf: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        seen_lines: set[int] = set()
        if self.profile.sql_concat_query:
            for node in captures(sf.language, sf.tree.root_node,
                                 self.profile.sql_concat_query).get("n", []):
                self._judge(node, sf, out, seen_lines, needs_dynamic=False)
        if self.profile.sql_interp_query:
            for node in captures(sf.language, sf.tree.root_node,
                                 self.profile.sql_interp_query).get("n", []):
                self._judge(node, sf, out, seen_lines, needs_dynamic=True)
        return out

    def _judge(self, node, sf: SourceFile, out: list, seen_lines: set,
               needs_dynamic: bool) -> None:
        text = node_text(node)
        if not _SQL_RE.search(text):
            return
        if needs_dynamic and not self._is_dynamic(node):
            return
        line = line_of(node)
        if line in seen_lines:
            return
        seen_lines.add(line)
        sink = self._enclosing_sink(node)
        if sink:
            out.append(_mk_finding("P005", Severity.RED,
                                   "String-composed SQL reaches an execution sink", sf, line,
                                   text, f"Composed SQL is passed to '{sink}' — SQL injection risk; "
                                   "use parameterized queries.", precision=self.precision))
        else:
            out.append(_mk_finding("P004", Severity.YELLOW, self.title, sf, line, text,
                                   "SQL assembled from dynamic strings; prefer parameterized queries.",
                                   precision=self.precision))

    def _is_dynamic(self, node) -> bool:
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type in self.profile.sql_dynamic_types:
                return True
            stack.extend(cur.named_children)
        return False

    def _enclosing_sink(self, node) -> str | None:
        cur = node.parent
        while cur is not None:
            if cur.type in self.profile.sql_sink_call_types:
                fn = cur.child_by_field_name("function") or cur.child_by_field_name("name") \
                    or cur.child_by_field_name("type")
                if fn is not None:
                    name = node_text(fn)
                    if _SINK_RE.search(name):
                        return name.split("(")[0][-60:]
            cur = cur.parent
        return None


class SmellComments(Rule):
    id = "P007"
    severity = Severity.BLUE
    title = "AI-style incompleteness comment"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for i, line in enumerate(sf.text.decode("utf-8", errors="replace").splitlines(), 1):
            m = _SMELLS.search(line)
            if m:
                out.append(_mk_finding(self.id, self.severity, self.title, sf, i,
                                       line.strip(), f"Marker '{m.group(0)}' suggests "
                                       "incomplete/demo-grade code left by generation."))
        return out


def common_rules(profile) -> list[Rule]:
    return [EmptyCatch(profile), SecretsRule(), SqlStringBuild(profile), SmellComments()]
```
Grammar notes locked by the tests: Java's profile sets no `sql_interp_query` (no string interpolation — concat only). Python's profile registers `(string) @n` as the interp query — `_is_dynamic` demands an `interpolation` child, so f-strings fire and plain literals never do. All per-language knowledge now lives in the adapters' `syntax()` profiles (Tasks 7/11/16/18); this module contains no language names.

- [ ] **Step 4: Run — PASS (11 tests).**
- [ ] **Step 5: Commit** — `feat(engine2): cross-language rules — empty catch, secrets, SQL composition, smell comments`

### Task 20: Complexity (P006) + Java rules (J001, J002) + .NET rules (D001–D003)

**Files:**
- Create: `src\auditor\core\complexity.py`, `src\auditor\adapters\java\rules.py`, `src\auditor\adapters\dotnet\rules.py`
- Modify: `src\auditor\adapters\java\adapter.py` and `src\auditor\adapters\dotnet\adapter.py` — add `language_rules()`
- Test: `tests\test_complexity.py`, `tests\test_lang_rules.py`

**Interfaces:**
- Produces: `complexity.complexity_findings(files: list[SourceFile], threshold: int = 10, diag=None) -> list[Finding]` using `lizard.analyze_file.analyze_source_code(filename, source_str)` (P006, detail includes function name + CCN; per-file lizard failures recorded into `diag.rule_errors`, never silently dropped); `JavaAdapter.language_rules()` → `[StringEqualsCompare(), MissingTryWithResources()]`; `DotnetAdapter.language_rules()` → `[AsyncVoidMethod(), BlockingTaskWait(), RawSqlInterpolation()]`.

- [ ] **Step 1: Write the failing tests**

`tests\test_complexity.py`:
```python
from pathlib import Path

from auditor.core.complexity import complexity_findings
from auditor.core.models import SourceFile

COMPLEX_PY = "def classify(n):\n" + "".join(
    f"    {'if' if i == 0 else 'elif'} n < {i + 1}:\n        return {i}\n"
    for i in range(11)) + "    return -1\n"


def test_p006_flags_complex_function():
    sf = SourceFile(path=Path("c.py"), rel="c.py", language="python",
                    text=COMPLEX_PY.encode())
    fs = complexity_findings([sf])
    assert len(fs) == 1 and fs[0].rule_id == "P006"
    assert "classify" in fs[0].detail and fs[0].severity.value == "yellow"


def test_p006_simple_function_clean():
    sf = SourceFile(path=Path("s.py"), rel="s.py", language="python",
                    text=b"def f():\n    return 1\n")
    assert complexity_findings([sf]) == []


def test_p006_works_for_tsx():
    code = "export function big(n: number) {\n" + "".join(
        f"  if (n === {i}) return {i};\n" for i in range(12)) + "  return -1;\n}\n"
    sf = SourceFile(path=Path("b.tsx"), rel="b.tsx", language="tsx", text=code.encode())
    fs = complexity_findings([sf])
    assert [f.rule_id for f in fs] == ["P006"]


def test_lizard_per_file_failure_reaches_failure_counters(monkeypatch):
    # independent-sweep catch: the swallowed per-file lizard exception used to
    # land in rule_errors ONLY — rule_health stayed 1.0 and verdict could PASS
    from auditor.core import complexity as cx
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import verdict

    def boom(name, src):
        raise RuntimeError("lizard exploded")
    monkeypatch.setattr(cx.lizard.analyze_file, "analyze_source_code", boom)
    sf = SourceFile(path=Path("x.py"), rel="x.py", language="python", text=b"x = 1\n")
    diag = Diagnostics()
    assert cx.complexity_findings([sf], diag=diag) == []
    assert diag.rule_attempted == 1 and diag.rule_failures == 1
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"rule_attempted": diag.rule_attempted,
                    "rule_failures": diag.rule_failures,
                    "rule_errors": diag.rule_errors}) != "pass"
```

`tests\test_lang_rules.py`:
```python
from pathlib import Path

from auditor.adapters.dotnet.rules import (AsyncVoidMethod, BlockingTaskWait,
                                           RawSqlInterpolation)
from auditor.adapters.java.rules import MissingTryWithResources, StringEqualsCompare
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(code: str, language: str) -> SourceFile:
    ext = {"java": ".java", "csharp": ".cs"}[language]
    sf = SourceFile(path=Path("f" + ext), rel="f" + ext, language=language,
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def test_j001_string_eq():
    sf = _sf('class A { boolean f(String s) { return s == "admin"; } }', "java")
    assert [f.rule_id for f in StringEqualsCompare().check(sf)] == ["J001"]
    clean = _sf('class A { boolean f(String s) { return "admin".equals(s); } }', "java")
    assert StringEqualsCompare().check(clean) == []


def test_j002_resource_without_twr():
    sf = _sf('class A { void f() throws Exception { '
             'java.io.FileInputStream in = new java.io.FileInputStream("x"); } }', "java")
    assert [f.rule_id for f in MissingTryWithResources().check(sf)] == ["J002"]
    clean = _sf('class A { void f() throws Exception { '
                'try (java.io.FileInputStream in = new java.io.FileInputStream("x")) {} } }',
                "java")
    assert MissingTryWithResources().check(clean) == []


def test_d001_async_void():
    sf = _sf("class A { static async void Fire() { await Task.Delay(1); } }", "csharp")
    assert [f.rule_id for f in AsyncVoidMethod().check(sf)] == ["D001"]
    handler = _sf("class A { async void OnClick(object sender, EventArgs e) "
                  "{ await Task.Delay(1); } }", "csharp")
    assert AsyncVoidMethod().check(handler) == []


def test_d002_blocking_wait():
    sf = _sf("class A { void F() { var x = FetchAsync().Result; GetAsync().Wait(); "
             "var y = RunAsync().GetAwaiter().GetResult(); } }", "csharp")
    ids = [f.rule_id for f in BlockingTaskWait().check(sf)]
    assert ids == ["D002", "D002", "D002"]
    clean = _sf("class A { void F(SomeStruct s) { var r = s.Result; } }", "csharp")
    assert BlockingTaskWait().check(clean) == []


def test_precision_reaches_findings_not_just_rules():
    # fourth-round regression: heuristic must arrive ON THE FINDING, never
    # silently defaulting back to "exact"
    j = _sf('class A { void f() throws Exception { '
            'java.io.FileInputStream in = new java.io.FileInputStream("x"); } }', "java")
    assert [f.precision for f in MissingTryWithResources().check(j)] == ["heuristic"]
    cs = _sf("class A { void F() { var x = FetchAsync().Result; } }", "csharp")
    assert [f.precision for f in BlockingTaskWait().check(cs)] == ["heuristic"]
    raw = _sf('class A { void F(Db db, string id) { '
              'db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}"); } }', "csharp")
    assert [f.precision for f in RawSqlInterpolation().check(raw)] == ["heuristic"]
    eq = _sf('class A { boolean f(String s) { return s == "admin"; } }', "java")
    assert [f.precision for f in StringEqualsCompare().check(eq)] == ["exact"]


def test_d003_raw_sql():
    sf = _sf('class A { void F(Db db, string id) { '
             'db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}"); } }', "csharp")
    assert [f.rule_id for f in RawSqlInterpolation().check(sf)] == ["D003"]
    clean = _sf('class A { void F(Db db) { db.Users.FromSqlRaw("SELECT * FROM Users"); } }',
                "csharp")
    assert RawSqlInterpolation().check(clean) == []
```

- [ ] **Step 2: Run — fail.**

- [ ] **Step 3: Implement**

`src\auditor\core\complexity.py`:
```python
from __future__ import annotations

import lizard

from auditor.core.models import Finding, Severity, SourceFile

THRESHOLD = 10


def complexity_findings(files: list[SourceFile], threshold: int = THRESHOLD,
                        diag=None) -> list[Finding]:
    out: list[Finding] = []
    for sf in files:
        # per-FILE attempt/failure accounting: a swallowed lizard exception must
        # still reach rule_failures, or rule_health stays 1.0 and the verdict can
        # PASS (independent-sweep catch: same class as the project_rules bug)
        if diag is not None:
            diag.rule_attempted += 1
        try:
            analysis = lizard.analyze_file.analyze_source_code(
                str(sf.path), sf.text.decode("utf-8", errors="replace"))
        except Exception as e:
            if diag is not None:
                diag.rule_failures += 1
                diag.rule_errors.append(f"complexity on {sf.rel}: {e.__class__.__name__}")
            continue
        for fn in analysis.function_list:
            if fn.cyclomatic_complexity > threshold:
                out.append(Finding(
                    rule_id="P006", severity=Severity.YELLOW,
                    title="Cyclomatic complexity above 10",
                    file=sf.rel, line=fn.start_line,
                    snippet=fn.name,
                    detail=f"{fn.name} has cyclomatic complexity "
                           f"{fn.cyclomatic_complexity} (> {threshold}).",
                    language=sf.language, engine="auditor"))
    return out
```

`src\auditor\adapters\java\rules.py`:
```python
from __future__ import annotations

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_RESOURCE_TYPES = frozenset({
    "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
    "BufferedReader", "BufferedWriter", "Scanner", "PrintWriter",
    "Socket", "ServerSocket", "RandomAccessFile",
})


def _finding(rule: Rule, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule.id, severity=rule.severity, title=rule.title,
                   file=sf.rel, line=line_of(node), snippet=node_text(node)[:120],
                   detail=detail, language=sf.language, engine="auditor",
                   precision=rule.precision)


class StringEqualsCompare(Rule):
    id = "J001"
    severity = Severity.YELLOW
    title = "String compared with =="

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for node in captures("java", sf.tree.root_node, "(binary_expression) @b").get("b", []):
            op = node.child_by_field_name("operator")
            if op is None or node_text(op) not in ("==", "!="):
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if any(n is not None and n.type == "string_literal" for n in (left, right)):
                out.append(_finding(self, sf, node,
                                    "== compares object identity, not content; use .equals()."))
        return out


class MissingTryWithResources(Rule):
    id = "J002"
    severity = Severity.YELLOW
    title = "Resource opened without try-with-resources"
    precision = "heuristic"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for node in captures("java", sf.tree.root_node,
                             "(object_creation_expression) @o").get("o", []):
            type_node = node.child_by_field_name("type")
            if type_node is None:
                continue
            simple = node_text(type_node).split(".")[-1]
            if simple not in _RESOURCE_TYPES:
                continue
            cur = node.parent
            in_resources = False
            while cur is not None:
                if cur.type == "resource_specification":
                    in_resources = True
                    break
                cur = cur.parent
            if not in_resources:
                out.append(_finding(self, sf, node,
                                    f"new {simple}(...) outside try-with-resources; the handle "
                                    "leaks if an exception occurs before close()."))
        return out
```

`src\auditor\adapters\dotnet\rules.py`:
```python
from __future__ import annotations

import re

from auditor.core.interfaces import Rule
from auditor.core.models import Finding, Severity, SourceFile
from auditor.core.treesitter import captures, line_of, node_text

_RAW_SQL_APIS = re.compile(r"(FromSqlRaw|ExecuteSqlRaw|SqlQueryRaw|SqlCommand)")


def _finding(rule: Rule, sf: SourceFile, node, detail: str) -> Finding:
    return Finding(rule_id=rule.id, severity=rule.severity, title=rule.title,
                   file=sf.rel, line=line_of(node), snippet=node_text(node)[:120],
                   detail=detail, language=sf.language, engine="auditor",
                   precision=rule.precision)


class AsyncVoidMethod(Rule):
    id = "D001"
    severity = Severity.YELLOW
    title = "async void method outside event handlers"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for m in captures("csharp", sf.tree.root_node, "(method_declaration) @m").get("m", []):
            mods = [node_text(c) for c in m.children if c.type == "modifier"]
            ret = m.child_by_field_name("returns") or m.child_by_field_name("type")
            if "async" not in mods or ret is None or node_text(ret) != "void":
                continue
            params = m.child_by_field_name("parameters")
            ptext = node_text(params) if params is not None else ""
            if "EventArgs" in ptext and "sender" in ptext:
                continue  # conventional event-handler signature
            out.append(_finding(self, sf, m,
                                "async void cannot be awaited and its exceptions crash the "
                                "process; return Task instead."))
        return out


class BlockingTaskWait(Rule):
    id = "D002"
    severity = Severity.YELLOW
    title = "Blocking on task (.Result / .Wait() / GetAwaiter().GetResult())"
    precision = "heuristic"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        root = sf.tree.root_node
        for node in captures("csharp", root, "(member_access_expression) @a").get("a", []):
            name = node.child_by_field_name("name")
            obj = node.child_by_field_name("expression")
            if name is None or obj is None:
                continue
            prop = node_text(name)
            objt = node_text(obj)
            async_obj = obj.type == "invocation_expression" and "Async" in objt
            if prop == "Result" and async_obj:
                out.append(_finding(self, sf, node,
                                    ".Result on an async call blocks the thread (deadlock risk); await it."))
            elif prop in ("Wait", "GetResult") and (async_obj or "GetAwaiter" in objt):
                out.append(_finding(self, sf, node.parent if node.parent is not None else node,
                                    "Synchronous wait on a task (deadlock risk); use await."))
        return out


class RawSqlInterpolation(Rule):
    id = "D003"
    severity = Severity.RED
    title = "Interpolated/concatenated SQL passed to raw-SQL API"
    precision = "heuristic"

    def check(self, sf: SourceFile) -> list[Finding]:
        out = []
        for call in captures("csharp", sf.tree.root_node, "(invocation_expression) @i").get("i", []):
            fn = call.child_by_field_name("function")
            if fn is None or not _RAW_SQL_APIS.search(node_text(fn)):
                continue
            args = call.child_by_field_name("arguments")
            if args is None:
                continue
            dynamic = False
            stack = list(args.named_children)
            while stack:
                cur = stack.pop()
                if cur.type in ("interpolation", "binary_expression"):
                    dynamic = True
                    break
                stack.extend(cur.named_children)
            if dynamic:
                out.append(_finding(self, sf, call,
                                    "Raw-SQL API receives interpolated/concatenated input — "
                                    "SQL injection; use parameters (e.g. FromSqlInterpolated "
                                    "or SqlParameter)."))
        return out
```

Wire `language_rules` into the adapters:
```python
# java/adapter.py
    def language_rules(self):
        from auditor.adapters.java.rules import MissingTryWithResources, StringEqualsCompare
        return [StringEqualsCompare(), MissingTryWithResources()]

# dotnet/adapter.py
    def language_rules(self):
        from auditor.adapters.dotnet.rules import (AsyncVoidMethod, BlockingTaskWait,
                                                   RawSqlInterpolation)
        return [AsyncVoidMethod(), BlockingTaskWait(), RawSqlInterpolation()]
```

- [ ] **Step 4: Run both new test files — PASS.** If `AsyncVoidMethod` finds zero, dump the CST (`sf.tree.root_node`) — the C# grammar names the return-type field `returns` in some versions and `type` in others; the dual lookup above covers both, but verify against the installed tree-sitter-c-sharp 0.23.5 and keep whichever field resolves.
- [ ] **Step 5: Commit** — `feat(engine2): lizard complexity + Java/.NET language rules`

### Task 21: Pattern-engine orchestrator + optional semgrep/opengrep layer

**Files:**
- Create: `src\auditor\core\patterns.py`, `src\auditor\core\semgrep_runner.py`, `src\auditor\semgrep_rules\auditor-extra.yml`
- No `pyproject.toml` change needed: hatchling packages `src/auditor` wholesale, so the bundled YAML ships inside the wheel (spot-check with a wheel build only if distribution problems appear).
- Test: `tests\test_patterns_semgrep.py`

**Interfaces:**
- Produces: `patterns.run_pattern_engine(adapter, project_root: Path, files: list[SourceFile], frameworks: list[str], diag: Diagnostics | None = None) -> list[Finding]` = `common_rules(adapter.syntax())` + `adapter.language_rules()` (framework-filtered) + `complexity_findings(files)` + `adapter.project_rules(project_root, frameworks)`; every parse/rule failure is recorded in `diag`, never swallowed. `patterns.dedupe(findings)` collapses ONLY exact `(rule_id, file, line)` duplicates — cross-engine findings on the same line are all kept (v2 policy). `semgrep_runner.find_binary(explicit: str | None = None) -> tuple[str, str] | None` (returns (path, version); prefers `opengrep` then `semgrep` on PATH); `semgrep_runner.run_semgrep(binary: str, project_root: Path, extra_configs: list[str], expected_paths: set[str] | None = None) -> tuple[list[Finding], str]` where status ∈ `success | partial (...) | failed | failed (exit N) | timed_out | invalid_output` — returncode ∉ (0, 1) is a failure (measured: config errors exit 7); completeness is reconciled from `paths.scanned` vs `expected_paths` PLUS the JSON `errors`/`paths.skipped` arrays (any gap ⇒ partial), because rc+valid-JSON alone do NOT prove coverage (measured: a tolerated broken file scans clean); zero findings is NEVER conflated with engine failure; findings map (`check_id`, `path`, `start.line`, `extra.message`, `extra.severity`) to `rule_id="S:"+check_id`; never raises; `semgrep_runner.bundled_rules_path() -> Path` via `importlib.resources`.

- [ ] **Step 1: Write the bundled YAML** (our own rules, MIT — complements builtins, no overlap with P/R/N/J/D ids)

`src\auditor\semgrep_rules\auditor-extra.yml` (ASCII, UTF-8, NO BOM):
```yaml
# Provenance: original rules written for ai-code-auditor (MIT), authored from
# first principles against public API documentation (eval/exec, pickle,
# child_process, Runtime.exec, weak hashes). NOT derived from, copied from, or
# adapted from the Semgrep Registry or any Semgrep-Rules-License content.
rules:
  - id: auditor-python-eval-input
    languages: [python]
    severity: ERROR
    message: eval()/exec() on dynamic input executes arbitrary code.
    patterns:
      - pattern-either:
          - pattern: eval(...)
          - pattern: exec(...)
      - pattern-not: eval("...")
      - pattern-not: exec("...")
  - id: auditor-python-pickle-load
    languages: [python]
    severity: WARNING
    message: pickle.load/loads on untrusted data enables code execution.
    pattern-either:
      - pattern: pickle.load(...)
      - pattern: pickle.loads(...)
  - id: auditor-js-child-process-concat
    languages: [typescript, javascript]
    severity: ERROR
    message: Shell command built from dynamic strings (command injection).
    pattern-either:
      - pattern: exec(`...${...}...`)
      - pattern: execSync(`...${...}...`)
  - id: auditor-java-runtime-exec-concat
    languages: [java]
    severity: ERROR
    message: Runtime.exec with concatenated input (command injection).
    pattern: Runtime.getRuntime().exec($X + $Y)
  - id: auditor-weak-hash
    languages: [python, typescript, javascript, java, csharp]
    severity: WARNING
    message: MD5/SHA1 are broken for security purposes.
    pattern-regex: (?i)\b(md5|sha-?1)\s*[(.]
```

- [ ] **Step 2: Write the failing tests**

`tests\test_patterns_semgrep.py`:
```python
import json
from pathlib import Path

from auditor.core import semgrep_runner
from auditor.core.models import Finding, Severity
from auditor.core.patterns import dedupe, run_pattern_engine


def test_pattern_engine_on_python_fixture(fixtures_dir):
    from auditor.adapters.python.adapter import PythonAdapter
    from auditor.core.walk import collect_source_files
    root = fixtures_dir / "python_repo"
    a = PythonAdapter()
    files = collect_source_files(root, a)
    fs = run_pattern_engine(a, root, files, frameworks=[])
    ids = {f.rule_id for f in fs}
    assert {"P001", "P002", "P005", "P006", "P007"} <= ids


def test_framework_filter_skips_react_rules_for_plain_ts(fixtures_dir):
    from auditor.adapters.typescript.adapter import TypeScriptAdapter
    from auditor.core.walk import collect_source_files
    root = fixtures_dir / "ts_repo"
    a = TypeScriptAdapter()
    files = collect_source_files(root, a)
    without = run_pattern_engine(a, root, files, frameworks=[])
    with_fw = run_pattern_engine(a, root, files, frameworks=["react", "next"])
    assert not any(f.rule_id.startswith(("R", "N")) for f in without)
    assert any(f.rule_id.startswith("R") for f in with_fw)
    assert any(f.rule_id == "N001" for f in with_fw)  # .env.local scan


def test_project_rules_failure_counts_and_forbids_pass(tmp_path):
    # fifth-round: a crashing project_rules previously hit rule_errors WITHOUT
    # rule_failures, leaving confidence 100 and verdict PASS
    from auditor.core.models import Diagnostics, SourceFile
    from auditor.core.patterns import run_pattern_engine
    from auditor.core.scoring import analysis_confidence, verdict

    class BoomAdapter:
        name = "python"
        def syntax(self):
            from auditor.adapters.python.adapter import PythonAdapter
            return PythonAdapter().syntax()
        def language_rules(self):
            return []
        def project_rules(self, root, frameworks):
            raise RuntimeError("project rule exploded")

    sf = SourceFile(path=tmp_path / "a.py", rel="a.py", language="python", text=b"x = 1\n")
    diag = Diagnostics()
    run_pattern_engine(BoomAdapter(), tmp_path, [sf], [], diag=diag)
    assert diag.rule_failures >= 1 and diag.rule_attempted >= 1
    conf = analysis_confidence(diag, offline=False, files_read=1)
    assert conf < 100
    assert verdict({"red": 0, "yellow": 0}, conf,
                   {"rule_attempted": diag.rule_attempted,
                    "rule_failures": diag.rule_failures}) != "pass"


def test_dedupe_keeps_different_findings_on_same_line():
    builtin = Finding("P005", Severity.RED, "t", "a.py", 10)
    sg_other = Finding("S:x.other-rule", Severity.RED, "t", "a.py", 10, engine="semgrep")
    exact_dup = Finding("P005", Severity.RED, "t", "a.py", 10)
    out = dedupe([sg_other, builtin, exact_dup])
    assert [f.rule_id for f in out] == ["P005", "S:x.other-rule"]  # both kept, dup collapsed


def test_find_binary_none_when_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert semgrep_runner.find_binary() is None


def test_run_semgrep_parses_json(monkeypatch, tmp_path):
    canned = {"results": [{
        "check_id": "auditor-python-eval-input",
        "path": str(tmp_path / "x.py"),
        "start": {"line": 3},
        "extra": {"message": "eval bad", "severity": "ERROR"},
    }]}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep("semgrep", tmp_path, [])
    assert status == "success" and len(fs) == 1
    f = fs[0]
    assert f.rule_id == "S:auditor-python-eval-input" and f.severity == Severity.RED
    assert f.file == "x.py" and f.line == 3 and f.engine == "semgrep"


def test_run_semgrep_failure_states_are_distinct(monkeypatch, tmp_path):
    import subprocess as sp

    def boom(*a, **k):
        raise OSError("no binary")
    monkeypatch.setattr("subprocess.run", boom)
    assert semgrep_runner.run_semgrep("nope.exe", tmp_path, []) == ([], "failed")

    def slow(*a, **k):
        raise sp.TimeoutExpired(cmd="x", timeout=600)
    monkeypatch.setattr("subprocess.run", slow)
    assert semgrep_runner.run_semgrep("x", tmp_path, [])[1] == "timed_out"

    class BadExit:
        returncode = 7   # measured: semgrep config errors exit 7
        stdout = "{}"
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: BadExit())
    assert semgrep_runner.run_semgrep("x", tmp_path, [])[1] == "failed (exit 7)"

    class Garbage:
        returncode = 0
        stdout = "not json {"
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: Garbage())
    assert semgrep_runner.run_semgrep("x", tmp_path, [])[1] == "invalid_output"


def test_run_semgrep_results_and_errors_together_is_partial(monkeypatch, tmp_path):
    canned = {"results": [{"check_id": "r", "path": str(tmp_path / "a.py"),
                           "start": {"line": 1},
                           "extra": {"message": "m", "severity": "WARNING"}}],
              "errors": [{"type": "SyntaxError", "path": str(tmp_path / "broken.py")}],
              "paths": {"scanned": [str(tmp_path / "a.py")]}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep("x", tmp_path, [])
    assert len(fs) == 1                       # findings are kept
    assert "partial" in status and "1 file errors" in status  # completeness not claimed


def test_run_semgrep_unscanned_expected_file_is_partial(monkeypatch, tmp_path):
    # fifth-round: rc=0, errors=0, yet a targeted file silently not scanned
    a, b = tmp_path / "a.py", tmp_path / "b.py"
    canned = {"results": [], "errors": [], "paths": {"scanned": [str(a)]}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    fs, status = semgrep_runner.run_semgrep("x", tmp_path, [],
                                            expected_paths={str(a), str(b)})
    assert fs == [] and "partial" in status and "not scanned" in status


def test_run_semgrep_full_coverage_is_success(monkeypatch, tmp_path):
    a = tmp_path / "a.py"
    canned = {"results": [], "errors": [], "paths": {"scanned": [str(a)]}}

    class P:
        returncode = 0
        stdout = json.dumps(canned)
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    assert semgrep_runner.run_semgrep("x", tmp_path, [], expected_paths={str(a)})[1] == "success"


def test_bundled_rules_exist_and_bom_free():
    p = semgrep_runner.bundled_rules_path()
    raw = p.read_bytes()
    assert raw and not raw.startswith(b"\xef\xbb\xbf")
```

- [ ] **Step 3: Run — fail. Then implement**

`src\auditor\core\patterns.py` (v2: zero adapter imports — env scanning arrives via `adapter.project_rules()`; failures land in Diagnostics, never swallowed; cross-engine suppression removed):
```python
from __future__ import annotations

from pathlib import Path

from auditor.core.complexity import complexity_findings
from auditor.core.models import Diagnostics, Finding, SourceFile
from auditor.core.rules_common import common_rules
from auditor.core.treesitter import parse_source


def run_pattern_engine(adapter, project_root: Path, files: list[SourceFile],
                       frameworks: list[str], diag: Diagnostics | None = None) -> list[Finding]:
    rules = [*common_rules(adapter.syntax()), *adapter.language_rules()]
    active = [r for r in rules
              if not r.frameworks or set(r.frameworks) & set(frameworks)]
    findings: list[Finding] = []
    for sf in files:
        try:
            parse_source(sf)
        except Exception as e:
            _note(diag, "parse_error_files", f"{sf.rel}: {e.__class__.__name__}")
            continue
        if sf.tree.root_node.has_error:
            _note(diag, "parse_error_files", f"{sf.rel}: partial parse (syntax errors)")
        for rule in active:
            if diag is not None:
                diag.rule_attempted += 1
            try:
                findings += rule.check(sf)
            except Exception as e:
                if diag is not None:
                    diag.rule_failures += 1
                _note(diag, "rule_errors", f"{rule.id} on {sf.rel}: {e.__class__.__name__}")
    # complexity and project_rules are rule invocations too — count them so a
    # failure lowers confidence and forbids pass (fifth-round: project_rules
    # exceptions previously hit rule_errors WITHOUT rule_failures, leaving
    # confidence 100 and a PASS verdict). complexity does its OWN per-file
    # attempt/failure accounting inside complexity_findings; this wrapper only
    # covers a catastrophic whole-call raise.
    try:
        findings += complexity_findings(files, diag=diag)
    except Exception as e:
        if diag is not None:
            diag.rule_attempted += 1
            diag.rule_failures += 1
        _note(diag, "rule_errors", f"complexity({adapter.name}): {e.__class__.__name__}")
    if diag is not None:
        diag.rule_attempted += 1
    try:
        findings += adapter.project_rules(project_root, frameworks)
    except Exception as e:
        if diag is not None:
            diag.rule_failures += 1
        _note(diag, "rule_errors", f"project_rules({adapter.name}): {e.__class__.__name__}")
    return dedupe(findings)


def _note(diag: Diagnostics | None, field_name: str, message: str) -> None:
    if diag is not None:
        getattr(diag, field_name).append(message)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """v2 policy: engines are complementary by design, so a semgrep finding is
    NEVER dropped just for sharing a line with a builtin one (that silently ate
    real, different findings). Only exact duplicates collapse."""
    seen: set[tuple[str, str, int]] = set()
    out: list[Finding] = []
    for f in sorted(findings, key=lambda f: (f.file, f.line, f.rule_id, f.engine)):
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
```

`src\auditor\core\semgrep_runner.py`:
```python
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
    """Returns (findings, status). Status ∈ success | partial (...) | failed |
    timed_out | invalid_output — zero findings must NEVER be confusable with
    engine failure OR with incomplete coverage. Measured exit codes
    (evidence/README.md): clean scan = 0; config errors = 7 ⇒ not in (0,1).
    Completeness (fifth-round): rc+JSON validity do NOT prove it — semgrep can
    tolerate/skip files. We reconcile `paths.scanned` against the source files we
    EXPECTED it to cover (`expected_paths`, absolute POSIX). Any expected file
    missing from scanned, or a non-empty `errors`/`paths.skipped`, demotes
    success to partial."""
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
    # Completeness reconciliation (fifth-round): errors + skipped + scanned-vs-expected
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
    status = "success" if not reasons else "partial (" + ", ".join(reasons) + ")"
    out: list[Finding] = []
    for res in data.get("results", []):
        try:
            rel = Path(res["path"]).resolve().relative_to(project_root.resolve()).as_posix()
        except ValueError:
            rel = Path(res.get("path", "?")).name
        extra = res.get("extra", {})
        out.append(Finding(
            rule_id="S:" + res.get("check_id", "unknown"),
            severity=_SEV_MAP.get(extra.get("severity", "WARNING"), Severity.YELLOW),
            title=(extra.get("message") or "semgrep finding").splitlines()[0][:100],
            file=rel, line=int(res.get("start", {}).get("line", 0)),
            snippet="", detail=extra.get("message", ""), language="",
            engine="semgrep"))
    return out, status
```

- [ ] **Step 4: Run `tests\test_patterns_semgrep.py` — PASS.** Also run an OPTIONAL live check (skip silently if no binary): `.venv\Scripts\python -c "from auditor.core.semgrep_runner import *; b=find_binary(); print(b and run_semgrep(b[0], __import__('pathlib').Path('tests/fixtures/python_repo'), []))"`.
- [ ] **Step 5: Run the FULL suite** — all previous fixtures now also satisfy the Phase-6 assertions planted in Tasks 9/14/16/18.
- [ ] **Step 6: Commit** — `feat(engine2): pattern orchestrator, dedupe, optional opengrep/semgrep layer with bundled MIT rules`

**PHASE CHECKPOINT CP-6 — STOP.** Present to the user: Engine 2 complete — builtin rules + complexity + optional semgrep layer; licensing stance (own YAML only; registry packs opt-in via `--semgrep-config` at user's own responsibility). Show pattern findings from all four fixture repos.
**Gate:** core-neutrality test green (`test_no_language_names_in_core_rules_module`) and `grep "from auditor.adapters" src/auditor/core/` returns nothing; dedupe same-line-different-finding test green; rule exceptions land in Diagnostics (demonstrate one intentionally-broken rule surfacing in report.json). **Blockers:** any silent rule failure. **Deferred decisions:** none.

---

## PHASE 7 — Scoring, reports, full CLI

### Task 22: Scoring + report builders (md + json)

**Files:**
- Create: `src\auditor\core\scoring.py`, `src\auditor\report\build.py`, `src\auditor\report\json_out.py`, `src\auditor\report\markdown.py`
- Test: `tests\test_scoring.py`, `tests\test_report.py`

**Interfaces:**
- Produces: `scoring.WEIGHTS = {Severity.RED: 15, Severity.YELLOW: 5, Severity.BLUE: 1}`; `scoring.language_score(findings) -> int` (`max(0, 100 - Σ weight)`); `scoring.overall_score(parts: list[tuple[int, int]]) -> int | None` (list of `(score, file_count)`, file-count-weighted rounded average, `None` for empty). `build.build_report(target: str, projects: list[dict], engines: dict, limitations: list[str]) -> dict` where each project dict arrives as `{"language", "root", "frameworks", "file_count", "findings": list[Finding]}` and leaves with added `"score"`, `"counts"`; report dict carries keys `tool, version, generated_at, target, engines, summary{overall_score, counts}, scoring_formula, projects, limitations`. `json_out.write_json(data, path)`; `markdown.write_markdown(data, path)` rendering: executive summary, engines table, score table with the formula, per-language findings tables (🔴/🟡/🔵 icon, rule, `file:line`, snippet, detail), limitations section.

- [ ] **Step 1: Write the failing tests**

`tests\test_scoring.py`:
```python
from auditor.core.models import Finding, Severity
from auditor.core.scoring import language_score, overall_score


def _f(sev):
    return Finding("X", sev, "t", "f", 1)


def test_language_score_excludes_blue_from_risk():
    fs = [_f(Severity.RED), _f(Severity.YELLOW), _f(Severity.BLUE)]
    assert language_score(fs) == 100 - 15 - 5  # blue is informational, not risk


def test_language_score_floors_at_zero():
    assert language_score([_f(Severity.RED)] * 10) == 0


def test_overall_weighted_by_files():
    assert overall_score([(100, 1), (50, 3)]) == round((100 * 1 + 50 * 3) / 4)
    assert overall_score([]) is None


def test_confidence_is_coverage_ratio_based():
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence
    clean = Diagnostics(semgrep_status="opengrep 1.25.0: success")
    assert analysis_confidence(clean, offline=False, files_read=10) == 100
    assert analysis_confidence(clean, offline=True, files_read=10) == 50
    # denominators matter: 5-of-5 skipped is a disaster, 5-of-50000 is noise
    tiny = Diagnostics(skipped_files=["a", "b", "c", "d", "e"],
                       semgrep_status="x: success")
    assert analysis_confidence(tiny, offline=False, files_read=0) == 0
    huge = Diagnostics(skipped_files=["a", "b", "c", "d", "e"],
                       semgrep_status="x: success")
    assert analysis_confidence(huge, offline=False, files_read=49_995) == 100


def test_fourth_round_counterexamples_are_closed():
    """100/100 parse errors gave 70=PASS and all-rules-failed gave 80=PASS
    under coverage-v1 (measured). Both must be 0 => block under v2."""
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence, verdict
    all_parse = Diagnostics(parse_error_files=[f"f{i}.ts" for i in range(100)],
                            semgrep_status="x: success")
    assert analysis_confidence(all_parse, offline=False, files_read=100) == 0
    all_rules = Diagnostics(rule_attempted=400, rule_failures=400,
                            semgrep_status="x: success")
    assert analysis_confidence(all_rules, offline=False, files_read=100) == 0
    assert verdict({"red": 0, "yellow": 0}, 0,
                   {"rule_attempted": 400, "rule_failures": 400}) == "block"


def test_manifest_cov_counts_unique_files_not_reads():
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence
    # same broken file read 3 times: 1 unique file, 1 unique error => cov 0, not 2/3
    d = Diagnostics(manifest_files=["pyproject.toml"],
                    manifest_errors=["pyproject.toml: TOMLDecodeError"],
                    semgrep_status="x: success")
    d2 = Diagnostics(manifest_files=["pyproject.toml", "requirements.txt", "Pipfile"],
                     manifest_errors=["pyproject.toml: TOMLDecodeError"],
                     semgrep_status="x: success")
    assert analysis_confidence(d, False, 10) < analysis_confidence(d2, False, 10)


def test_monorepo_two_corrupt_manifests_give_zero_coverage(tmp_path):
    # fifth-round: two pyproject.toml in different roots must NOT merge by name
    from auditor.adapters.python.adapter import PythonAdapter
    from auditor.core.models import Diagnostics
    from auditor.core.scoring import analysis_confidence
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "pyproject.toml").write_text("[project\nx", encoding="utf-8")
    (tmp_path / "b" / "pyproject.toml").write_text("[project\ny", encoding="utf-8")
    diag = Diagnostics()
    PythonAdapter().parse_dependencies(tmp_path / "a", diag=diag)
    d2 = Diagnostics()
    PythonAdapter().parse_dependencies(tmp_path / "b", diag=d2)
    diag.merge(d2)
    assert len(set(diag.manifest_errors)) == 2   # distinct by full path
    assert len(set(diag.manifest_files)) == 2
    # both manifests broken => manifest coverage 0
    assert analysis_confidence(diag, offline=False, files_read=5) == 0


def test_verdict_contract():
    from auditor.core.scoring import verdict
    assert verdict({"red": 1, "yellow": 0}, 100, {}) == "block"
    assert verdict({"red": 0, "yellow": 0}, 39, {}) == "block"     # incomplete ≠ passed
    assert verdict({"red": 0, "yellow": 2}, 100, {}) == "review"
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"manifest_errors": ["x"]}) == "review"
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"rule_attempted": 50, "rule_failures": 1}) == "review"  # ANY rule failure ≠ pass
    assert verdict({"red": 0, "yellow": 0}, 100, {}) == "pass"
```

`tests\test_report.py`:
```python
import json
from pathlib import Path

from auditor.core.models import Finding, Severity
from auditor.report.build import build_report
from auditor.report.json_out import write_json
from auditor.report.markdown import write_markdown


def _data():
    findings = [
        Finding("H001", Severity.RED, "Declared dependency not found in registry",
                "requirements.txt", 2, snippet="ghost-ai-utils==9.9.9",
                detail="ghost-ai-utils ...", language="python"),
        Finding("P001", Severity.YELLOW, "Empty catch", "app.py", 11, language="python"),
        Finding("P005", Severity.RED, "SQL sink", "app.py", 20, language="python",
                precision="heuristic"),
    ]
    return build_report(
        target="https://github.com/x/y",
        projects=[{"language": "python", "root": ".", "frameworks": [],
                   "file_count": 2, "findings": findings}],
        engines={"registry": "online", "semgrep": "not available",
                 "ast": "tree-sitter 0.26", "complexity": "lizard"},
        limitations=["Maven Central exposes no download counts"])


def test_build_report_scores_and_counts():
    data = _data()
    assert data["projects"][0]["score"] == 100 - 2 * 15 - 5   # 2 red + 1 yellow = 65
    assert data["projects"][0]["counts"] == {"red": 2, "yellow": 1, "blue": 0}
    assert data["summary"]["overall_score"] == 65
    assert data["summary"]["verdict"] == "block"
    assert "100" in data["scoring_formula"]


def test_json_report_roundtrip(tmp_path):
    p = tmp_path / "report.json"
    write_json(_data(), p)
    loaded = json.loads(p.read_text(encoding="utf-8"))
    assert loaded["projects"][0]["findings"][0]["severity"] == "red"
    by_rule = {f["rule_id"]: f for f in loaded["projects"][0]["findings"]}
    assert by_rule["P005"]["precision"] == "heuristic"   # never defaults to exact
    assert by_rule["H001"]["precision"] == "exact"


def test_report_redacts_credentials_in_snippets():
    from auditor.core.models import Finding, Severity
    data = build_report(
        target="x",
        projects=[{"language": "python", "root": ".", "frameworks": [], "file_count": 1,
                   "findings": [Finding("H001", Severity.RED, "t", "requirements.txt", 1,
                                        snippet="pkg @ https://user:S3cretPass@host/x.whl")]}],
        engines={}, limitations=[])
    snip = data["projects"][0]["findings"][0]["snippet"]
    assert "S3cretPass" not in snip and "user:***@" in snip


def test_markdown_report_contains_the_essentials(tmp_path):
    p = tmp_path / "report.md"
    write_markdown(_data(), p)
    md = p.read_text(encoding="utf-8")
    for token in ("AI Code Auditor", "🔴", "🟡", "python", "requirements.txt:2",
                  "Limitations", "max(0, 100", "P005*"):
        assert token in md, token
    assert "P001*" not in md   # exact findings carry no heuristic marker
```

- [ ] **Step 2: Run — fail. Then implement**

`src\auditor\core\scoring.py` (v2: risk and confidence are DIFFERENT axes — offline
mode and unverifiable packages lower confidence, never "risk"; BLUE findings are
informational and excluded from risk entirely; the weighted average is never
allowed to hide a red — the summary always carries lowest-language + red count):
```python
from __future__ import annotations

from auditor.core.models import Diagnostics, Finding, Severity

WEIGHTS = {Severity.RED: 15, Severity.YELLOW: 5}
FORMULA = (
    "code_health per language = max(0, 100 - 15*red - 5*yellow) — HIGHER is "
    "safer (this is a health/safety score, deliberately NOT named 'risk'); blue "
    "findings are informational and never affect health; overall = file-count-"
    "weighted average, ALWAYS reported alongside lowest language and red count. "
    "analysis_confidence = coverage-v2 (experimental): round(100 * file_coverage "
    "* manifest_coverage * (0.5 + 0.5*registry_coverage) * rule_health * "
    "parse_factor * semgrep_factor) where file_coverage = read/(read+skipped), "
    "manifest_coverage = 1 - unique_error_files/unique_manifest_files, "
    "registry_coverage = 0 offline else 1 - failures/attempted, "
    "rule_health = 1 - rule_failures/rule_attempted (uncapped), "
    "parse_factor = 1 - min(1, parse_errors/files_read) (uncapped), "
    "semgrep_factor = 1.0 success / 0.97 partial / 0.95 otherwise. "
    "verdict: block if red>0 or confidence<40 or ALL rule invocations failed; "
    "review if yellow>0 or confidence<70 or any manifest/rule/parse failure; "
    "else pass — any rule failure forbids pass."
)


def language_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(WEIGHTS.get(f.severity, 0) for f in findings))


def overall_score(parts: list[tuple[int, int]]) -> int | None:
    total_files = sum(n for _, n in parts)
    if not total_files:
        return None
    return round(sum(score * n for score, n in parts) / total_files)


def analysis_confidence(diag: Diagnostics, offline: bool, files_read: int) -> int:
    """Coverage-v2 (experimental, ratio-based): skipping 5 of 5 files is NOT the
    same as 5 of 50,000 — every deduction is a denominator-aware ratio, and the
    fourth-round counterexamples are closed: 100% parse failure or 100% rule
    failure drives confidence to 0 (uncapped ratios), never a silent 70/80."""
    seen = files_read + len(diag.skipped_files)
    file_cov = files_read / seen if seen else 1.0
    m_files = len(set(diag.manifest_files))
    m_err = len(set(diag.manifest_errors))
    manifest_cov = 1.0 - m_err / max(1, m_files, m_err)
    if offline:
        registry_cov = 0.0
    elif diag.registry_attempted:
        registry_cov = 1.0 - diag.registry_failures / diag.registry_attempted
    else:
        registry_cov = 1.0
    rule_health = 1.0 - (diag.rule_failures / diag.rule_attempted
                         if diag.rule_attempted else 0.0)
    parse_factor = 1.0 - min(1.0, len(diag.parse_error_files) / max(1, files_read))
    sg = diag.semgrep_status
    sg_factor = 1.0 if sg.endswith("success") else (0.97 if "partial" in sg else 0.95)
    return round(100 * file_cov * manifest_cov * (0.5 + 0.5 * registry_cov)
                 * rule_health * parse_factor * sg_factor)


def verdict(counts: dict, confidence: int, diag: dict) -> str:
    """Product contract: ANY rule failure forbids pass; total collapse of a
    mandatory dimension (all builtin rules failed, or confidence floor) is a
    block; an OPTIONAL engine (semgrep) that actually STARTED and then failed or
    ran partially forbids pass too (fifth-round: partial=97/failed=95 must not
    slip through as pass)."""
    attempted = diag.get("rule_attempted", 0)
    failures = diag.get("rule_failures", 0)
    total_rule_collapse = attempted > 0 and failures >= attempted
    if counts.get("red", 0) > 0 or confidence < 40 or total_rule_collapse:
        return "block"
    sg = diag.get("semgrep_status", "")
    # "not available"/"not attempted"/"success" are fine; a started-then-broken
    # optional engine is a coverage gap the user must see
    sg_degraded = any(k in sg for k in ("partial", "failed", "timed_out",
                                        "invalid_output"))
    if counts.get("yellow", 0) > 0 or confidence < 70 \
            or diag.get("manifest_errors") or failures \
            or diag.get("rule_errors") \
            or diag.get("parse_error_files") or sg_degraded:
        return "review"   # ANY recorded rule error forbids pass, counters aside
    return "pass"
```

`src\auditor\report\build.py`:
```python
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from auditor import __version__
from auditor.core.models import Finding, Severity
from auditor.core.scoring import FORMULA, language_score, overall_score, verdict


import re as _re

_CRED_URL = _re.compile(r"(\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"]{1,64}:)([^@/\s'\"]{2,})(@)")
_TOKEN_PARAM = _re.compile(r"((?:token|key|secret|password|pwd|auth)=)([^&\s'\"]{4,})", _re.I)


def _redact(text: str) -> str:
    """Reports must never leak credentials that appear in dep lines / configs
    (e.g. `pkg @ https://user:PASS@host/...`)."""
    text = _CRED_URL.sub(r"\1***\3", text)
    return _TOKEN_PARAM.sub(r"\1***", text)


def _counts(findings: list[Finding]) -> dict[str, int]:
    return {sev.value: sum(1 for f in findings if f.severity is sev) for sev in Severity}


def build_report(target: str, projects: list[dict], engines: dict,
                 limitations: list[str], diagnostics: dict | None = None,
                 confidence: int | None = None) -> dict:
    out_projects = []
    parts = []
    all_counts = {"red": 0, "yellow": 0, "blue": 0}
    lowest: tuple[str, int] | None = None
    for proj in projects:
        findings: list[Finding] = proj["findings"]
        score = language_score(findings)
        counts = _counts(findings)
        for k in all_counts:
            all_counts[k] += counts[k]
        parts.append((score, max(1, proj.get("file_count", 1))))
        if lowest is None or score < lowest[1]:
            lowest = (proj["language"], score)
        out_projects.append({
            "language": proj["language"], "root": proj["root"],
            "frameworks": proj.get("frameworks", []),
            "file_count": proj.get("file_count", 0),
            "score": score, "counts": counts,
            "findings": [dict(asdict(f), severity=f.severity.value,
                              snippet=_redact(f.snippet), detail=_redact(f.detail))
                         for f in findings],
        })
    return {
        "tool": "ai-code-auditor",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "engines": engines,
        "summary": {
            "overall_score": overall_score(parts),
            "score_kind": "code_health (higher = safer; experimental indicator)",
            "lowest_language": {"language": lowest[0], "score": lowest[1]} if lowest else None,
            "counts": all_counts,
            "analysis_confidence": confidence,
            "verdict": verdict(all_counts, confidence if confidence is not None else 100,
                               diagnostics or {}),
        },
        "scoring_formula": FORMULA,
        "projects": out_projects,
        "diagnostics": diagnostics or {},
        "limitations": limitations,
    }
```

`src\auditor\report\json_out.py`:
```python
from __future__ import annotations

import json
from pathlib import Path


def write_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
```

`src\auditor\report\markdown.py`:
```python
from __future__ import annotations

from pathlib import Path

_ICON = {"red": "🔴", "yellow": "🟡", "blue": "🔵"}


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def write_markdown(data: dict, path: Path) -> None:
    L: list[str] = []
    s = data["summary"]
    overall = s["overall_score"]
    L.append("# AI Code Auditor Report")
    L.append("")
    L.append(f"**Target:** `{data['target']}`  ")
    L.append(f"**Generated:** {data['generated_at']}  ")
    L.append(f"**Tool:** {data['tool']} v{data['version']}")
    L.append("")
    L.append("## Executive Summary | الملخص التنفيذي")
    L.append("")
    score_txt = "N/A (no supported languages detected)" if overall is None else f"**{overall}/100**"
    L.append(f"Overall code-health score (higher = safer) | درجة سلامة الكود: {score_txt}")
    L.append(f"**Verdict | الحكم الآلي: `{s.get('verdict', 'n/a').upper()}`**")
    c = s["counts"]
    L.append(f"- 🔴 Critical: {c['red']}   🟡 Warning: {c['yellow']}   🔵 Info: {c['blue']}")
    low = s.get("lowest_language")
    if low and overall is not None and low["score"] < overall:
        L.append(f"- ⚠️ Lowest language | أدنى لغة: **{low['language']} = {low['score']}/100** "
                 "(the average must not hide this)")
    if s.get("analysis_confidence") is not None:
        L.append(f"- Analysis confidence | ثقة التحليل: {s['analysis_confidence']}/100 "
                 "(separate axis: how COMPLETE the checks were, not how risky the code is)")
    L.append("")
    L.append("## Engines")
    L.append("")
    L.append("| Engine | Status |")
    L.append("|---|---|")
    for k, v in data["engines"].items():
        L.append(f"| {k} | {v} |")
    L.append("")
    L.append("## Scores per language")
    L.append("")
    L.append("| Language | Files | Score | 🔴 | 🟡 | 🔵 |")
    L.append("|---|---|---|---|---|---|")
    for p in data["projects"]:
        pc = p["counts"]
        L.append(f"| {p['language']} (`{p['root']}`) | {p['file_count']} | "
                 f"**{p['score']}/100** | {pc['red']} | {pc['yellow']} | {pc['blue']} |")
    L.append("")
    L.append(f"**Scoring contract | عقد الدرجات:** `{data['scoring_formula']}` "
             "— i.e. `max(0, 100 - 15*🔴 - 5*🟡)` per language; 🔵 is informational "
             "and never changes the score. Findings marked `*` are heuristic "
             "(`precision: heuristic`), not proofs.")
    L.append("")
    for p in data["projects"]:
        L.append(f"## {p['language'].capitalize()} — `{p['root']}` "
                 f"({p['score']}/100)")
        if p["frameworks"]:
            L.append(f"Frameworks: {', '.join(p['frameworks'])}")
        L.append("")
        if not p["findings"]:
            L.append("No findings. | لا توجد ملاحظات.")
            L.append("")
            continue
        L.append("| Sev | Rule | Location | Snippet | Detail |")
        L.append("|---|---|---|---|---|")
        for f in p["findings"]:
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            marker = "*" if f.get("precision") == "heuristic" else ""
            L.append(f"| {_ICON[f['severity']]} | {f['rule_id']}{marker} | `{loc}` | "
                     f"`{_md_escape(f['snippet'][:60]) or '-'}` | "
                     f"{_md_escape(f['detail'][:200] or f['title'])} |")
        L.append("")
    diag = data.get("diagnostics") or {}
    if any(diag.get(k) for k in ("manifest_errors", "skipped_files",
                                 "parse_error_files", "rule_errors")):
        L.append("## Diagnostics | تشخيصات التحليل")
        L.append("")
        for key in ("manifest_errors", "skipped_files", "parse_error_files", "rule_errors"):
            for item in diag.get(key, []):
                L.append(f"- `{key}`: {item}")
        L.append("")
    L.append("## Limitations | حدود الفحص")
    L.append("")
    for item in data["limitations"] or ["None."]:
        L.append(f"- {item}")
    L.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L), encoding="utf-8")
```

- [ ] **Step 3: Run both test files — PASS.**
- [ ] **Step 4: Commit** — `feat(report): documented scoring + markdown/json report generators`

### Task 23: Full CLI + monorepo fixture + CLI E2E

**Files:**
- Create: `src\auditor\adapters\__init__.py` content (replace empty file), `src\auditor\core\ownership.py`, `tests\fixtures\monorepo\...` (copies described below)
- Modify: `src\auditor\cli.py` (full implementation)
- Test: `tests\test_ownership.py`, `tests\test_cli_e2e.py` (keep `tests\test_cli_version.py` passing)

`src\auditor\core\ownership.py` (pure, unit-testable — the CLI only feeds it):
```python
from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from auditor.core.models import Finding


def fs_case_insensitive(sample: Path | None) -> bool:
    """Probe the ACTUAL filesystem instead of assuming per-OS: swap the sample
    file's case and check it resolves to the same file. Case-normalization is
    only applied when the filesystem itself is insensitive — on sensitive
    filesystems Foo.ts and foo.ts are DIFFERENT files and must stay distinct."""
    if sample is not None:
        try:
            swapped = sample.with_name(sample.name.swapcase())
            if swapped.name != sample.name and swapped.exists():
                return os.path.samefile(sample, swapped)
            if swapped.name != sample.name:
                return False
        except OSError:
            pass
    return os.name == "nt"


def norm(path: str, insensitive: bool) -> str:
    p = path.replace("\\", "/")
    return p.casefold() if insensitive else p


def assign_findings(findings: list[Finding], owner: dict[str, int],
                    proj_meta: list[tuple[tuple[str, ...], int]],
                    prefixes: dict[int, str], globs: dict[int, tuple[str, ...]],
                    insensitive: bool) -> tuple[dict[int, list[Finding]], list[Finding], list[str]]:
    """exact full-file ownership first; deepest-root component fallback ONLY when
    the file's suffix belongs to that project's adapter (a Dockerfile/YAML at
    repo root goes to the repository bucket, never to 'the first language');
    '..' components are rejected (path-escape guard)."""
    assigned: dict[int, list[Finding]] = {}
    repo_bucket: list[Finding] = []
    dropped: list[str] = []
    meta = sorted(proj_meta, key=lambda t: -len(t[0]))
    for f in findings:
        rel = f.file.replace("\\", "/")
        if ".." in rel.split("/"):
            dropped.append(f.file)
            continue
        key = norm(rel, insensitive)
        idx = owner.get(key)
        if idx is None:
            parts = tuple(norm(rel, insensitive).split("/"))
            suffix = Path(rel).suffix.lower()
            idx = next((i for root_parts, i in meta
                        if parts[:len(root_parts)] == root_parts
                        and suffix in globs.get(i, ())), None)
        if idx is None:
            repo_bucket.append(f)
            continue
        prefix = prefixes.get(idx, "")
        if prefix and norm(rel, insensitive).startswith(norm(prefix, insensitive)):
            rel = rel[len(prefix):]
        assigned.setdefault(idx, []).append(replace(f, file=rel))
    return assigned, repo_bucket, dropped
```

`tests\test_ownership.py` (the four third-round cases):
```python
from pathlib import Path

from auditor.core.models import Finding, Severity
from auditor.core.ownership import assign_findings, fs_case_insensitive, norm


def _f(path):
    return Finding("S:x", Severity.YELLOW, "t", path, 1, engine="semgrep")


def test_case_sensitivity_respects_filesystem_mode():
    owner = {norm("web/Foo.ts", False): 0}
    got, bucket, _ = assign_findings([_f("web/foo.ts")], owner,
                                     [(("web",), 0)], {0: "web/"},
                                     {0: (".ts",)}, insensitive=False)
    # sensitive fs: foo.ts is NOT Foo.ts — exact map misses, fallback still owns
    # it by suffix+root, but the two names never collapse into one key
    assert norm("web/Foo.ts", False) != norm("web/foo.ts", False)
    assert 0 in got
    got_i, _, _ = assign_findings([_f("web/FOO.ts")],
                                  {norm("web/Foo.ts", True): 0},
                                  [(("web",), 0)], {0: "web/"},
                                  {0: (".ts",)}, insensitive=True)
    assert 0 in got_i  # insensitive fs: exact map hits across case


def test_prefix_collision_api_vs_api_old():
    got, bucket, _ = assign_findings([_f("api-old/src/index.ts")], {},
                                     [(("api",), 0)], {0: "api/"},
                                     {0: (".ts",)}, insensitive=True)
    assert got == {} and len(bucket) == 1  # 'api' must NOT swallow 'api-old'


def test_unowned_non_source_goes_to_repo_bucket_even_with_root_project():
    got, bucket, _ = assign_findings([_f("Dockerfile")], {},
                                     [((), 0)], {0: ""},
                                     {0: (".py",)}, insensitive=True)
    assert got == {} and [b.file for b in bucket] == ["Dockerfile"]


def test_two_projects_same_root_disambiguated_by_globs_and_owner_map():
    owner = {norm("a.py", True): 0, norm("b.ts", True): 1}
    got, bucket, _ = assign_findings([_f("a.py"), _f("b.ts"), _f("c.ts")], owner,
                                     [((), 0), ((), 1)], {0: "", 1: ""},
                                     {0: (".py",), 1: (".ts",)}, insensitive=True)
    assert set(got) == {0, 1} and [x.file for x in got[1]] == ["b.ts", "c.ts"]


def test_path_escape_dropped():
    got, bucket, dropped = assign_findings([_f("../outside.py")], {},
                                           [((), 0)], {0: ""},
                                           {0: (".py",)}, insensitive=True)
    assert got == {} and bucket == [] and dropped == ["../outside.py"]


def test_fs_probe_runs(tmp_path):
    p = tmp_path / "Sample.txt"
    p.write_text("x", encoding="utf-8")
    assert isinstance(fs_case_insensitive(p), bool)  # True on Windows/mac default
```

**Interfaces:**
- Produces: `adapters.default_adapters() -> list[LanguageAdapter]` (python, typescript, java, dotnet — in that order); CLI `auditor scan TARGET [--output DIR] [--offline] [--no-semgrep] [--semgrep-bin PATH] [--semgrep-config CFG ...] [--verbose]`. Exit codes: `0` = scan OK no reds, `1` = scan OK with ≥1 red finding, `2` = fatal (`AuditorError`). Prints a short console summary and writes `report.md` + `report.json` into `--output` (default `auditor-report`).
- Wiring per project: `declared = adapter.parse_dependencies(root)` → `files = project_files(...)` → `adapter.prepare(root, files)` → `frameworks` → Engine 1 (`audit_hallucinations`, registry from `{pypi,npm,maven,nuget}→client` map unless `--offline`) → Engine 2 (`run_pattern_engine`) → optional semgrep once per scan root (not per project) → merge via `patterns.dedupe`. Limitations list auto-assembled: offline mode; per-ecosystem registry errors seen; `java` present ⇒ "Maven Central exposes no download counts; Java namespace→artifact mapping is curated-prefix based (unmapped imports are reported as H007, not RED)"; `dotnet` present ⇒ ".NET System.*/Microsoft.* usings are treated as BCL"; semgrep availability note.

- [ ] **Step 1: Build the monorepo fixture** — `tests\fixtures\monorepo\` containing: top-level `requirements.txt` + `app.py` (copy of `python_repo` files), and `web\` (copy of all `ts_repo` files including `.env.local`). Do it with real copies (no symlinks — Windows).

- [ ] **Step 2: Write the failing test**

`tests\test_cli_e2e.py`:
```python
import json

from auditor.cli import main


def test_cli_scan_monorepo_offline(fixtures_dir, tmp_path, capsys):
    out = tmp_path / "rep"
    code = main(["scan", str(fixtures_dir / "monorepo"),
                 "--output", str(out), "--offline", "--no-semgrep"])
    assert code == 1  # pattern engines still find RED (secret/SQL sink/react) offline
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    langs = {p["language"] for p in data["projects"]}
    assert langs == {"python", "typescript"}
    all_rules = {f["rule_id"] for p in data["projects"] for f in p["findings"]}
    assert "H003" in all_rules          # offline blue markers
    assert "P002" in all_rules          # secret in python app.py
    assert "R001" in all_rules          # hooks in condition in Widget.tsx
    assert "N001" in all_rules          # .env.local public secret
    assert (out / "report.md").read_text(encoding="utf-8").startswith("# AI Code Auditor Report")
    # coverage-v2: offline => registry_cov 0 => 0.5 factor; no semgrep binary => 0.95
    assert data["summary"]["analysis_confidence"] == 48
    assert data["summary"]["verdict"] == "block"          # reds exist
    assert data["summary"]["lowest_language"] is not None
    assert "diagnostics" in data and "semgrep_status" in data["diagnostics"]
    printed = capsys.readouterr().out
    assert "report.md" in printed and "confidence" in printed and "BLOCK" in printed


def test_cli_surfaces_manifest_corruption_end_to_end(tmp_path):
    # the no-silent-failure contract, driven through the FULL path to report.json
    (tmp_path / "pyproject.toml").write_text("[project\nbroken toml", encoding="utf-8")
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    out = tmp_path / "rep"
    code = main(["scan", str(tmp_path), "--output", str(out), "--offline", "--no-semgrep"])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert any("pyproject.toml" in e for e in data["diagnostics"]["manifest_errors"])
    assert data["summary"]["verdict"] in ("review", "block")  # never a clean pass
    assert code == 0 or code == 1
    strict = main(["scan", str(tmp_path), "--output", str(out), "--offline",
                   "--no-semgrep", "--strict"])
    assert strict == 1  # incomplete analysis must not exit 0 in strict mode


def test_cli_bad_target_exits_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "خطأ" in capsys.readouterr().err  # bilingual error goes to stderr


def test_cli_empty_dir_exits_0(tmp_path):
    code = main(["scan", str(tmp_path), "--output", str(tmp_path / "r"), "--offline"])
    assert code == 0
    data = json.loads((tmp_path / "r" / "report.json").read_text(encoding="utf-8"))
    assert data["projects"] == [] and data["summary"]["overall_score"] is None
```

- [ ] **Step 3: Implement**

`src\auditor\adapters\__init__.py`:
```python
from __future__ import annotations

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.adapters.java.adapter import JavaAdapter
from auditor.adapters.python.adapter import PythonAdapter
from auditor.adapters.typescript.adapter import TypeScriptAdapter


def default_adapters():
    return [PythonAdapter(), TypeScriptAdapter(), JavaAdapter(), DotnetAdapter()]
```

`src\auditor\cli.py` (full replacement):
```python
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
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        build_parser().print_help()
        return 0
    try:
        return _scan(args)
    except AuditorError as e:
        print(f"error | خطأ: {e}", file=sys.stderr)
        return 2


def _scan(args) -> int:
    from auditor.adapters import default_adapters
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.patterns import dedupe, run_pattern_engine
    from auditor.core.semgrep_runner import find_binary, run_semgrep
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

        from auditor.core.models import Diagnostics
        from auditor.core.treesitter import register_adapters
        register_adapters(adapters)
        global_diag = Diagnostics()

        if args.semgrep_config:
            print("note: extra semgrep configs run under the rule authors' license "
                  "(Semgrep Rules License v1.0 restricts registry packs).")

        # Ownership lives in core/ownership.py (pure + unit-tested): exact
        # full-file map, suffix-gated deepest-root fallback, repo bucket,
        # '..' guard, and FILESYSTEM-probed case normalization.
        from auditor.core.ownership import assign_findings, fs_case_insensitive, norm
        sample = None
        if projects:
            sample = next((f for f in projects[0][1].rglob("*") if f.is_file()), None)
        insensitive = fs_case_insensitive(sample)

        results = []
        proj_meta = []            # (rel_root_parts, index)
        prefixes: dict[int, str] = {}
        globs: dict[int, tuple[str, ...]] = {}
        owner: dict[str, int] = {}
        languages_seen: set[str] = set()
        expected_sg_paths: set[str] = set()   # for semgrep completeness reconciliation
        for adapter, proot in projects:
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
        # files we expect it to cover (completeness signal — fifth-round)
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
        if registries and getattr(registries.get("nuget"), "inner", None) is not None \
                and getattr(registries["nuget"].inner, "degraded", False):
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
        data = build_report(args.target, results, engines, limitations,
                            diagnostics=dc_asdict(global_diag), confidence=confidence)
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
```

- [ ] **Step 4: Run `tests\test_cli_e2e.py` AND `tests\test_cli_version.py` — PASS. Then full suite green.**
- [ ] **Step 5: Commit** — `feat(cli): full scan pipeline, monorepo fixture, exit codes, bilingual errors`

**PHASE CHECKPOINT CP-7 — STOP.** Present to the user: run `auditor scan tests\fixtures\monorepo --offline` live, show console output and both generated reports. Confirm report format/wording before the real-world trial.
**Gate:** health-vs-confidence separation demonstrated (the monorepo E2E asserts confidence exactly 48 = coverage-v2 with offline registry_cov 0 and no semgrep binary — recompute if the model changes, never leave two numbers); lowest-language line appears whenever it undercuts the average; verdict pass/review/block and diagnostics section render; exit codes 0/1/2 each demonstrated. **Blockers:** average hiding a red project in the summary. **Deferred decisions:** report wording/format tweaks.

---

## PHASE 8 — Real-world trial, README, examples

### Task 24: README (ar/en) + live trial on a real multi-language repo + examples

**Files:**
- Create: `README.md`, `examples\report.md`, `examples\report.json`
- Possibly modify: any component that crashes on real-world input (fix + regression test)

- [ ] **Step 1: README.md** — bilingual (Arabic first, English second), covering: what it does (Engine 1 + Engine 2), install (`pip install -e .`), usage (`auditor scan <url|path>`, all flags), rule catalog table (from this plan), scoring formula, limitations (Java/.NET mapping accuracy, Maven downloads, semgrep licensing stance + how to opt into registry packs), architecture diagram (core/adapters/registries/report tree), development (pytest). State clearly: no LLM, deterministic, offline-capable.

- [ ] **Step 2: Live trial** (network required):
```powershell
.venv\Scripts\auditor scan https://github.com/microsoft/vscode-extension-samples --output trial-1
```
plus a second target that includes Python+TS (e.g. `https://github.com/open-telemetry/opentelemetry-demo` — polyglot: it contains .NET/Java/TS/Python services). Success criteria: exit code 0/1 (not 2), no traceback, reports written, registry cache file created, second run visibly faster (cache hit). Fix any crash found (encoding, weird manifests, huge files) with a regression test per fix.

- [ ] **Step 3: Copy the better of the two trial outputs** into `examples\report.md` + `examples\report.json` (trim if enormous). Add one line to README pointing at them.

- [ ] **Step 4: Full suite + fresh-install check**
```powershell
.venv\Scripts\python -m pytest -q
python -m venv .venv-check ; .venv-check\Scripts\python -m pip install . ; .venv-check\Scripts\auditor --version
```

- [ ] **Step 5: Final commit** — `docs: bilingual README + real-world example reports`

**PHASE CHECKPOINT CP-8 (final) — STOP.** Present: example report from a real repo, final test count, and the full deliverables list against the original spec.
**Gate:** two real-repo scans exit 0/1 (never 2) with zero tracebacks; second run demonstrably faster (cache); README documents every limitation from the review (private-source channels, Maven downloads, heuristic precisions, next-graph exclusions: middleware/instrumentation/metadata routes and string-built import paths); fresh-venv install check passes. **Blockers:** crash on real-world input without a regression test. **Deferred decisions:** publishing/licensing of the tool itself.

---

## Post-plan notes for the executor

- Fixture `.env.local` files and YAML must be written by the Write tool (UTF-8 no BOM) — never via PowerShell `Out-File`.
- If a tree-sitter node-type name in a query does not match (grammar drift), print the CST with `print(sf.tree.root_node)` in a scratch script and adjust the single query string; never downgrade the tree-sitter dependency.
- Real-registry smoke checks (optional, manual): `python -c "from auditor.registries.pypi import PyPIClient; print(PyPIClient().lookup('requests'))"` and equivalents; never bake live-network calls into the pytest suite.
- The `responses` library intercepts `requests` globally — every registry unit test must register ALL URLs its client will hit, or assert on `PackageInfo.error`.



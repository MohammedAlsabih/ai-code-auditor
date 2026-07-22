# AI Code Auditor

[![CI](https://github.com/MohammedAlsabih/ai-code-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/MohammedAlsabih/ai-code-auditor/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MohammedAlsabih/ai-code-auditor?include_prereleases)](https://github.com/MohammedAlsabih/ai-code-auditor/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A deterministic static analyzer for repositories that contain AI-generated
or AI-modified code. It looks for two defect classes that are common in
generated code: dependencies that do not exist (hallucinated packages), and
risky code patterns. No LLM is used at runtime — the same input always
produces the same findings, and nothing is executed from the scanned
repository. The tool does not attempt to prove *who* wrote a piece of code;
it only checks for the mistakes that generated code tends to contain.

> **Status: alpha (`0.1.0a1`).** Interfaces, report schemas, and rule
> behavior may change between releases. The tool narrows human attention;
> it is not a replacement for code review, tests, or a security audit, and
> an empty report is not evidence that code is safe.

## What it checks

**Engine 1 — hallucinated dependencies.** Every import and every declared
dependency is compared against the public registries (PyPI, npm, Maven
Central, NuGet). A declared package that does not exist in its registry is
a likely hallucination and a squattable name. A very new package with
near-zero downloads is flagged as a supply-chain warning. Lookups send
package *names* only; `--offline` disables all network access and marks
registry-dependent rules as unverified instead of guessing.

**Engine 2 — risky patterns.** AST rules via tree-sitter, per language:

| Family | Language | Examples |
|---|---|---|
| P | all | hardcoded secrets (masked in output), string-built SQL, empty catch blocks, cyclomatic complexity, stdlib drift vs `requires-python` |
| R | React | Rules-of-Hooks violations, effect dependency problems, `key={index}`, non-literal `dangerouslySetInnerHTML` |
| N | Next.js | server/client boundary violations resolved over a real module-import graph, `NEXT_PUBLIC_` secrets (values never echoed) |
| J / D | Java / .NET | `==` on strings, missing try-with-resources, `async void`, blocking `.Result`/`.Wait()`, raw SQL interpolation |
| S | multi | an optional Semgrep/OpenGrep layer; only bundled MIT-licensed rules run by default |

Supported languages: Python, TypeScript/JavaScript (React, Next.js), Java,
C#. Python 3.11 or 3.12 is required to run the tool itself; Windows and
Linux are covered by CI.

## Finding levels and precision

Findings carry a SARIF-compatible `level`:

- `error` — high-confidence defect (e.g. a hallucinated npm import, a
  secret-shaped literal, SQL composed into an execution sink)
- `warning` — needs review (e.g. an unverified undeclared import, a private
  env var read in client code)
- `note` — informational (e.g. AI-style incompleteness comments)

Each finding also declares its `precision`: `exact` when the rule's premise
is mechanically certain, `heuristic` when it rests on a convention (for
example Python's import-name-equals-package convention, or Java/.NET prefix
maps).

## Gate policy and verdict

The verdict is derived from a per-finding `gate_action`, not from levels or
counts alone:

| level | precision | gate_action |
|---|---|---|
| error | exact | **block** |
| error | heuristic | review |
| warning | exact / heuristic | review |
| note | exact / heuristic | informational |

An exact error blocks the gate. A heuristic error is a strong signal, not a
proof — by default it demands review instead of blocking (a project can
promote it to `block` in its config, below). Notes never gate.
`summary.gate_counts` in `report.json` shows exactly what drove the verdict.
The `code_health` score is a severity-ordering indicator only, never a
safety claim.

## Analysis confidence vs. registry verification

These are two separate axes in the report summary:

- `analysis_confidence` — how *complete* the file/manifest/rule analysis
  was (skipped files, unparsed manifests, rule failures). It contains no
  registry factor.
- `registry_status` — whether dependency verification ran:
  `complete`, `partial` (some lookups failed → the verdict can not be
  `pass`), `unavailable` (intended `--offline`), or `not_applicable`, with
  a numeric `registry_confidence` only when lookups actually ran.

Because an intended `--offline` run is not an analysis defect, a clean and
complete offline scan can end in `PASS` with exit code 0 — including under
`--strict`. Registry-dependent rules still surface as unverified notes.

## Execution evidence

`report.json` records not just findings but whether each rule actually ran:
`analysis_manifest.execution` holds per-project, per-rule facts (eligible
inputs, attempts, failures, blocked or partially parsed inputs, structured
reasons) plus a derived status: `executed`, `partial`, `failed`, `blocked`,
`unavailable`, `skipped`, `not_applicable`, `not_recorded`, or
`inconsistent`. A rule that ran and found nothing is `executed` — there is
deliberately no "passed". The report explorer's **Rules** tab visualizes
this block per rule and per project.

## Install

```
python -m venv .venv
.venv/Scripts/pip install -e .           # core scanner
.venv/Scripts/pip install -e ".[web]"    # + local report explorer
auditor --version                        # ai-code-auditor 0.1.0a1
```

Or install the wheel attached to the
[latest release](https://github.com/MohammedAlsabih/ai-code-auditor/releases).
Not on PyPI yet.

## Scan

```
auditor scan https://github.com/org/repo        # clone + scan a public repo
auditor scan path/to/project --output my-report
auditor scan . --offline                        # no network at all
auditor scan . --strict                         # REVIEW also fails (for CI)
auditor scan . --no-semgrep                     # builtin rules only
auditor scan . --semgrep-bin opengrep --semgrep-config my.yml
auditor scan . --sarif                          # also write report.sarif
auditor scan . --baseline old/report.json       # mark findings new/unchanged
auditor scan . --baseline old/report.json --new-only   # gate on new findings only
auditor scan . --config path/to/.auditor.toml   # explicit project config
```

Exit codes: `0` pass · `1` verdict BLOCK (or REVIEW with `--strict`) · `2`
fatal error. Output lands in `--output` (default `auditor-report/`):
`report.md` for humans, `report.json` for machines (full diagnostics ledger,
`analysis_confidence`, `registry_status`, gate counts), and `report.sarif`
(SARIF 2.1.0) when `--sarif` is given — importable into GitHub code
scanning and other SARIF consumers. The SARIF file carries rule metadata,
repo-relative locations, line-independent fingerprints, and baseline states;
it never contains source snippets, review notes, or machine paths.

## Baselines

`--baseline` takes a `report.json` from an earlier scan. Every current
finding is matched against it by a content fingerprint (project, file, rule,
engine, and the normalized matched text — deliberately not the line number,
so moving code around does not create "new" findings) and labeled
`baseline_state: new | unchanged`. With `--new-only`, only *new* findings
drive the verdict — the report still contains everything, and the summary
counts how many baseline findings were resolved. Typical CI shape: fail the
gate on regressions while an inherited backlog is worked down separately.

## Project configuration

An `.auditor.toml` at the repository root (or `--config PATH`) tunes the
scan. Schema v1 covers scoping; schema v2 adds gate policy:

```toml
schema_version = 2

exclude_paths = ["fixtures", "legacy/generated"]
dependency_exclude_paths = ["docs"]     # code rules still run there
npm_roots = ["tools/scripts"]           # manifestless dirs that are npm-owned

[policy]
heuristic_errors = "block"   # promote heuristic errors from review to block

[rule_levels]                # per-rule level overrides, catalog-validated
R007 = "warning"
P005 = "error"
```

A rule-level override changes the finding's effective level transparently:
the report keeps the original as `default_level` with
`level_source = "project_policy"`. Malformed configs fail loudly, and the
applied policy is recorded in `analysis_manifest.policy`.

## Report explorer

```
auditor serve auditor-report/report.json --repo path/to/project --port 8765
```

Requires the `[web]` extra. A loopback-only local web UI for one report:
search, level/rule/path filters, a read-only source viewer, a rule-coverage
tab (catalog × execution evidence), a coverage panel, and a review workflow
(confirmed / false positive / accepted risk / note) stored in a
`*.reviews.json` sidecar next to the report. Reports scanned with
`--baseline` get New/Existing badges and an All/New/Existing filter. The
report file itself is never modified.

## Privacy

- Scans and reports are local; the tool uploads nothing.
- Reports may contain source snippets — treat `report.json`/`report.md`
  with the same confidentiality as the code itself.
- Online mode queries public registries with package names only. Private
  registries are never contacted; packages behind them are reported as
  unverifiable rather than looked up.
- Report text passes a redaction layer (auth headers, tokens,
  password-shaped values), and absolute machine paths are not written into
  reports. Redaction is heuristic — review before sharing.

## Limitations

- Java/.NET import-to-artifact mapping uses curated prefix maps; unmapped
  imports are reported as unresolved warnings, never guessed errors.
- Maven Central exposes no download counts, so the new-package heuristics
  are weaker there.
- The Next.js module graph excludes middleware, instrumentation, and
  metadata routes; dynamic import paths built from strings are reported as
  unresolved edges, not guessed.
- JSX inside plain `.js` files is not analyzed (`.jsx`/`.tsx` are).
- Semgrep Registry packs are opt-in via `--semgrep-config` and run under
  your own license responsibility; only bundled MIT rules run by default.

See [`examples/report.md`](examples/report.md) and
[`examples/report.json`](examples/report.json) for real output from the
test fixture, and [SECURITY.md](SECURITY.md) for the security policy.

## Development

```
pip install -e ".[web,dev]"     # pinned pytest/mypy/ruff/type stubs
python -m pytest -q             # offline by design; registries are mocked
python -m ruff check src
python -m mypy src              # config lives in [tool.mypy]
cd web && npm ci && npm run typecheck && node --test tests/*.mjs && npm run build
```

The frontend build output (`src/auditor/web/static/`) is committed so the
wheel and a plain checkout work without Node. CI runs the full matrix on
Ubuntu and Windows, Python 3.11 and 3.12.

## License

MIT — see [LICENSE](LICENSE).

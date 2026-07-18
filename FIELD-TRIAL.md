# Field trial — clean-install verification (2026-07-18)

Purpose: verify the tool installs and runs from a **built wheel in a clean
environment** (not the dev tree), on the real Task-24 repository, online and
offline. No findings fixed and no rules added this round (per instruction).

## Reproducible commands

```powershell
# 1. build the wheel from the dev tree
.venv\Scripts\python -m build --wheel            # -> dist\ai_code_auditor-0.1.0-py3-none-any.whl

# 2. clean environment, install from the WHEEL only
py -3.12 -m venv .venv-field
.venv-field\Scripts\python -m pip install dist\ai_code_auditor-0.1.0-py3-none-any.whl
.venv-field\Scripts\auditor --version           # -> ai-code-auditor 0.1.0

# 3. run on the real repo, online then offline
.venv-field\Scripts\auditor scan https://github.com/open-telemetry/opentelemetry-demo --output field-online
.venv-field\Scripts\auditor scan https://github.com/open-telemetry/opentelemetry-demo --output field-offline --offline
```

Install checks passed: CLI runs from the clean venv; the bundled semgrep YAML
ships **inside** the wheel (`…/site-packages/auditor/semgrep_rules/auditor-extra.yml`
resolves). No install/run blocker was found, so no fix was made.

Report paths: `field-online/report.{md,json}`, `field-offline/report.{md,json}`.

## Run metrics

| run | exit | time | verdict | code_health | confidence | projects | findings | red | yellow | blue | exact | heuristic | manifest_incomplete | rule_failures | semgrep |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| online  | 1 | 77s | BLOCK | 66 | 86 | 18 | 168 | 2 | 100 | 66 | 98 | 70 | 1 | 0 | not available |
| offline | 1 | 75s | BLOCK | 67 | 43 | 18 | 788 | 2 | 94 | 692 | 701 | 87 | 1 | 0 | not available |

Notes: exit 1 = BLOCK (two red findings). Offline confidence 43 (< online 86) is
correct — registry coverage is 0 offline (×0.5 factor). Offline findings balloon
to 788 because every external import becomes H003 (blue, "check skipped
offline") instead of being resolved. No rule crashes in either run
(rule_failures 0). semgrep absent (no binary on this machine) — builtin rules only.

## Top-10 findings (online, severity-ranked) — manual review

| # | rule | sev | prec | location | verdict | note |
|---|---|---|---|---|---|---|
| 1 | R001 | red | heuristic | ts hooks/useThemeColor.ts:18 | **confirmed** | `useColorScheme()` inside a ternary — a real rules-of-hooks violation |
| 2 | R007 | red | heuristic | ts pages/_document.tsx:59 | **confirmed** | `dangerouslySetInnerHTML={{__html: this.props.envString}}` — dynamic __html, genuine XSS-vector pattern |
| 3 | H002 | yellow | heuristic | py src/shared/tools.py:9 | **uncertain** | `httpx` undeclared in that project's manifest; likely a real omission (or a shared/parent manifest) |
| 4 | H002 | yellow | exact | ts src/flagd-ui/assets/js/app.js:5 | **false positive** | `phoenix_html` is an **Elixir/Hex** dep loaded by the Phoenix asset pipeline, not npm |
| 5 | H002 | yellow | exact | ts .../app.js:7 | **false positive** | `phoenix` (Elixir/Hex), same cause |
| 6 | H002 | yellow | exact | ts .../app.js:8 | **false positive** | `phoenix_live_view` (Elixir/Hex), same cause |
| 7 | H002 | yellow | exact | ts .../vendor/heroicons.js:1 | **false positive** | `tailwindcss/plugin` inside a **vendored** asset file, not the project's own dep graph |
| 8 | H002 | yellow | exact | ts src/load-generator/script.js:4 | **false positive** | `k6/http` is a **k6 runtime** import (load-test script), not npm |
| 9 | H002 | yellow | heuristic | dotnet Consumer.cs:5 | **uncertain** | `Microsoft.Extensions.Hosting` undeclared in this csproj; often transitive/framework-provided |
| 10 | H002 | yellow | heuristic | dotnet Consumer.cs:7 | **uncertain** | `Npgsql` undeclared here; may be declared in a sibling/central props |

Tally: **2 confirmed, 5 false positive, 3 uncertain.**

### Dominant false-positive class (for a later decision — NOT fixed this round)
The root TypeScript project (`.`, 6 files) sweeps in `.js` files that are **not
npm-managed**: Phoenix asset-pipeline scripts (`phoenix*` are Elixir/Hex deps),
a vendored `heroicons.js`, and a k6 load-test `script.js` (`k6/*` is a k6
runtime). Their bare imports are looked up against **npm**, and because
same-named npm packages exist, they surface as `H002 exact` — confidently
attributing a non-npm import to npm. All five top-10 FPs are this one class.
Candidate mitigations (future round, user's call): skip `.js` files with no
governing `package.json` in scope; ignore known non-npm import roots
(`k6/…`, Phoenix `deps/`); or down-rank a bare `.js` import to heuristic.

## Result
Clean-install verification **passed** (build → install → run, online + offline,
no blocker). The engine is usable on a real polyglot repo; the main accuracy
gap observed is the non-npm-`.js` false-positive class above. Next: pick the
user's first real target and run.

## Correction (2026-07-18) — NuGet service-index init race fixed
*(The metrics above are the historical field-trial record and are left
unchanged. This section documents a run-blocker fixed afterward, before the
user's first real target.)*

**Symptom in the run above.** The online run reported 4 `H004` findings tagged
`lookup crashed: KeyError` (`registry_failures=4`) for `Grpc.Tools`,
`Microsoft.VisualStudio.Azure.Containers.Tools.Targets`,
`Npgsql.EntityFrameworkCore.PostgreSQL`, and `OpenTelemetry.AutoInstrumentation`
— the .NET packages, which the engine looks up concurrently.

**Root cause.** `NuGetClient._resource` published `self._resources = {}` and
*then* filled it while fetching the service index. A second thread entering the
window saw a non-`None` **empty** dict, skipped initialisation, and indexed it
— `KeyError('flat')`. Deterministically reproduced with two threads + Events
(one parked mid-fetch, the other racing in).

**Fix.** `src/auditor/registries/nuget.py`: the endpoint map is now built into a
**local** dict and published to `self._resources` **only once complete**, under
a double-checked `threading.Lock`. `_resources` therefore transitions
`None → complete`, never `None → partial`. Endpoint-resolution behaviour is
unchanged; no rules were added and no findings were altered.

**Verification.** Deterministic regression
`tests/test_registry_nuget.py::test_service_index_init_is_atomic_under_race`
(Events, no sleeps) — asserts the map is still `None` while a thread is parked
mid-build, and that both racing callers return the correct `flat` endpoint with
zero `KeyError`; plus
`test_parallel_lookup_four_packages_zero_keyerror` (the four packages above,
looked up in parallel, all resolve). A 6 400-call barrier-synchronised stress
race produced **zero** `KeyError`. Full suite **353 passed / 1 skipped on Python
3.11 and 3.12**; `ruff check src`, `mypy src`, and `git diff --check` clean.

A fresh online run would no longer crash on these four lookups
(`registry_failures` drops by 4); the historical numbers above are kept as the
as-observed record and were **not** re-generated.

# CP-8 product-contract batch — 12 counter-cases (2026-07-18)

All 12 reproduced independently BEFORE any fix (12 parallel skeptic agents +
WSL for the symlink dimension). All 12 CONFIRMED. All 12 fixed. No new rules
added; no general review opened.

## Before → after (per point)

| # | Claim (confirmed) | Fix |
|---|---|---|
| **1** confidence source | `analysis_confidence` ignored `manifest_incomplete` + include gaps; manifest coverage counted error MESSAGES; a dead `Diagnostics.analysis_confidence` string method existed | coverage counts affected FILES by path (`_manifest_error_files`); `manifest_incomplete` folds in; `verdict` forbids PASS on `manifest_incomplete`/`include_gaps`; dead method removed — one numeric source |
| **2** repo vs project root | shared `-r ../shared/base.txt` refused as "outside scan root"; ancestor `.npmrc` missed | `LanguageAdapter.set_repo_root`/`_confinement_root`/`_config_search_dirs`; guards use REPO root; `private_registry_reason` walks ancestors. WSL: in-repo shared file **read**, repo-escaping symlink **refused, no leak** |
| **3** Java/.NET mapping + TFM | Java group-only match hid a WRONG artifact; .NET generic guess produced RED H008; `netcoreapp2.1`/missing-TFM misjudged | Java requires FULL `group:artifact` when a curated map exists; .NET `import_mapping_trust="guess"` ⇒ absent ⇒ H007 never red; `_is_old_tfm` handles netcoreapp1/2, `TargetFrameworkVersion` (v4.7.2), packages.config ⇒ old |
| **4** member hooks + directive | `React.useState`/`hooks.useX` invisible in hooks + N006; `has_use_client` read only first 3 nodes | `_CALL_QUERY` matches member-expression callees, walk to enclosing call; real directive prologue (from first stmt, stop at first non-string, skip comments) |
| **5** R007 forms | only `{{__html:x}}` handled; `={expr}` and spread missed; precision "exact" | flag unless PROVABLY `{__html: <literal>}`; identifier/spread/interpolation all caught; precision **heuristic** (no taint analysis) |
| **6** semgrep paths | out-of-root result kept as basename; relative paths not normalized | relative paths anchored to `project_root`; out-of-root results **dropped** + `"outside scan root dropped"` in status — never basename'd |
| **7** redaction | only finding snippet/detail redacted; target + diagnostics leaked secrets | `_redact_tree` recursively redacts EVERY outgoing string (target, findings, diagnostics, limitations, engines) |
| **8** dedupe | keyed on `(rule_id,file,line)` — dropped different findings on one line | keys on FULL finding identity; two secrets on one line both kept |
| **9** multi-module provider | a declared dep matched by one import was removed from the provider pool globally ⇒ a sibling flipped H007→**RED H008** | provider pool = all declared (registry-dead removed later); a matched dist stays a candidate provider for siblings. `megatool`→`megahelper` = H007, not red |
| **10** cache/setup | garbage cached date passed type check then crashed `age_days`; any `setup()` parsed; `**kwargs` silent | `_valid_hit` parses `created`/`latest` + rejects negative downloads; `setup()` requires a setuptools/distutils import; `setup(**cfg)` ⇒ manifest_incomplete |
| **11** examples | hand-trimmed ⇒ counts ≠ serialized findings | regenerated from ONE deterministic run (monorepo offline); `test_p11` asserts counts == serialized findings |
| **12** mypy | `mypy`/`ruff`/`types-defusedxml` unpinned; bare `mypy src` errored | pinned in `[dev]`; `[tool.mypy] ignore_missing_imports`; **bare `mypy src` clean on 3.11 AND 3.12** |

## Contract change worth calling out (points 9 + 3)
A definitive RED **H008** ("hallucinated / slopsquatting") now fires only when
NO existing declared distribution could be the module's source, and never for a
.NET generic namespace guess. Consequences, intentional and documented in-test:
- python_repo `superjsonify`: H008 → **H007** (`requests` is declared+exists, so
  it could provide it; without per-distribution module metadata a red is not
  justified).
- dotnet_repo `HyperSql.Client`: H008 → **H007** (a namespace guess is never red).
- npm stays exact: `axios-retry-ai` still **H008** red (import name IS the
  package name).
`test_p9_no_declared_provider_still_red_h008` proves H008 still fires when
nothing could explain the import.

## Gates
- pytest **309 passed / 1 skipped on Python 3.11 AND 3.12** · ruff `src` clean ·
  **bare `mypy src` clean on both** (reproducible, no flags)
- E2E: incomplete manifest (dynamic setup.py) ⇒ verdict ≠ pass, end to end
  (`test_cli_incomplete_manifest_never_passes`); report never leaks target creds
- corpus RE-RUN (react-hooks 7.1.1, same version, 18 shared files identical):
  20 files, **only the 2 documented divergences**; `react_namespace_hook.tsx`
  AGREE (R001), `dangerous_html_direct.tsx` R007 auditor-extra
- Java wrong-artifact + .NET unmapped-namespace + semgrep escape/nested-relative
  + no-secret-in-report all have dedicated regressions (`tests/test_cp8_contracts.py`)
- monorepo confidence still exactly **48** (unchanged)
- +30 regressions this batch

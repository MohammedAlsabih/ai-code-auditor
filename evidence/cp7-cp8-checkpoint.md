# CP-7 + CP-8 (final) — 2026-07-18, autonomous per user authorization

## CP-7 (T23, commit e603d48)
- Live `auditor scan tests/fixtures/monorepo --offline`: verdict=BLOCK,
  health 14, lowest typescript=0, 🔴=7, confidence 48/100, exit 1.
- Confidence exactly 48 (coverage-v2: offline registry_cov=0 ⇒ ×0.5; no
  semgrep ⇒ ×0.95) — asserted in the E2E, single source of truth.
- Exit codes demonstrated: 0 (empty dir), 1 (block / strict-review), 2 (bad
  target, bilingual stderr).
- LIVE-RUN DEFECT FOUND & FIXED: legacy Windows console codepage (cp1256)
  crashed on the summary emoji (UnicodeEncodeError) — invisible under pytest
  capture. Streams now reconfigure(errors="replace"); cp1256 regression test.

## CP-8 (T24)
- **Trial 1** microsoft/vscode-extension-samples: exit 0, no traceback, 40s;
  REVIEW, health 94 (lowest typescript 85), confidence 93.
  Second run: **17s (cache hit, vs 40s)** — cache file present under
  %LOCALAPPDATA%\ai-code-auditor.
- **Trial 2** open-telemetry/opentelemetry-demo (polyglot): exit 1 (BLOCK —
  legitimate reds), no traceback, 111s; 20+ projects across ALL FOUR
  languages; monorepo ownership + per-language scores working.
  Reds: R007 non-literal __html (pages/_document.tsx), R001 ternary hook
  (hooks/useThemeColor.ts) — both genuine rule hits.
  Histogram: P007×62, H007×49 (Java curated-map limit, as documented),
  H002×27, H010×8, P006×6, H006×6, P001×3, H004×1.
- examples/report.{md,json} = trial-2 output (json trimmed to 8 findings per
  project with an explicit trim marker).
- Fresh venv `pip install .` ⇒ `auditor --version` OK.
- Final suites: 277 passed / 1 skipped on Python 3.11 AND 3.12; ruff clean;
  mypy clean.

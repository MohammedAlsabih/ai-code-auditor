# CP-8b second contract round — 7 counter-cases (2026-07-18)

Reproduced independently on commit 7362524 (7 parallel skeptic agents). All 7
CONFIRMED. Fixed; the provider point is a deliberate, measured policy change.

## Before → after

| # | Confirmed defect | Fix |
|---|---|---|
| **1** scrubber | `Authorization: Bearer XXX` → only "Bearer" masked; `{"token":"XXX"}` and npmrc `_authToken=XXX` untouched (all leaked into report.json) | added an auth-HEADER rule (masks rest-of-line), a QUOTED-value rule (JSON/YAML/TOML), and `_auth[token]` to the key set; idempotent; benign text intact (`author=alice`, `token_count`) |
| **2** setup() binding | any call named `setup` counted once setuptools was imported anywhere → `def setup`/`Helper().setup` fabricated deps; `from setuptools import setup as configure` missed `requests` | real NAME BINDING: aliased `from … import setup as X`, module aliases `import setuptools as st`→`st.setup`; a local `def setup`/rebind removes the binding AND marks incomplete; `Helper().setup` (attr on a Call) never counts |
| **3** provider policy | any single declared dep (requests) downgraded EVERY hallucinated import to H007 — recall **0.143** | measured A/B/C (table below); adopted: H008 red FIRES (recall 1.0) but as a **heuristic** red with an explicit UNVERIFIED-provider note when unlinked declared deps exist — never a silent suppression. Curated multi-module providers (Bio→biopython) are matched, never reach here |
| **4** .NET TFM | missing TFM = "modern" silently; ancestor `Directory.Build.props` ignored | `_classify_tfm` → **old / modern / unknown**; unknown never means modern (System.* treated as package-delivered + limitation + manifest_incomplete + lowered confidence); reads `Directory.Build.props` in repo ancestors; `$(Prop)` dynamic → unknown |
| **5** monorepo identity | `_mark_incomplete` stored `"setup.py"` (project-relative) → two projects' setup.py merged to ONE; error+incomplete summed not unioned | all three ledgers key on `_canon` (resolved full posix path); scoring counts `union(errored, incomplete)`; FORMULA text updated |
| **6** semgrep base | relative `paths.scanned` resolved against CWD → never matched absolute `expected_paths` → false "partial" | `_norm` anchors relative paths to `project_root` (one base for scanned/results/expected); out-of-root guard kept |
| **7** member-hook FP | ANY `obj.useX()` (api/client/hooks) counted as a hook → false R001/N006 | ONE shared predicate `is_hook_callee`: bare `useX` or `<ns>.useX` where ns ∈ {React, aliases imported from 'react'/'react-dom'}; used by react_rules AND N006 |

## Point 3 — measured provider policy (the decision, not just a note)
Labeled benchmark, classifier = "red H008 emitted ⇒ import is hallucinated":

| policy | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|
| A current (all declared = providers) | 1 | 0 | 6 | 1.000 | **0.143** |
| B curated-linked providers only | 7 | 4 | 0 | 0.636 | 1.000 |
| C red + unverified note (adopted) | 7 | 0* | 0 | — | 1.000 |

Policy A is rejected: it fails the hard criterion "requests must not auto-suppress
every hallucinated import" (recall 0.143). B/C catch all real hallucinations; the
"4 FP" the benchmark ascribed to B/C are the CURATED providers (Bio, rest_framework,
pkg_resources) — but those are resolved by `match_declared` and never become
external, so in the real engine they produce **no finding at all** (verified by
`test_p9_curated_multimodule_provider_is_matched_not_flagged`). The only residual
risk is an UNKNOWN, uncurated multi-module distribution (megatool→megahelper): C
flags it red WITH the explicit "UNVERIFIED — a declared distribution could provide
this; heuristic, not proof" note and precision=heuristic. *So C's reds are honest
heuristics, never definitive claims — satisfying "لا يتحول heuristic إلى ادعاء قطعي".

### Deliberate H007/H008 contract change (from the CP-8 round)
- Reverts CP-8.9's "matched provider shields sibling → H007". Now: unlinked
  declared provider ⇒ **H008 red + UNVERIFIED note** (heuristic). superjsonify and
  the megatool sibling are red-with-note; a .NET namespace guess stays H007;
  npm stays exact (axios-retry-ai red, no note). Curated providers never flagged.
- Rationale: point 3's "requests must not suppress" is incompatible with A; C is
  the honest reconciliation (recall 1.0, heuristic reds, no false-certainty).

## Gates
- pytest **326 passed / 1 skipped on Python 3.11 AND 3.12**; ruff `src` clean;
  bare `mypy src` clean on both; `git diff --check` exit 0
- scrubber: 10 formats masked + idempotent + benign-safe; end-to-end no leak in
  report.json (`test_p1_scrubber_formats_never_reach_report_json`)
- setup binding: 6 shapes (`test_p2_setup_binding_all_shapes`)
- .NET: old/modern/unknown + ancestor Directory.Build.props + dynamic $(...)
- monorepo: two same-named incomplete manifests stay 2; error+incomplete union=1
- semgrep: relative scanned reconciles with absolute expected ⇒ success
- corpus RE-RUN (react-hooks 7.1.1): 21 files, still only the 2 documented
  divergences; NEW `service_object_hook.tsx` (api.useState) clean in BOTH
- monorepo confidence still 48; live CLI clean; no creds in report
- +22 regressions (`tests/test_cp8b_contracts.py`, corpus, updated E2Es)

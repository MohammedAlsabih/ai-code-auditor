# CP-5 — Phase 5 complete (2026-07-18, autonomous per user authorization)

Commits: b5d2abb (T15 Maven), 0fc0b54 (T16 Java), ab9ed41 (T17 NuGet),
T18 in the following commit.

## State
All FOUR adapters (python, typescript, java, dotnet) + all FOUR registry
clients (PyPI, npm, Maven repo1, NuGet) complete. Each language has a
planted-bug fixture and a passing E2E through Engine 1.
221 passed / 1 skipped on Python 3.11 AND 3.12 · ruff clean · mypy clean.

## Gate results
- javax split green: JDK (swing/crypto/annotation.processing/transaction.xa/
  xml.parsers) vs external (servlet/persistence/annotation/xml.bind/
  transaction/inject) — incl. the 4 trap prefixes
- JUnit4-declared regression green (org.junit.Test matches junit:junit)
- NuGet service-index resolution mocked + tested; degraded flag tested
- Maven created-guard covered (old artifact => no HEADs; fresh => HEAD ALL
  poms, min Last-Modified)
- NUnit alias resolved (NUnit.Framework -> NUnit, not the relic id)
- old-TFM System.* extras covered by test (net472 => System.Text.Json external)

## Documented accuracy limits (restated per spec)
- Java: import->artifact resolution is a curated longest-prefix map
  (PACKAGE_TO_ARTIFACT) plus declared-groupId prefixes. Anything unmapped
  degrades to H007 "cannot map" — NEVER a guessed red. mapping findings all
  carry precision=heuristic.
- .NET: namespace->package-id candidates are the full namespace + first two
  segments (+ curated alias fixups). Same heuristic stamping; misses degrade
  to H007/H008-heuristic, and the CP-3 trust gate downgrades H008 to H007
  whenever an unmatched declared package could be the provider.
- Maven: no download counts exist at all (H005 unreachable for maven);
  created is a Last-Modified heuristic on young artifacts only.
- NuGet: search is NEVER used for existence (it lags); registration
  1900-unlisted stamps excluded from created/latest.

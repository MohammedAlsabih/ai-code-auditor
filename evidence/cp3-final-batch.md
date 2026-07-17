# CP-3 Final Batch — 9 counter-cases (2026-07-18)

All 9 claims reproduced independently BEFORE fixing (9 parallel skeptic agents,
plus WSL for the symlink hypothesis). All 9 confirmed. All 9 fixed.

| # | Claim | Repro verdict | Fix |
|---|---|---|---|
| 1 | Bio/dns/grpc→H002, rest_framework→H008 red, all `exact` | CONFIRMED (exact rule ids) | Trust policy: `import_mapping_trust` per-import ("exact" only for curated aliases/win32); identity convention = heuristic. Unmatched-declared deps become "potential providers": convention-guess H008 degrades to H007-with-provider-hint; H001-dead deps excluded from providers. + curated aliases (Bio, dns, grpc, rest_framework, kafka, MySQLdb, psycopg2, …) + corpus test incl. google/azure |
| 2 | setup.py regex reads comments/strings; dynamic silently dropped | CONFIRMED (all 3 sub-cases) | AST parser (`ast.parse`, never executed); literal lists only, per-element line numbers; dynamic exprs → note + `manifest_incomplete` |
| 3 | foo.py claims `foo.nonexistent` as internal | CONFIRMED (ns.ghost half did NOT reproduce — already correct) | Three-way split: packages (subtree) / module files (exact) / namespace dirs (exact) |
| 4 | `https://TOKEN@host` and `api_key=` survive redaction | CONFIRMED (narrower: access-key/private-token/password already covered) | Full-userinfo redaction; sensitive-key list (api-key, access-key, private-token, auth-token, session-token, token, password, passwd, pwd, secret, authorization, credential(s), auth) with `=`/`:` forms |
| 5 | Cache validates shape not field types | CONFIRMED (`"false"` served; created=123 → age_days AttributeError) | `_HIT_SCHEMA` per-field type validation (incl. bool-is-int guard); any mismatch = cold miss |
| 6 | Silent [] for project/tool/poetry-group/uv-sources wrong types; oversize double-entry | CONFIRMED (all 5 sub-cases; duplicate count 2) | `_schema_note` on every coercion + marks `manifest_incomplete`; walk `_note` dedups per entry; NEW `Diagnostics.analysis_confidence()` = full/partial/degraded derived from the ledger |
| 7 | uv list-of-conditional-sources ignored | CONFIRMED (dep-a False, dep-b True) | list[table] handled; conservative: ANY local/vcs/workspace alternative (even marker-gated, mixed with index) ⇒ skip_registry |
| 8 | `>3.13.0-rc1,<3.13.0-rc3` → None | CONFIRMED (packaging accepts both forms) | Bounds from `SpecifierSet`/`Specifier.version` via `Version` normalization (`_bound_versions`); wildcard `==3.12.*` handled |
| 9 | Symlinked manifest escapes scan root | Windows: untestable (OSError 22). WSL: CONFIRMED (leaked-dep-name declared silently; `-r` half already blocked) | Central guard in `LanguageAdapter._read`: resolved path outside `_scan_root` ⇒ refused + manifest_errors entry. Re-verified under WSL after fix: no leak, ledger entry present |

## Verification
- pytest: 132 passed, 1 skipped (symlink test skips w/o privilege) on Python 3.11.0 AND 3.12
- ruff check src: clean · mypy src: clean
- lizard: 9 functions >CCN 10 remain (NOT claimed clean); the two I regressed
  while editing (_poetry_deps 21→split, _judge_import 18→split) were reduced;
  no general refactor performed
- WSL end-to-end re-verification of point 9 after the fix

## New heuristics + precision limits (for the session report)
- dash→dot declared-match (google-cloud-storage ⇝ google.cloud.storage) STILL
  silences fully — deliberate FP-avoidance bias; an adversarial declared
  `foo-bar` that does not provide `foo.bar` would be wrongly silenced (accepted,
  documented).
- H008 red now requires: curated mapping, OR no surviving potential provider.
  Its precision stamp is "heuristic" whenever the identity convention was used.
- Providers list excludes registry-confirmed-dead declared deps unless a
  private source is configured.

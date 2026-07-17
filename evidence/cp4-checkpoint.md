# CP-4 — Phase 4 complete (2026-07-18, autonomous per user authorization)

Commits: 19a29da (T10 npm), dbcbbfc (T11 TS adapter), f94e9dc+bbbf7fe (T12 R001-R003),
fabe6d4 (T13 R004-R007), T14 in the following commit.

## Coverage
- npm client (size-capped, schema-tolerant, verbatim case-sensitive cache key)
- TypeScript adapter: deps (npm: aliases, workspace/file/git skips), imports
  (import/export/require/dynamic), node builtins, tsconfig aliases (+targets,
  baseUrl, 1-level extends), frameworks (react/next incl. src/ layouts),
  scoped unresolvable_hint (core stays neutral), _scan_root symlink guard
- 11 rules: R001-R007 (react) + N001-N005 (next) + N006 module-graph
  (dual-state BFS, orphan analysis, type-only-edge exclusion, alias-target
  resolution)
- Fixture ts_repo with planted bugs; E2E over adapter+engine AND adapter+rules

## Gate results
- pytest: 194 passed, 1 skipped (3.11 AND 3.12) · ruff clean · mypy clean
- Corpus-derived negatives all green: custom hook OK, complete deps OK,
  setter-only effect OK, literal __html OK, client-boundary leaf OK,
  memo/forwardRef OK, prior-callback-return OK
- All next-graph tests green (10, incl. the three fifth-round cases)
- **ESLint corpus RE-RUN against the implemented rules** (not code-derived
  tests): evidence/react-compare/compare_auditor.py → 18 files,
  16 AGREE, 2 DIVERGE — exactly the two documented intentional divergences:
  - effect_no_deps.tsx: R004 (spec requires flagging; exhaustive-deps ignores
    a missing deps argument by design)
  - hook_in_try_catch.tsx: R001 (react.dev/rules-of-hooks forbids; ESLint
    7.1.1 verified silent)

## Integration defect found & fixed during E2E
`jsx_attribute` queries crash on the plain `typescript` grammar (only tsx has
JSX nodes) — R006/R007/N003/N006 jsx passes now gate on sf.language == "tsx".
Precision limit documented: JSX inside plain .js files is not analyzed (Next
convention uses .jsx/.tsx).

## Example findings (fixture E2E)
- H001 red package.json: left-pad-ai-super declared, not in registry
- H002 yellow lib/db.ts: pg imported, not declared (exists in registry)
- H008 red lib/db.ts: axios-retry-ai imported, not declared, not in registry
- R001 red components/Widget.tsx: useState inside if (visible)
- R004 yellow components/Widget.tsx: useEffect without deps array
- R006 yellow components/Widget.tsx: key={index}
- R007 red components/Widget.tsx: dangerouslySetInnerHTML={{__html: html}}
- N001 red .env.local: NEXT_PUBLIC_API_SECRET (value never echoed)
- N006 red app/page.tsx: useState + onClick in a server import path (graph)

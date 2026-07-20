# AI Code Auditor Report

**Target:** `tests/fixtures/monorepo` · **Generated:** 2026-07-20T08:17:47.058937+00:00 · **Tool:** ai-code-auditor v0.1.0

## Executive Summary | الملخص التنفيذي

Overall code-health score (higher = safer) | درجة سلامة الكود: **14/100**
**Verdict | الحكم الآلي: `BLOCK`**
- 🔴 Error: 7   🟡 Warning: 9   🔵 Note: 8
- ⚠️ Lowest language | أدنى لغة: **typescript = 0/100** (the average must not hide this)
- Analysis confidence | ثقة التحليل: 48/100 (separate axis: how COMPLETE the checks were, not how risky the code is)

## Engines

| Engine | Status |
|---|---|
| ast | tree-sitter 0.26 (python/java/csharp/typescript/tsx) |
| registry | offline |
| complexity | lizard |
| semgrep | disabled by --no-semgrep (builtin rules only) |

## Scores per language

| Language | Files | Score | Error | Warning | Note |
|---|---|---|---|---|---|
| python (`.`) | 2 | **50/100** | 2 | 4 | 4 |
| typescript (`web`) | 5 | **0/100** | 5 | 5 | 4 |

**Scoring contract | عقد الدرجات:** `code_health per language = max(0, 100 - 15*error - 5*warning) — HIGHER is safer (this is a health/safety score, deliberately NOT named 'risk'); note findings are informational and never affect health; overall = file-count-weighted average, ALWAYS reported alongside lowest language and error count. analysis_confidence = coverage-v2 (experimental): round(100 * file_coverage * manifest_coverage * (0.5 + 0.5*registry_coverage) * rule_health * parse_factor * semgrep_factor) where file_coverage = read/(read+skipped), manifest_coverage = 1 - affected_manifest_files/unique_manifest_files where affected = union(errored, incomplete) by canonical path (a partially-extracted manifest or a missing/outside include counts too), registry_coverage = 0 offline else 1 - failures/attempted, rule_health = 1 - rule_failures/rule_attempted (uncapped), parse_factor = 1 - min(1, parse_errors/files_read) (uncapped), semgrep_factor = 1.0 success / 0.97 partial / 0.95 otherwise. verdict: block if error>0 or confidence<40 or ALL rule invocations failed; review if warning>0 or confidence<70 or any manifest/rule/parse failure; else pass — any rule failure forbids pass.` — i.e. `max(0, 100 - 15*error - 5*warning)` per language; `note` is informational and never changes the score. Findings marked `*` are heuristic (`precision: heuristic`), not proofs.

## Python — `.` (50/100)

| Level | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 warning | H007* | `app.py:4` | `yaml` | yaml: imported but not declared; registry check skipped (--offline) |
| 🟡 warning | H007* | `app.py:5` | `superjsonify` | superjsonify: imported but not declared; registry check skipped (--offline) |
| 🔴 error | P002 | `app.py:8` | `API_KEY = "***"  # planted AWS-style key for Engine 2` | AWS access key committed in source. |
| 🟡 warning | P001 | `app.py:14` | `except Exception:` | Exception is silently swallowed — failures become invisible. |
| 🔵 note | P007 | `app.py:15` | `pass  # TODO: implement error handling` | Marker 'TODO: implement' suggests incomplete/demo-grade code left by generation. |
| 🔵 note | P007 | `app.py:19` | `# In a real application, use parameterized queries` | Marker 'In a real app' suggests incomplete/demo-grade code left by generation. |
| 🔴 error | P005* | `app.py:20` | `"SELECT * FROM users WHERE name = '" + name + "'"` | Composed SQL is passed to 'cursor.execute' — SQL injection risk; use parameterized queries. |
| 🟡 warning | P006 | `app.py:23` | `classify` | classify has cyclomatic complexity 11 (> 10). |
| 🔵 note | H003 | `requirements.txt:1` | `requests==2.32.3` | requests: registry check skipped (--offline) |
| 🔵 note | H003 | `requirements.txt:2` | `ghost-ai-utils==9.9.9` | ghost-ai-utils: registry check skipped (--offline) |

## Typescript — `web` (0/100)
Frameworks: react, next

| Level | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🔴 error | N001 | `.env.local:1` | `NEXT_PUBLIC_API_SECRET=***` | NEXT_PUBLIC_API_SECRET in .env.local ships to the client bundle. |
| 🔴 error | N006* | `app/page.tsx:4` | `useState(0)` | useState runs in a SERVER import path (module-graph); add "use client" at the boundary that should own this file. |
| 🔴 error | N006* | `app/page.tsx:5` | `onClick={() => setCount(count + 1)}` | onClick event handler in a SERVER import path (module-graph). |
| 🔴 error | R001* | `components/Widget.tsx:7` | `useState('')` | useState is called inside a if statement; hooks must run unconditionally at the top level. |
| 🟡 warning | R004* | `components/Widget.tsx:9` | `useEffect(() => {     setVisible(true);   })` | useEffect has no dependency array; it re-runs after every render. |
| 🔴 error | R007* | `components/Widget.tsx:13` | `dangerouslySetInnerHTML={{ __html: html }}` | __html is not a proven string literal; any user-influenced content here is an XSS vector (heuristic — no taint analysis). |
| 🟡 warning | R006 | `components/Widget.tsx:15` | `key={index}` | key={index} is the .map() index; reordering or deleting items will confuse React reconciliation. |
| 🟡 warning | H007* | `lib/db.ts:3` | `pg` | pg: imported but not declared; registry check skipped (--offline) |
| 🟡 warning | H007* | `lib/db.ts:4` | `axios-retry-ai` | axios-retry-ai: imported but not declared; registry check skipped (--offline) |
| 🟡 warning | P004* | `lib/db.ts:9` | ``SELECT * FROM users WHERE id = ${userId}`` | SQL assembled from dynamic strings; prefer parameterized queries. |
| 🔵 note | H003 | `package.json` | `dependencies: left-pad-ai-super@^1.0.0` | left-pad-ai-super: registry check skipped (--offline) |
| 🔵 note | H003 | `package.json` | `dependencies: next@^16.0.0` | next: registry check skipped (--offline) |
| 🔵 note | H003 | `package.json` | `dependencies: react@^19.0.0` | react: registry check skipped (--offline) |
| 🔵 note | H003 | `package.json` | `devDependencies: @types/node@^24.0.0` | @types/node: registry check skipped (--offline) |

## Limitations | حدود الفحص

- Offline mode: no registry verification was performed.
- semgrep layer: disabled by --no-semgrep (builtin rules only).
- Undetectable private-source channels (env vars, ~/.m2/settings.xml mirrors, CI config) cannot be ruled out for not-found packages.
- Private registries are NEVER contacted; packages behind them are classified unverified (H010), and the public registry is not treated as the source of truth for them.

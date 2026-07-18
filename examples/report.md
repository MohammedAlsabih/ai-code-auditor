# AI Code Auditor Report

**Target:** `tests\fixtures\monorepo` · **Generated:** 2026-07-18T12:35:56.540265+00:00 · **Tool:** ai-code-auditor v0.1.0

## Executive Summary | الملخص التنفيذي

Overall code-health score (higher = safer) | درجة سلامة الكود: **14/100**
**Verdict | الحكم الآلي: `BLOCK`**
- 🔴 Critical: 7   🟡 Warning: 9   🔵 Info: 8
- ⚠️ Lowest language | أدنى لغة: **typescript = 0/100** (the average must not hide this)
- Analysis confidence | ثقة التحليل: 48/100 (separate axis: how COMPLETE the checks were, not how risky the code is)

## Engines

| Engine | Status |
|---|---|
| ast | tree-sitter 0.26 (python/java/csharp/typescript/tsx) |
| registry | offline |
| complexity | lizard |
| semgrep | not available (builtin rules only) |

## Scores per language

| Language | Files | Score | 🔴 | 🟡 | 🔵 |
|---|---|---|---|---|---|
| python (`.`) | 2 | **50/100** | 2 | 4 | 4 |
| typescript (`web`) | 5 | **0/100** | 5 | 5 | 4 |

**Scoring contract | عقد الدرجات:** `code_health per language = max(0, 100 - 15*red - 5*yellow) — HIGHER is safer (this is a health/safety score, deliberately NOT named 'risk'); blue findings are informational and never affect health; overall = file-count-weighted average, ALWAYS reported alongside lowest language and red count. analysis_confidence = coverage-v2 (experimental): round(100 * file_coverage * manifest_coverage * (0.5 + 0.5*registry_coverage) * rule_health * parse_factor * semgrep_factor) where file_coverage = read/(read+skipped), manifest_coverage = 1 - affected_manifest_files/unique_manifest_files where affected = union(errored, incomplete) by canonical path (a partially-extracted manifest or a missing/outside include counts too), registry_coverage = 0 offline else 1 - failures/attempted, rule_health = 1 - rule_failures/rule_attempted (uncapped), parse_factor = 1 - min(1, parse_errors/files_read) (uncapped), semgrep_factor = 1.0 success / 0.97 partial / 0.95 otherwise. verdict: block if red>0 or confidence<40 or ALL rule invocations failed; review if yellow>0 or confidence<70 or any manifest/rule/parse failure; else pass — any rule failure forbids pass.` — i.e. `max(0, 100 - 15*🔴 - 5*🟡)` per language; 🔵 is informational and never changes the score. Findings marked `*` are heuristic (`precision: heuristic`), not proofs.

## Python — `.` (50/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H007* | `app.py:4` | `yaml` | yaml: imported but not declared; registry check skipped (--offline) |
| 🟡 | H007* | `app.py:5` | `superjsonify` | superjsonify: imported but not declared; registry check skipped (--offline) |
| 🔴 | P002 | `app.py:8` | `API_KEY = "***"  # planted AWS-style key for Engine 2` | AWS access key committed in source. |
| 🟡 | P001 | `app.py:14` | `except Exception:` | Exception is silently swallowed — failures become invisible. |
| 🔵 | P007 | `app.py:15` | `pass  # TODO: implement error handling` | Marker 'TODO: implement' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `app.py:19` | `# In a real application, use parameterized queries` | Marker 'In a real app' suggests incomplete/demo-grade code left by generation. |
| 🔴 | P005* | `app.py:20` | `"SELECT * FROM users WHERE name = '" + name + "'"` | Composed SQL is passed to 'cursor.execute' — SQL injection risk; use parameterized queries. |
| 🟡 | P006 | `app.py:23` | `classify` | classify has cyclomatic complexity 11 (> 10). |
| 🔵 | H003 | `requirements.txt:1` | `requests==2.32.3` | requests: registry check skipped (--offline) |
| 🔵 | H003 | `requirements.txt:2` | `ghost-ai-utils==9.9.9` | ghost-ai-utils: registry check skipped (--offline) |

## Typescript — `web` (0/100)
Frameworks: react, next

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🔴 | N001 | `.env.local:1` | `NEXT_PUBLIC_API_SECRET=***` | NEXT_PUBLIC_API_SECRET in .env.local ships to the client bundle. |
| 🔴 | N006* | `app/page.tsx:4` | `useState(0)` | useState runs in a SERVER import path (module-graph); add "use client" at the boundary that should own this file. |
| 🔴 | N006* | `app/page.tsx:5` | `onClick={() => setCount(count + 1)}` | onClick event handler in a SERVER import path (module-graph). |
| 🔴 | R001* | `components/Widget.tsx:7` | `useState('')` | useState is called inside a if statement; hooks must run unconditionally at the top level. |
| 🟡 | R004* | `components/Widget.tsx:9` | `useEffect(() => {     setVisible(true);   })` | useEffect has no dependency array; it re-runs after every render. |
| 🔴 | R007* | `components/Widget.tsx:13` | `dangerouslySetInnerHTML={{ __html: html }}` | __html is not a proven string literal; any user-influenced content here is an XSS vector (heuristic — no taint analysis). |
| 🟡 | R006 | `components/Widget.tsx:15` | `key={index}` | key={index} is the .map() index; reordering or deleting items will confuse React reconciliation. |
| 🟡 | H007* | `lib/db.ts:3` | `pg` | pg: imported but not declared; registry check skipped (--offline) |
| 🟡 | H007* | `lib/db.ts:4` | `axios-retry-ai` | axios-retry-ai: imported but not declared; registry check skipped (--offline) |
| 🟡 | P004* | `lib/db.ts:9` | ``SELECT * FROM users WHERE id = ${userId}`` | SQL assembled from dynamic strings; prefer parameterized queries. |
| 🔵 | H003 | `package.json` | `dependencies: left-pad-ai-super@^1.0.0` | left-pad-ai-super: registry check skipped (--offline) |
| 🔵 | H003 | `package.json` | `dependencies: next@^16.0.0` | next: registry check skipped (--offline) |
| 🔵 | H003 | `package.json` | `dependencies: react@^19.0.0` | react: registry check skipped (--offline) |
| 🔵 | H003 | `package.json` | `devDependencies: @types/node@^24.0.0` | @types/node: registry check skipped (--offline) |

## Limitations | حدود الفحص

- Offline mode: no registry verification was performed.
- semgrep layer: not available (builtin rules only).
- Undetectable private-source channels (env vars, ~/.m2/settings.xml mirrors, CI config) cannot be ruled out for not-found packages.
- Private registries are NEVER contacted; packages behind them are classified unverified (H010), and the public registry is not treated as the source of truth for them.

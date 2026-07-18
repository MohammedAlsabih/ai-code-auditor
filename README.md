# AI Code Auditor | مدقّق الكود المولَّد بالذكاء الاصطناعي

<div dir="rtl">

## ما هذه الأداة؟

أداة **حتمية** (بدون أي نموذج لغوي) لفحص المستودعات التي كُتب جزء كبير منها
بأدوات توليد الكود، وتكشف فئتين من العيوب النمطية لهذا الكود:

1. **المحرّك الأول — التبعيات المهلوسة:** كل استيراد وكل تبعية معلنة تُقارن
   بالسجل العام الرسمي (PyPI / npm / Maven Central / NuGet). حزمة معلنة غير
   موجودة في السجل = هلوسة محتملة واسم قابل للاستيلاء (slopsquatting).
   حزمة حديثة جداً بتنزيلات شبه معدومة = إنذار سلسلة توريد.
2. **المحرّك الثاني — الأنماط الخطرة:** قواعد AST عبر tree-sitter لكل لغة:
   أسرار مكتوبة في الكود، SQL مركّب نصياً، كتل catch فارغة، قواعد React
   (Rules of Hooks) وحدود Next.js بين الخادم والعميل عبر **رسم بياني فعلي
   لاستيراد الوحدات**، وقواعد Java/.NET المتخصصة، وتعقيد دوراني عبر lizard،
   وطبقة semgrep/opengrep اختيارية.

بدون تنفيذ أي كود من المستودع المفحوص، وبدون أي LLM، وقابلة للعمل دون شبكة
(`--offline`).

## التثبيت

</div>

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
.venv\Scripts\auditor --version
```

<div dir="rtl">

## الاستخدام

</div>

```powershell
auditor scan https://github.com/org/repo            # يفحص مستودعاً عاماً
auditor scan C:\path\to\project --output my-report  # مساراً محلياً
auditor scan . --offline                            # بدون أي اتصال شبكي
auditor scan . --strict                             # review يفشل أيضاً (CI)
auditor scan . --no-semgrep                         # القواعد المدمجة فقط
auditor scan . --semgrep-bin C:\tools\opengrep.exe --semgrep-config my.yml
```

**Exit codes:** `0` = clean/pass · `1` = verdict BLOCK (or REVIEW with
`--strict`) · `2` = fatal error (bad target, git failure).

Reports land in `--output` (default `auditor-report/`): `report.md`
(bilingual, human) + `report.json` (machine, full diagnostics ledger).

## Rule catalog | فهرس القواعد

| Family | Rules | What it catches |
|---|---|---|
| **H** hallucination | H001 red declared-not-in-registry · H002 yellow undeclared-but-exists · H003 blue offline-unverified · H004 blue registry-unreachable · H005 yellow brand-new+no-downloads · H006 yellow fresh package · H007 yellow unmappable import (accuracy limit, never guessed red) · H008 red imported+not-declared+not-in-registry · H009 red quarantined · H010 yellow private-source unverifiable · H012 blue archived | Engine 1, all four ecosystems |
| **P** common | P001 empty catch · P002 red known secret tokens (masked) · P003 yellow credential literal · P004/P005 SQL string composition (P005 red at execution sink) · P006 cyclomatic complexity >10 · P007 blue AI-incompleteness comments · P008 blue stdlib drift vs requires-python | language-neutral core, syntax via adapter profiles |
| **R** React | R001 red conditional hook (if/loop/ternary/&&/try + early-return) · R002 red hook in hook-callback · R003 yellow hook outside component/custom-hook (memo/forwardRef exempt) · R004 yellow effect without deps array · R005 yellow obviously missing deps · R006 yellow key={index} · R007 red non-literal dangerouslySetInnerHTML | corpus-compared vs eslint-plugin-react-hooks 7.1.1: 16/18 agree, 2 documented intentional divergences |
| **N** Next.js | N001 red NEXT_PUBLIC secret (code + .env*, value never echoed) · N002 yellow private env in client · N003 red client API in server component (per-file fallback) · N004 red server-only import in client · N005 yellow async client component · N006 red client API in server **module-graph** path (dual-state BFS, orphans analyzed as server default) | graph excludes middleware/instrumentation/metadata routes (documented) |
| **J/D** | J001 String == · J002 missing try-with-resources · D001 async void · D002 .Result/.Wait blocking · D003 red raw-SQL interpolation | Java / .NET |
| **S:** | prefixed semgrep/opengrep findings (optional layer) | bundled MIT rules only by default |

## Scoring | الدرجات

`code_health = max(0, 100 − 15·🔴 − 5·🟡)` per language (🔵 informational,
never counted), overall = file-count-weighted average **always shown next to
the lowest language** so the average can never hide a red project.
`analysis_confidence` is a **separate axis** — how *complete* the checks were
(coverage-v2: file/manifest/registry/rule/parse/semgrep ratios), not how risky
the code is. Verdict: `block` (any red, confidence < 40, or total rule
collapse) / `review` (any yellow OR any manifest/rule/parse failure) / `pass`.

## Architecture | البنية

```
src/auditor/
├── cli.py                 # scan pipeline + exit codes
├── fetch.py               # hardened git clone (hooks/env neutralized, redaction)
├── discovery.py           # project discovery + manifestless fallback
├── core/                  # language-AGNOSTIC: zero adapter imports (test-enforced)
│   ├── models.py            # Finding / DeclaredDep / Diagnostics ledger
│   ├── interfaces.py        # LanguageAdapter + SyntaxProfile contracts
│   ├── hallucination.py     # Engine 1 (trust-gated H-verdicts)
│   ├── rules_common.py      # P-rules via adapter syntax profiles
│   ├── patterns.py          # Engine 2 orchestrator (failure accounting)
│   ├── complexity.py        # lizard P006
│   ├── semgrep_runner.py    # optional layer, completeness-reconciled
│   ├── scoring.py           # health/confidence/verdict contracts
│   └── ownership.py         # monorepo finding assignment
├── adapters/              # one per language: python / typescript / java / dotnet
├── registries/            # PyPI / npm / Maven repo1 / NuGet + TTL cache
└── report/                # markdown + json builders
```

## Limitations | الحدود المعلنة

- **Java/.NET mapping accuracy:** import→artifact resolution rests on curated
  prefix maps + declared-id prefixes. Unmapped imports degrade to **H007
  (unresolved)** — never a guessed red. All mapping-based findings carry
  `precision: heuristic`.
- **Python trust policy:** import-name == PyPI-name is a *convention*; a red
  H008 requires either a curated mapping or the absence of any unmatched
  declared distribution that could provide the module.
- **Maven Central exposes no download counts** (H005 unreachable there);
  `created` is a Last-Modified heuristic on young artifacts only.
- **Private registries are never contacted.** Packages behind them are
  H010-unverifiable; env-var/mirror/CI channels cannot be ruled out.
- **Next graph exclusions:** middleware, instrumentation and metadata routes
  are not part of the render graph; string-built dynamic import paths are not
  resolved (reported as unresolved edges, never guessed).
- **semgrep licensing:** only our own MIT-provenance rules are bundled and run
  by default. Semgrep-Registry packs are opt-in via `--semgrep-config` and run
  under *your* license responsibility (Semgrep Rules License v1.0).
- JSX inside plain `.js` files is not analyzed (grammar limits; `.jsx`/`.tsx`
  are).

See `examples/report.md` + `examples/report.json` for real output.

## Development

```powershell
python -m pip install -e ".[dev]"          # pins pytest/mypy/ruff/type-stubs
.venv\Scripts\python -m pytest -q          # offline, both 3.11/3.12
.venv\Scripts\python -m ruff check src
.venv\Scripts\python -m mypy src           # config in [tool.mypy]; no flags needed
```

Deterministic by design: same input ⇒ same findings. No telemetry. No LLM.

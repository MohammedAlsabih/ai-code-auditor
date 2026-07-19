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
| **H** hallucination | H001 error declared-not-in-registry · H002 warning undeclared-but-exists · H003 note offline-unverified · H004 note registry-unreachable · H005 warning brand-new+no-downloads · H006 warning fresh package · **H007 warning unverified undeclared import** (unmappable OR probable-hallucination whose registry name came from a *heuristic* mapping — Python identity, Java/.NET prefix; never a hard block) · **H008 error hallucinated import** (only when the mapping is *exact* — npm literal — and the name is absent) · H009 error quarantined · H010 warning private-source unverifiable · H012 note archived | Engine 1, all four ecosystems |
| **P** common | P001 empty catch · P002 error known secret tokens (masked) · P003 warning credential literal · P004/P005 SQL string composition (P005 error at execution sink) · P006 cyclomatic complexity >10 · P007 note AI-incompleteness comments · P008 note stdlib drift vs requires-python | language-neutral core, syntax via adapter profiles |
| **R** React | R001 error conditional hook (if/loop/ternary/&&/try + early-return) · R002 error hook in hook-callback · R003 warning hook outside component/custom-hook (memo/forwardRef exempt) · R004 warning effect without deps array · R005 warning obviously missing deps · R006 warning key={index} · R007 error non-literal dangerouslySetInnerHTML | corpus-compared vs eslint-plugin-react-hooks 7.1.1: 16/18 agree, 2 documented intentional divergences |
| **N** Next.js | N001 error NEXT_PUBLIC secret (code + .env*, value never echoed) · N002 warning private env in client · N003 error client API in server component (per-file fallback) · N004 error server-only import in client · N005 warning async client component · N006 error client API in server **module-graph** path (dual-state BFS, orphans analyzed as server default) | graph excludes middleware/instrumentation/metadata routes (documented) |
| **J/D** | J001 String == · J002 missing try-with-resources · D001 async void · D002 .Result/.Wait blocking · D003 error raw-SQL interpolation | Java / .NET |

Finding classification uses SARIF-compatible **levels**: `error` / `warning` /
`note` (OASIS SARIF 2.1.0 `result.level`, §3.27.10). The red/yellow/blue
colors that appear in reports and the web UI are **presentation only** — a
visual derivation of the level, never the contract value. Legacy `severity`
fields remain in report.json temporarily for backward compatibility.
| **S:** | prefixed semgrep/opengrep findings (optional layer) | bundled MIT rules only by default |

## Scoring | الدرجات

`code_health = max(0, 100 − 15·error − 5·warning)` per language (`note` informational,
never counted), overall = file-count-weighted average **always shown next to
the lowest language** so the average can never hide a error project.
`analysis_confidence` is a **separate axis** — how *complete* the checks were
(coverage-v2: file/manifest/registry/rule/parse/semgrep ratios), not how risky
the code is. Verdict: `block` (any error, confidence < 40, or total rule
collapse) / `review` (any warning OR any manifest/rule/parse failure) / `pass`.

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
  (unresolved)** — never a guessed error. All mapping-based findings carry
  `precision: heuristic`.
- **Hallucination severity contract:** a definitive **error H008** fires only for
  an *exact* mapping (npm, where the import literally is the package name). Every
  *heuristic* mapping (Python import↔dist convention, Java/.NET prefix maps) that
  resolves to an absent name is a **warning H007** "unverified undeclared import" —
  it always surfaces for review but never blocks on a guess. A declared package
  never silently suppresses it; an unlinked declared distribution is named in the
  finding as a possible (unverified) provider.
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

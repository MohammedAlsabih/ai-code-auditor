# المراجعة العدائية لبحث وخطة AI Code Auditor — جداول القرارات والأدلة

**التاريخ:** 2026-07-17 · **المنهج:** كل فرضية خضعت لمحاولة دحض عبر تجربة حية قابلة للتكرار أو مصدر رسمي مباشر. لا يوجد ادعاء "تم التحقق" بلا أمر ونتيجة محفوظة.
**مواضع الأدلة:** ملفات التجارب كلها محفوظة تحت `%TEMP%\claude\C--project-auditor\...\scratchpad\` (أبرزها: `react-compare\` قابل لإعادة التشغيل بالكامل، `semgrep_license_text.txt`، `log4j-metadata.xml`، `nuget-index.json`، `xml_stress.py`).
**اصطلاح الحكم:** ✅ تأكيد القرار الأصلي · 🔧 تعديل · 🧪 إبقاء تجريبياً · ⛔ إخراج من الـ MVP · ❌ فرضية مدحوضة (تُدرج في قائمة المرفوضات).

---

## المحور 1 — قابلية تدقيق البحث

| الادعاء الأصلي | طريقة الاختبار / الأمر | النتيجة الفعلية | المصدر والتاريخ | الحكم |
|---|---|---|---|---|
| إصدارات tree-sitter (0.26.0) والقواعد الأربع وsemgrep 1.170.0 | `curl.exe -s https://pypi.org/pypi/<pkg>/json` لكل حزمة | كلها مطابقة (tree-sitter 0.26.0 بتاريخ 2026-06-30 بالضبط) | PyPI JSON API، 2026-07-17 | ✅ |
| lizard: "الإصدار 1.23.0 قديم من 2024-03" | نفس الأمر + سجل الإصدارات | **خطأ التاريخ**: 1.23.0 صدر **2026-06-02**، و6 إصدارات بين أبريل–يونيو 2026 | PyPI، 2026-07-17 | 🔧 تصويب في RESEARCH — والاختيار يتعزز |
| ترخيص قواعد semgrep "يحظر المنتجات المنافسة" | جلب النص الحرفي `curl -sL semgrep.dev/legal/rules-license/` + `grep -ci compet` = **0** | لا يوجد أي بند "منافسة". القيود الحرفية: "only for your own internal business purposes" + "does not allow you to distribute the rules, or to make them available to others as a service" + non-sublicensable | النص الحي (آخر تحديث 2024-12-13)، وصول 2026-07-17 | 🔧 تصويب التسبيب؛ القرار (عدم التضمين + passthrough بمسؤولية المستخدم) يثبت نصياً |
| opengrep-rules "بديل نظيف قابل للتضمين" | GitHub API + LICENSE خام | **المستودع مؤرشف** (آخر دفعة 2025-11-28)، الترخيص Commons Clause فوق LGPL-2.1 وما زال يسمّي Semgrep Inc. مرخِّصاً، وREADME يحصره في "research, testing & benchmarking" | api.github.com + raw LICENSE، 2026-07-17 | ❌ الفرضية مدحوضة — لكن خطتنا لم تتضمّنه أصلاً فلا أثر تنفيذي |
| أرقام الأدوات المنافسة | GitHub API لكل مستودع (نجوم/ترخيص/pushed_at/archived) | صحيحة عموماً؛ تصويبان: deptry انتقل إلى osprey-oss (1436★)، وترخيص FawltyDeps هو MIT رغم NOASSERTION في الـ API | api.github.com، 2026-07-17 | 🔧 تحديث الجدول |

**الأثر:** RESEARCH.md v2 أصبح جدول أدلة (ادعاء/أمر/نتيجة/مصدر) بدل عبارات "تم التحقق".

## المحور 2 — حدود المعمارية (حياد core)

| الفرضية | الاختبار | النتيجة | الحكم |
|---|---|---|---|
| core لا يستورد من adapters | `grep "from auditor.adapters" plan` وتصنيف السياقات | **انتهاك واحد**: `core/patterns.py` يستورد `scan_env_files` من `adapters/typescript/next_rules` (بقية النتائج: tests/cli/adapters — مشروعة) | 🔧 |
| core لا "يعرف" اللغات بغير الاستيرادات | جرد مواضع التفرع اللغوي في كود الخطة | 4 مواضع معرفة صريحة: سلسلة if/elif في `treesitter.get_language` تستورد حزم القواعد بأسمائها؛ `_CATCH_QUERIES` بخمسة مفاتيح؛ تفرع `sf.language == "python"` في EmptyCatch؛ جدول `_COMPOSED` + تفرع csharp في SqlStringBuild. (`hallucination/walk/scoring/complexity` محايدة فعلاً) | 🔧 |

**القرار:** قلب الاعتماد — المحوّل يوفّر `grammars()` (يسجّل قواعده في سجل treesitter عام) و`syntax() → SyntaxProfile` (الـ queries وأنواع العقد) و`project_rules(root, frameworks)` (فحوص مستوى المشروع مثل .env). النواة تستهلك الواجهات فقط. **الأثر:** إضافة لغة خامسة تلمس محوّلها فقط؛ لا تغيير في الدقة؛ كلفة تعديل معتدلة على المهام 2/3/14/19/21.

## المحور 3 — React/Next.js: قياس فعلي مقابل ESLint

**التجربة:** corpus من 18 ملف tsx + eslint 9.39.5 + eslint-plugin-react-hooks 7.1.1 + typescript-eslint 8.64.0 بإعداد flat معزول (`--no-config-lookup`، قاعدتان فقط) مقابل **تنفيذ حرفي** لخوارزميات الخطة (R001–R005) على tree-sitter 0.26.0. قابل لإعادة التشغيل من `scratchpad\react-compare\`.

**النتيجة الكمية:** توافق تام 12/18 · FP=3 · FN=3 · دقة/استدعاء 72.7% مقابل ESLint كمرجع · **صفر أخطاء في أسماء عقد القواعد النحوية** (كود الخطة اشتغل دون أي تعديل).

| الانحراف | التشخيص | الحكم | الأثر |
|---|---|---|---|
| FN: `flag && useMemo()` | العمليات المنطقية `binary_expression` ليست في أنواع التحكم | 🔧 إضافة && / \|\| / ?? | يغلق فئة FN شائعة بسطر |
| FN: hook بعد `if (x) return null;` | فحص الأسلاف لا يرى الأشقاء السابقين | 🔧 مسح heuristic للأشقاء السابقين عن return (بلا CFG) — يُعلَّم precision=heuristic | يلتقط الحالة القياسية |
| FN: `onClick={() => useState()}` وكل callbacks غير الـ hooks | R003 كان يقفز فوق الدوال المجهولة لأول دالة مسماة | 🔧 إعادة تعريف R003: الحكم على الدالة الحاضنة **الأعمق** | يغلق فئة كاملة (map/promises/handlers) |
| FP (مقابل ESLint): hook داخل try/catch | ESLint 7.1.1 لا يعلّمها فعلاً؛ لكن react.dev/reference/rules/rules-of-hooks يحظرها نصاً | ✅ إبقاء مقصود، موثق كاختلاف عن ESLint بمرجعه | صرامة أعلى من الـ linter بوعي |
| FP (مقابل ESLint): useEffect بلا مصفوفة | exhaustive-deps يتجاهلها بتصميمه؛ **مواصفة المشروع تطلبها نصاً** | ✅ إبقاء (أصفر) — انحراف تفرضه المواصفة | موثق |
| FP: R005 يلتقط useState المعرّف داخل الـ callback نفسه | خطأ نطاق في جمع الأسماء التفاعلية | 🔧 استثناء declarators داخل عقدة الـ callback | يزيل FP حقيقياً |
| فجوة module-graph: ملف hooks بلا directive مستورد من Server Component | برهان عملي: 0 نتائج على حالة تفشل بناءً في Next 16 (الوثائق الرسمية: الحدود على مستوى module graph) | 🧪 اقتراح تمريرة import-graph خفيفة (N006، BFS على الاستيرادات المستخرجة أصلاً) — **معلّق على قرارك** لأنه توسيع تحليل | بدونه: فئة FN بنيوية موثقة؛ معه: تغطية بند المواصفة فعلياً |
| ملف بلا directive مستورد من Client boundary (شرعي) | التجربة: 0 نتائج | ✅ لا FP في الاتجاه المعاكس | — |

## المحور 4 — دلالات الحزم المشتبهة

| الفرضية | الدليل | الحكم |
|---|---|---|
| "غير موجودة في السجل" = هلوسة قطعاً | حالة aiocpa: حزمة خبيثة **حُجرت ثم أزيلت** → 404 اليوم؛ والحزم الخاصة (npm scoped بلا توكن) تعيد 404 أيضاً | 🔧 إعادة صياغة H001 بلغة الوقائع: "غير موجودة في السجل العام" + الهلوسة كسبب مرجّح لا حكم |
| يمكن كشف السجلات الخاصة من المستودع | مصفوفة رسمية كاملة (محور 6): ملفات قابلة للكشف (.npmrc للمشروع، ‎--index-url في requirements، tool.uv.index/poetry.source، nuget.config، ‎<repositories> في pom، gradle repositories) مقابل غير قابلة (env vars، ‎~/.m2/settings.xml mirrors، إعدادات CI) | 🔧 قاعدة جديدة **H010 أصفر**: "غير موجودة في السجل العام + مصدر خاص مُهيأ أو نطاق scoped ⇒ غير قابلة للتحقق (وانكشاف dependency-confusion)" بدل H001 الحمراء؛ وتحفظ دائم للقنوات غير القابلة للكشف |
| التفريق: حديثة/شبيهة باسم مشهور/مسجلة-بعد-هلوسة | الحداثة+التحميلات = H005/H006 (إشارة لا حكم — الصياغة عُدلت)؛ تشابه الأسماء يتطلب قوائم شعبية مدمجة؛ "سُجلت بعد ظهورها كهلوسة" يتطلب dataset تاريخي | تشابه الأسماء: ⛔ خارج MVP (مذكور كامتداد مع trendmicro dataset) — لا نحوّل الاحتمال إلى حكم |
| حالة archived في PyPI (اكتشاف أثناء المراجعة) | ثبتت حياً على 4 حزم (`{"status":"archived"}`) وبلا أي طلب إضافي | 🔧 إضافة **H012 أزرق** "حزمة مؤرشفة من مالكها" — كلفة صفرية |

## المحور 5 — دقة Java/.NET والمكتبات القياسية (قياس أرضي)

| الفرضية في الخطة | القياس | النتيجة | الحكم |
|---|---|---|---|
| كل `javax.*` = JDK | جرد وحدات JDK 21 الرسمية (docs.oracle.com، وحدة-وحدة) + فحص 18 artifact خارجياً بـ curl على repo1 (كلها 200) | **مدحوضة**: 21 بادئة javax فقط داخل JDK؛ servlet/persistence/mail/validation/inject/ws.rs/annotation/xml.bind... كلها خارجية — نقطة عمياء كاملة عن H002/H007/H008 + 4 فخاخ انقسام (annotation.processing/transaction.xa/rmi.ssl/xml.bind) | ❌→🔧 قائمة الـ 21 بادئة بمطابقة أطول-بادئة + استثناءات xml.bind/ws/soap |
| خريطة الحزم الـ 29 كافية | ground truth لـ 33 استيراداً شائعاً، كل إحداثية مؤكدة بـ curl=200 | 25 صحيحة / 4 نفس المجموعة-artifact خاطئ / 4 مفقودة-أو-ميتة. **الأخطر: JUnit4 يولّد H007 زائفة حتى مع `junit:junit` معلنة** (org.junit لا يطابق بادئة junit)؛ مفتاح kotlin ميت (الحزم `kotlin.*`)؛ caffeine غير قابلة للاشتقاق (شرطة ben-manes) | 🔧 إضافة/تصويب 8 مداخل + توثيق حدود |
| كل `System.*` = BCL | مصفوفة رسمية لكل TFM (learn.microsoft.com) | صحيحة تقريباً لـ net8/9 **باستثناء 5 namespaces تُسلَّم كحزم** (CommandLine/Data.SqlClient/Drawing/Management/Data.Entity)؛ **خاطئة بشدة** لـ net48/netstandard2.0 (Text.Json وCollections.Immutable حزم واجبة الإعلان) | 🔧 قائمة package-delivered دائمة + قراءة `TargetFramework(s)` (الجمع يلغي المفرد — موثق) لتوسيعها على الأطر القديمة؛ مجهول TFM ⇒ سلوك حديث |
| heuristic ‏NuGet (كامل/أول-قطعتين) | ‏15 حزمة شائعة، flat-container | 14/15 (93%). الإخفاق **مضلِّل** لا ضجيج: `NUnit.Framework` يحلّ إلى حزمة أثرية `nunit.framework 2.63.0` بدل NUnit؛ حالة الأحرف غير مؤثرة (مؤكد عملياً) | 🔧 خريطة أسماء مستعارة مصغرة ({nunit.framework→NUnit}) |
| Node builtins (قائمة 45) | node 24 فعلياً: builtinModules + require() + module.isBuiltin | 42/45 صحيحة؛ **`test`/`sea`/`sqlite` أسماء node:-scheme فقط** بكل النسخ (الوثائق الرسمية) وحزم npm بأسمائها موجودة (200) → القائمة الحالية تحجب فحوص سجل حقيقية؛ `sys` صحيحة (فرضية خطئها **مرفوضة**) | 🔧 حذف الأسماء الثلاثة المجردة فقط |
| ‏`sys.stdlib_module_names` وقت التشغيل يكفي | الاتجاهان مقيسان: distutils غائب عن 3.12 **وموجود كحزمة PyPI (200!)** → H002 زائفة اليوم؛ telnetlib موجود في 3.12 وغائب عن 3.13 وغير موجود على PyPI (404) → **H008 حمراء زائفة** لأي فاحص على 3.13+ | ❌→🔧 اتحاد ثابت: stdlib ∪ جدول المُزال (PEP 594 + PEP 632 + imp/lib2to3، بنسخ الإزالة) + فحص الاتجاه الثاني **فقط** عند requires-python قابلة للقراءة (P008 أزرق) — لا تخمين عند الغياب |

## المحور 6 — عملاء السجلات

| الفرضية | الاختبار | النتيجة | الحكم |
|---|---|---|---|
| تجميد solrsearch | مقارنة حية اليوم على jackson + spring | مؤكد بأعنف: يتخلف 21 إصداراً/major كامل؛ آخر طوابعه 2025-04/2025-06 | ✅ repo1 حصراً |
| `versions[0]` في metadata = أول نشر | **اختبار الدحض المصمم**: مواضع log4j 2.12.2–2.12.4 (منشورة 12/2021) + Last-Modified فعلية على 3 artifacts | **مدحوضة**: الترتيب version-sort لا زمني (البackports في موضعها الرقمي قبل 2.13.0 المنشور 2019)؛ والوثيقة الرسمية صامتة عن الترتيب أصلاً؛ و`<latest>` قد يكون beta | ❌→🔧 تاريخ الإنشاء يُلتقط فقط بحارس (إصدارات ≤10 + lastUpdated حديث) عبر HEAD على pom أدنى إصدار، موثقاً كـ heuristic؛ `<lastUpdated>` = آخر نشر (مؤكد من repository-metadata.html) |
| تثبيت عنوان NuGet registration | حل `v3/index.json` فعلياً + وثيقة الـ API | القيمة صحيحة لكن الوثيقة **تلزم** الحل الديناميكي ("must be dynamically fetched from the service index")، وhives ‏semver1 تعيد 404 لحزم SemVer2 حقيقية | 🔧 حل الفهرس مرة لكل تشغيل (‏3.6.0→Versioned→ثابت كاحتياط) |
| شكل PEP 792 | جلب حي: requests + 4 حزم مؤرشفة فعلياً + نص الـ PEP | المفتاح `status` (نص الـ PEP نفسه متناقض داخلياً مع مثاله؛ التطبيق الحي والمواصفة الحية = `status`)؛ الحالات المطبقة: active/archived/quarantined فقط؛ الغياب ⇒ active | ✅ (كود الخطة استخدم `status` أصلاً) + H012 للأرشفة |
| pypistats | 3 نداءات مهذبة | ‏200 JSON سليم بلا رؤوس rate-limit؛ ‏404 نصي غير JSON مؤكد؛ عدم القدرة على إعادة إثبات عتبة 429 دون قصف (لم نقصف) | ✅ الإبقاء على الخنق الوقائي؛ 404 ≠ عدم وجود الحزمة |
| npm alias و`#imports` | وثائق npm/nodejs الرسمية حرفياً | ‏`"foo": "npm:bar@^1"` ⇒ فحص السجل على bar؛ مفاتيح `#` ليست أسماء سجل أبداً (وأهدافها تبعيات عادية تُغطى بالفحص المعتاد) | 🔧 حقل `registry_name` في DeclaredDep + اعتبار `#x` داخلياً |

## المحور 7 — اكتمال التحليل وإظهار الفشل

| الحالة المختبرة | سلوك الخطة الأصلية | الحكم |
|---|---|---|
| manifest تالف (tomllib/json/ET error) | يُعاد `[]` صامتاً ويبدو المشروع "بلا تبعيات" | 🔧 قناة Diagnostics: `manifest_errors` تظهر في report.json + limitations |
| قاعدة ترمي exception | `try/except: continue` صامت في patterns | 🔧 تسجيل `rule_errors` (قاعدة/ملف/خطأ) بدل الإخفاء |
| ملف متجاوز للحجم/غير مقروء/symlink | تخطٍّ صامت في الـ walker | 🔧 عدّ `skipped_files` بأسبابها |
| AST به parse errors | يُحلَّل جزئياً بصمت | 🔧 عدّ `parse_error_files` (tree.root_node.has_error) |
| فشل/انتهاء مهلة semgrep | `[]` صامت | 🔧 `semgrep_status` صريح في engines |
| XML عدائي | تجربة `xml_stress.py`: قنبلة كيانات → ParseError "amplification factor breached" (حماية **BLAP خاصة بهذا البناء** expat 2.6.2 — ليست حماية موارد عامة)؛ عمق 50k: 0.01s؛ ‏2.7MB/100k عقدة: 0.07s؛ المشوّه يُلتقط | ✅ الإبقاء على سقف 2MB للـ manifests كخط الدفاع الفعلي + إظهار ParseError في diagnostics |
| ما هو syntactic وما يحتاج data-flow | جرد: SQL (P004/P005)، R005، D002، J002، N003، heuristic الـ early-return = تقريبية؛ الاستيرادات وفحوص الوجود = وقائع | 🔧 سمة `precision: exact|heuristic` لكل قاعدة تظهر في التقرير؛ **لا** data-flow جديد في الـ MVP (dangerouslySetInnerHTML يبقى syntactic موثقاً) |

## المحور 8 — Semgrep/OpenGrep

| الفرضية | الدليل | الحكم |
|---|---|---|
| النص الحرفي للترخيص | (المحور 1) — internal-use فقط + لا توزيع/لا خدمة، non-sublicensable، **لا بند منافسة**؛ يقيّد "من يستخدم القواعد" | ✅ القرار قائم: لا تضمين ولا جلب افتراضي؛ `--semgrep-config p/x` فعل المستخدم المرخَّص له |
| dedupe عند نتيجتين مختلفتين بنفس السطر | تحليل منطق الخطة: كان يُسقط نتيجة semgrep المختلفة كلياً إن صادف سطراً فيه نتيجة مدمجة → FN | 🔧 إلغاء الإسقاط عبر المحركات؛ إزالة التكرار الحرفي فقط (نفس rule_id/file/line)، والمحركان متكاملان بالتصميم |
| إسناد النتائج في monorepo بمسارات متطابقة | `('api-old/src/index.ts').startswith('api')` → True و`endswith('/src/index.ts')` → True (تصادمان مثبتان) | 🔧 خريطة ملكية: مسار موحّد (casefold على ويندوز) → مطابقة **ملف كامل** من قوائم ملفات المشاريع، وfallback لأعمق جذر عبر `PurePosixPath.is_relative_to` |

## المحور 9 — أمن المستودعات غير الموثوقة

| ناقل | الوضع | الحكم |
|---|---|---|
| install/restore/build scripts | لا نشغّل أياً منها (قراءة+parse فقط)؛ semgrep يقرأ ولا ينفّذ؛ ESLint غير مستخدم في الأداة | ✅ |
| git hooks/submodules | hooks لا تُستنسخ إلى `.git/hooks`؛ لا `--recurse-submodules` | ✅ |
| Git LFS/filters | smudge قد يجلب ملفات ضخمة | 🔧 `GIT_LFS_SKIP_SMUDGE=1` |
| symlinks | ويندوز ينشئها نصية عادة؛ على أنظمة أخرى قد تشير خارج المستودع فتُقرأ في التقرير | 🔧 `-c core.symlinks=false` عند الاستنساخ + تخطي `is_symlink()` في الـ walker |
| حجم/مهلة الاستنساخ والعمليات | غير محدودة سابقاً | 🔧 مهلة clone ‏300s؛ semgrep ‏600s (موجودة)؛ سقف ملف 1.5MB (موجود) + سقف manifest ‏2MB |
| حدود العزل على ويندوز | لا sandbox حقيقي متاح؛ الضمانة = "لا تنفيذ لمحتوى المستودع" + المهل والسقوف | ✅ موثقة صراحة في README/limitations |

## المحور 10 — معنى الدرجة (سيناريوهات محسوبة)

| سيناريو | بالمعادلة الأصلية | المشكلة |
|---|---|---|
| python نظيف (2 ملف) + TS كارثي (200 ملف، 10 🔴) | الإجمالي ≈ 1 | سليم |
| مشروع سام صغير (3 ملفات، score 0) + كبير نظيف (300 ملف، 100) | الإجمالي ≈ **99** | **يخفي الحرج** |
| ‏offline مع 30 تبعية معلنة | ‏30×H003 زرقاء → score 70 | **يخلط الثقة بالخطر**: لا خطر مثبت أصلاً |

**الحكم 🔧:** فصل صريح — `risk_score` لكل لغة = `max(0, 100 − 15🔴 − 5🟡)` (**الأزرق خارج الخطر**) · `analysis_confidence` ‏0–100 من diagnostics (خصومات موثقة: offline −40، H004/H010… إلخ) · العنوان يعرض دائماً: أدنى لغة + عدد 🔴 إلى جانب المتوسط المرجّح — **المتوسط لا يُسمح له بإخفاء أحمر**.

## المحور 11 — اكتمال parsing

| العنصر | الوضع الأصلي | الحكم |
|---|---|---|
| Pipfile | يُكتشف ولا يُقرأ → عاصفة FP "غير معلن" | 🔧 قراءة `[packages]`/`[dev-packages]` (tomllib، ‏5 أسطر) |
| npm aliases (`npm:`) | فحص السجل على الاسم المستعار (خطأ) | 🔧 `registry_name` |
| `imports` (`#x`) | كانت ستُفحص كسجل | 🔧 داخلية |
| tsconfig `extends` | ‏paths في الأساس تضيع | 🔧 اتباع extends مستوى واحد لملف محلي فقط؛ أبعد من ذلك ⛔ (يوثق) |
| manifests تالفة | صمت | 🔧 diagnostics (محور 7) |

## المحور 12 — بوابات المراحل

**التقييم أولاً:** الموجود فعلاً في الخطة: مخرجات لكل مرحلة + "ما سيُعرض" + اختبارات لكل مهمة (تشمل حالات سلبية حقيقية: 404، تعابير نظيفة، placeholder filter...). **الغائب المثبت:** معايير قبول مسماة، وحالات مانعة من الانتقال، وسجل قرارات مؤجلة. **الحكم 🔧:** إضافة سطر Gate لكل نقطة توقف (معايير القبول = قائمة الاختبارات الخضراء + عرض سلبي واحد على الأقل؛ blockers مسماة مثل فشل عجلات tree-sitter على 3.11 في CP-2؛ وبند "قرارات مؤجلة" يُعرض عليك) — دون إعادة اختراع الموجود.

---

# قائمة الفرضيات المرفوضة (حاولنا إثباتها ففشلت)

1. **"قائمة NODE_BUILTINS تحتوي `sys` خطأً"** — مرفوضة: node 24 يؤكدها builtin فعلياً (`module.isBuiltin('sys') === true`، تحذير DEP0025 فقط). بقيت القائمة؛ الحذف اقتصر على `test`/`sea`/`sqlite` المدحوضة بدليل مستقل.
2. **"أسماء عقد tree-sitter في خوارزميات React ستحتاج تصحيحاً عند التنفيذ"** — مرفوضة: التنفيذ الحرفي على tree-sitter 0.26.0 عمل دون أي تعديل (صفر mismatches في 18 ملفاً + nextdemo).
3. **"ترخيص قواعد semgrep يمنع منتجاً منافساً"** (من بحثنا الأول) — مرفوضة نصياً: `grep -ci compet` = 0 على النص الكامل؛ القيود الحقيقية أضيق وأدق.
4. **"يمكن الاستدلال على أول نشر في Maven من versions[0]"** — مرفوضة بثلاث حالات (log4j backports، spring 6.2.19، jackson 2.18.4) بتواريخ Last-Modified موثقة.
5. **"`p/react` وقواعد السجل الجاهزة تغطي احتياج hooks"** (فرضية "استخدم الجاهز") — بقيت مرفوضة بعد إعادة الفحص: p/nextjs فارغ وp/react أربع قواعد أمنية فقط ولا شيء لـ hooks — بناء قواعدنا هو الخيار الوحيد.
6. **"إصلاح إسناد semgrep بالبادئة النصية يكفي"** — مرفوضة قبل التبني: `startswith('api')` يبتلع `api-old` (مثبت) — اعتُمدت خريطة الملكية بدلاً منها.
7. **"opengrep-rules مصدر قواعد حي قابل للتبني"** — مرفوضة: مؤرشف منذ 2025-11.
8. **"استخدام `sys.stdlib_module_names` وقت التشغيل حل كافٍ لبايثون"** — مرفوضة بالاتجاهين، مع دليل صادم (حزمة PyPI باسم distutils تعيد 200).
9. **"حماية expat تكفي لملفات XML العدائية"** — مرفوضة بصياغتها العامة: المثبت هو حدود BLAP في هذا البناء تحديداً؛ سقف الحجم يبقى ضرورياً (الملف الكبير المشروع يمر بلا حماية).
10. **"blanket `javax.*` تحفظ الدقة"** — مرفوضة: تحجب 18 عائلة خارجية حقيقية وتعفي كل `javax.*` مهلوس من الكشف.

# الجولة الثانية — مراجعة نتائج المراجعة (2026-07-17، نفس اليوم)

11 فرضية من الدرجة الثانية على أحكام الجولة الأولى؛ منهج الدحض نفسه. ملفات التجارب الجديدة: `r003v2_test.py` (على قواعد TSX الحقيقية)، قياس tracemalloc، فحص `--metrics=off` على الثنائيين الفعليين في الـ scratchpad.

| # | الفرضية | الاختبار/الدليل | النتيجة | الحكم وأثره على الخطة |
|---|---|---|---|---|
| 1 | حياد النواة يحتاج أكثر من إزالة استيراد واحد؛ وقد يكون تمرير Rules جاهزة أبسط من SyntaxProfile | مقارنة التصميمين + سياسة المفاتيح المكررة | تمرير Rules جاهزة للقواعد **الخاصة** قائم أصلاً (language_rules/project_rules)؛ نقل EmptyCatch/SqlStringBuild إلى المحوّلات يكرر منطقهما ×4 — SyntaxProfile يبقي المنطق المشترك مشتركاً والمعرفة عند مالكها. السجل: append-only + idempotent (التسجيل المكرر no-op مُختبَر) + `reset_registry()` للاختبارات + اختبار حياد يفشل عند أي اسم لغة في rules_common | ✅ تثبيت تصميم v2 مع ضوابط السجل الجديدة |
| 2 | ‏fallback البادئة غير مأمون (api-old، تداخل، حالة أحرف، ملفات بلا مالك، لغتان بجذر واحد) | 🔬 tuples: ‏api/api-old آمنة؛ ‏casefold لازم على ويندوز (مثبت)؛ منطق v2 راجَعناه | خريطة الملكية بمطابقة ملف كامل هي الأساس (كما اقترحت)؛ الإصلاحات: casefold للمكوّنات في proj_meta، **سلة repository-level** للنتائج بلا مالك (YAML/Dockerfile) بدل إسقاطها، رفض مسارات `..`، والجذر "." يعمل fallback عاماً؛ لغتان بجذر واحد: exact-map يفصل بالملفات المملوكة فعلاً | 🔧 مطبق في T23 |
| 3 | ‏removed-table وحده ناقص: الاتجاه الثالث (وحدة أُضيفت بعد نسخة المشروع) + الـ backports | تحليل + نموذج فترات توافر مصغّر | صحيح: أضيف `ADDED_STDLIB` (zoneinfo/graphlib/tomllib بنسخ التقديم وأسماء backports) و`REMOVED_BACKPORTS` (distutils↔setuptools)؛ ‏P008 يعمل بالاتجاهين، يصمت عند إعلان الـ backport، وأزرق دائماً، ولا يصدر بلا requires-python | 🔧 مطبق في T7 + عنوان P008 محدث |
| 4 | حماية expat خاصة بالبناء؛ والقياس يجب أن يشمل الذاكرة والعقد | 🔬 tracemalloc: ‏2.7MB → **38MB ذروة (×14)**، عمق 50k → 48MB | مسجّل نصاً أن BLAP مثبتة لبناء 2.6.2 المحلي فقط؛ المقارنة حُسمت: **defusedxml + سقف 2MB معاً** (الأول يحيّد الكيانات على كل البناءات، الثاني يضبط الموارد المقاسة)، وكل ParseError/تخطٍّ في diagnostics | 🔧 defusedxml أضيف للتبعيات والقيود |
| 5 | فصل التراخيص الأربعة نصاً/تحليلاً + لا "مسموح بإطلاق" + لا remote افتراضياً + provenance | 🔬 ‏`--metrics=off` على semgrep الفعلي: قُبل وعمل (نتيجة=1)؛ opengrep بلا telemetry | جدول رباعي (نص حرفي | تحليل) في RESEARCH؛ صياغة p/... أصبحت "مسؤولية المستخدم" لا "مسموح"؛ الافتراضي محلي بالكامل (config ملفّي وحيد) + ‏metrics=off لـ semgrep حصراً؛ ترويسة provenance/MIT في auditor-extra.yml تصرّح بالأصالة | 🔧 مطبق في T21 + RESEARCH §4 |
| 6 | شرط ≤10 لا يجعل الترتيب زمنياً؛ وLast-Modified ليس معيارياً؛ و"frozen" أقوى من الدليل | إعادة فحص المنطق | صحيح بالكامل: ‏HEAD على **جميع** POMs للحزم الوليدة وأخذ الأقدم (اختبار يزرع الترتيب المعاكس عمداً)؛ الكبيرة created=unknown فلا H005/H006؛ ‏Last-Modified موثق كـ heuristic؛ الصياغة أصبحت "شديد التقادم/غير صالح للفحص" بدل "متجمد" | 🔧 مطبق في T15 + RESEARCH §3 |
| 7 | حل كل موارد NuGet من الفهرس + تسامح status/state + H001 كواقعة زمنية + عدم الاتصال بالسجل الخاص + redaction | مراجعة الوثائق + منطق v2 | ‏NuGetClient يحل flat/registration/search الثلاثة بأعلى نسخة متوافقة مع fallback ظاهر (`degraded` → limitations)؛ ‏PyPI يقرأ `status` أو `state`؛ ‏H001: "لم توجد في السجل المستعلَم وقت الفحص" + الأسباب المحتملة؛ سياسة معلنة: **لا اتصال بالسجلات الخاصة أبداً** والعام ليس مصدر حقيقة لحزمها (H010)؛ ‏redaction لبيانات الاعتماد في snippets مع اختبار | 🔧 مطبق في T17/T5/T8/T22/T23 |
| 8 | نمذجة alias بحقلين + ‏#imports وself-references داخلية | مراجعة v2 | v2 يطابق المطلوب أصلاً: ‏name (المحلي) + ‏registry_name (الفحص) واختبار يؤكد الاتجاهين؛ ‏`#x` داخلية؛ يضاف self-reference (اسم الحزمة نفسها من package.json) كداخلي — ثغرة صغيرة صحيحة | ✅ + 🔧 إضافة self-name في prepare |
| 9 | عرض المقاييس خاطئ + تصنيف الانحرافات + مخاطر R003/early-return + ‏use() | 🔬 ‏r003v2_test: **بلا استثناء الأغلفة: 3 FP مؤكدة (memo/forwardRef/React.memo)؛ معه 7/7**؛ ‏early-return: حالة if-تحوي-callback-return ‏FP مؤكدة والحل fn-boundary ‏4/4 | المقاييس صُوّبت: accuracy ‏66.7%، ‏P=R=F1 ‏72.7%؛ التصنيف الثلاثي مطبق (4 عيوب تنفيذ أُصلحت / انحرافان مقصودان spec-divergence / try-catch أيضاً reference-tool-gap)؛ استثناء الأغلفة و`_walk_no_functions` دخلا الخطة باختباراتهما؛ إعادة الـ corpus بوابة CP-4؛ ‏React `use()`: خارج النمط `^use[A-Z]` أصلاً فلا FP على شرطيته المسموحة — تغطيته خارج النطاق موثقة | 🔧 عيبان حقيقيان أمسكتهما هذه الجولة قبل التنفيذ |
| 10 | ‏import graph غير متوفر حالياً (النسبية تُسقط والـ aliases لا تُحل لملفات) + دلالات وراثة client + الكلفة | مراجعة كود الاستخراج | صحيح تماماً — كتلة N006 أعيدت كتابتها بصدق: استخراج حواف خاص بها، قواعد الحل (امتدادات/index/paths/re-exports/دورات/dynamic)، ‏traversal بحالة server/client مع **اختبار الوراثة داخل app/** (ضد قناع شرط التجاهل)، الكلفة ~150 سطراً، وتظل **قراراً معمارياً منفصلاً معلقاً على اعتمادك** | 🔧 الكتلة محدثة، القرار لك |
| 11 | التجميع النهائي بالحالات الخمس | هذه الوثيقة + RESEARCH + الخطة | مطبق أدناه | ✅ |

**إضافات قائمة المرفوضات (جولة ثانية):**

11. **"R003-الأعمق آمن بلا استثناء أغلفة"** — مرفوضة تجريبياً (3 FP على memo/forwardRef/React.memo) قبل أن تصل للتنفيذ.
12. **"مسح الأشقاء عن return آمن كما كُتب"** — مرفوضة جزئياً: حالة `if (x) { run(() => { return 1; }) }` ‏FP مؤكدة؛ الحل حدود الدوال.
13. **"عدد إصدارات ≤10 يجعل versions[0] صالحاً"** — مرفوضة: القلة تصغّر الخطأ ولا تلغيه؛ الحل min على كل POMs.
14. **"مقارنة مكونات المسار الخام تكفي"** — مرفوضة على ويندوز (حالة الأحرف؛ مثبت بالمثال).
15. **"semgrep لا يتصل خارجياً في وضعنا الافتراضي"** — مرفوضة جزئياً: الـ config محلي فعلاً، لكن الـ metrics تحتاج `--metrics=off` صراحة (اختبرناه).
16. **"agreement وprecision رقم واحد 72.7%"** — مرفوضة حسابياً: ‏accuracy ‏66.7% وP=R=F1 ‏72.7% مقياسان مختلفان.

**الحالات الخمس النهائية (مطلب التجميع):**
- **قرارات أصلية بقيت:** ‏tree-sitter 0.26 بالحزم الفردية · ‏repo1 للوجود · بنية core/adapters/registries/report · قواعد hooks داخلية · ‏semgrep اختياري بقواعدنا فقط · ‏lizard للتعقيد · صيغ التقرير والكاش · نموذج H-rules الأساسي · ‏SyntaxProfile/GrammarRegistry (صمدت أمام بديل التمرير الكامل).
- **قرارات تغيّرت (بالدليل):** ملكية semgrep بخريطة ملفات casefolded + سلة repository · ‏dedupe التطابق الحرفي فقط · ‏Maven ‏min-كل-POMs · ‏NuGet حل الموارد الثلاثة · ‏PyPI ‏status/state · فصل risk/confidence مع سطر أدنى-لغة · ‏stdlib بفترات التوافر والـ backports · ‏javax-21/System-TFM/builtins-3 · ‏R003 بالأغلفة وearly-return بحدود الدوال · ‏defusedxml+سقف · ‏redaction · ‏H010/H012/P008.
- **الفرضيات المرفوضة:** القائمة أعلاه (16 بنداً عبر الجولتين).
- **heuristics وحدود الثقة (موسومة `precision="heuristic"` في التقارير):** ‏SQL ‏P004/P005 · ‏R001-early-return · ‏R005 · ‏J002 · ‏D002 · ‏N003 (وN006 إن اعتُمدت) · خرائط Java/.NET · ‏Maven created عبر Last-Modified · كشف السجلات الخاصة (القنوات غير الملفّية غير قابلة للكشف).
- **خارج الـ MVP:** تشابه الأسماء typosquat-similarity (يحتاج قوائم شعبية مدمجة) · مطابقة dataset الهلوسات التاريخية · ‏data-flow/taint الحقيقي · ‏deps.dev كعميل بديل · حل tsconfig extends المتسلسل >1 · تغطية React ‏`use()` · ‏N006 معلقة على قرار صريح.

# الجولة الثالثة — فرضيات ما بعد التجميع (2026-07-17)

9 فرضيات على اتساق «الخطة كنظام» حتى report.json. **8 تأكدت كفجوات حقيقية وأُصلحت في كتل التنفيذ نفسها؛ واحدة تأكدت جزئياً.** الأدلة الجديدة دائمة في `evidence/` (44 ملفاً + README بأوامر إعادة التشغيل).

| # | الفرضية | الاختبار/الدليل | الحكم | الإصلاح واختبارات الـ regression |
|---|---|---|---|---|
| 1 | «لا فشل صامت» غير مكتمل: read_text_capped بلا مستخدم، وparse_dependencies/project_files بلا diag | تتبع سلسلة الاستدعاء في كتل الخطة | **تأكدت** | عقد جديد: `parse_dependencies(root, diag)` إلزامي التوثيق في الواجهة + helpers أساس `_read`/`_manifest_error` (يعدّان `manifest_reads`) تستخدمها كل قراءات manifests في المحوّلات الأربعة؛ `project_files(..., diag)`؛ regression شامل `test_cli_surfaces_manifest_corruption_end_to_end` (pyproject تالف → diagnostics في report.json → verdict≠pass → ‏exit 1 مع --strict) |
| 2 | ‏defusedxml في القيود فقط لا في كتل التنفيذ | grep على كتل T15/T16/T18 | **تأكدت** | الاستيرادات والـ catch في كتل Maven/Java/.NET نفسها (`defusedxml.ElementTree` + `DefusedXmlException`) وكل XML عبر `self._read` المسقّف؛ ‏Maven يطبّقها حتى على استجابات repo1 (مدخل خارجي أيضاً) |
| 3 | ‏run_semgrep يبتلع الفشل ولا يفحص returncode | 🔬 أكواد الخروج الفعلية: سليم=0، ‏config مفقود/تالف=**7** | **تأكدت** | التوقيع `-> (findings, status)` بحالات success/failed/timed_out/invalid_output + فحص returncode∉(0,1)؛ ‏CLI يسجل `الإصدار: الحالة`؛ الثقة تتأثر؛ ‏`test_run_semgrep_failure_states_are_distinct` يغطي الأربع |
| 4 | ‏precision لا يصل للتقرير | تتبع Finding/asdict | **تأكدت** | حقل `Finding.precision` + ختمه في كل المولدات (وقواعد الربط عبر `adapter.mapping_precision`: ‏java/dotnet = heuristic) + علامة `*` وليجند في Markdown + assertions في اختبار التقرير |
| 5 | الدرجات كعقد منتج: ‏‎-1*blue بقايا، «risk» تسمية معكوسة، الثقة تتجاهل manifest/rule errors، الخصومات مطلقة | حساب السيناريوهات | **تأكدت كلها** | التسمية `code_health` (أعلى=أسلم، موسومة experimental)؛ نص Markdown صُحح؛ ‏confidence أصبح **coverage-v1** نِسَبياً (اختبار 5-من-5 مقابل 5-من-50000 يعطي 0 مقابل 100) ويخصم manifest/rule/parse؛ **verdict آلي pass/review/block** ‏+ `--strict` (الفحص الناقص لا يخرج 0) مع `test_verdict_contract` |
| 6 | ‏floor-only يفوّت `>=3.11` + ‏distutils | 🔬 نموذج النطاقات: 6 حالات، القديم أعاد False على المثال المضاد | **تأكدت** | `_requires_python_range` (floor+ceiling، يدعم ‎>=,>,<,<=,==,~=) + ‏predicates عبور/احتواء/انتهاء بالاتجاهين + 6 اختبارات (منها المثال المضاد نصاً وbackport المُعلن والصمت عند غياب النطاق) |
| 7 | ‏casefold عالمي خاطئ على أنظمة حساسة، وtuple الجذر الفارغة تبتلع Dockerfile | 🔬 مجس ويندوز + تحليل fallback | **تأكدت** | وحدة `core/ownership.py` نقية: مجس نظام الملفات الفعلي (swapcase+samefile)، تطبيع مشروط، ‏fallback مقيد بـ **suffix ∈ globs المشروع** (غير المصدر → repository bucket حتى مع مشروع جذري)، حارس `..`؛ ‏6 اختبارات تغطي حالاتك الأربع |
| 8 | ‏N006: نقاط الدخول والوراثة الثنائية وtype-imports | مراجعة التصميم | **تأكدت — واعتُمدت مبدئياً** | التصميم v3 في الخطة: ‏entries بأسماء ملفات Next الاصطلاحية فقط؛ ‏visited بـ `(file, state)` **وكلا السياقين يُحللان** (مخالفة مسار server قائمة ولو وصله مسار client)؛ الوراثة بالاتجاهين (N002/N004/N5 في client الموروث)؛ استبعاد import/export type؛ اختبارات orphan/دورة/ملف مشترك/وراثة داخل app |
| 9 | بقايا صياغة + أدلة متطايرة + أرقام corpus القديمة ليست دليلاً على الخوارزميات المعدلة | grep + جرد | **تأكدت** (الشطر الأخير جزئياً: الأرقام تبقى دليلاً صالحاً على نسخة v1 المقيسة تحديداً) | حُذف «forbids competing tools» من القيود؛ «الخيار الوحيد» صيغ بدقة (ESLint خيار مرفوض التشغيل/التغليف)؛ ‏`evidence/` دائم داخل المشروع بأوامر إعادة التشغيل؛ إعادة قياس الـ corpus بعد التنفيذ بوابة CP-4 نصاً |

## diff القرارات (جولة 3)

| قبل | بعد |
|---|---|
| ‏diag اختياري عملياً وغير ممرر للـ manifests | عقد إلزامي: كل قراءة manifest عبر `_read` المسقّف وكل فشل في diagnostics |
| ‏run_semgrep → [] عند أي فشل | ‏(findings, status) رباعي الحالات + فحص returncode (المقيس: 7 للـ config) |
| ‏risk_score / خصومات ثقة مطلقة | ‏code_health (أعلى=أسلم) + ‏coverage-v1 نسبي + ‏verdict pass/review/block + ‏--strict |
| ‏P008 بأرضية فقط | نطاق كامل floor+ceiling بثلاثة أوضاع لكل اتجاه |
| ‏casefold دائماً + fallback جذري عام | مجس نظام ملفات فعلي + fallback مقيد بالامتدادات + repo bucket |
| ‏N006 معلقة | معتمدة مبدئياً بتصميم v3 (dual-state، وراثة ثنائية، ‏entries اصطلاحية، بلا type-edges) — التنفيذ بعد إقرار نهائي في CP-4 |
| أدلة في TEMP | ‏`evidence/` داخل المستودع |

# الجولة الرابعة — إغلاق التناقضات التنفيذية (2026-07-17)

9 فرضيات محدودة النطاق؛ **كلها تأكدت** (سبع بأدلة تجريبية مباشرة، واثنتان بالتتبع على كتل الكود). لا توسيع معماري — تصحيح عقود فقط.

| # | الفرضية | الاختبار المضاد ونتيجته | الإصلاح في كتل الكود + اختبار الـ regression |
|---|---|---|---|
| 1 | ‏precision لا يُمرر في المولدات وJ002/D002/D003 بلا سمة | تتبع: المولدات الثلاثة كانت تنشئ Finding بلا precision (يرتد إلى exact) | تمرير `precision=rule.precision` في react/java/dotnet `_finding` + معامل في `_mk_finding` يمرره SqlStringBuild + سمات heuristic على J002/D002/D003/N003؛ ‏regression: `test_precision_reaches_findings_not_just_rules` + تأكيدات JSON (`P005→heuristic`, `H001→exact`) وMarkdown (`P005*` موجودة، `P001*` غائبة) |
| 2 | ‏coverage-v1 يمنح PASS للانهيار | 🔬 محسوبة: ‏100/100 ‏parse errors → ‏70=PASS؛ كل القواعد فاشلة → ‏80=PASS | ‏coverage-v2: عدادات `rule_attempted/rule_failures`، ‏rule_health وparse_factor نسبيان **بلا سقوف**؛ ‏verdict: أي فشل قاعدة يمنع pass، والانهيار الكلي (كل القواعد أو أرضية الثقة) = **block**؛ ‏regression: `test_fourth_round_counterexamples_are_closed` (كلا السيناريوهين → 0 → block) |
| 3 | ‏manifest_reads يعد القراءات لا الملفات + انفصال diag عند إعادة parse | تتبع: ‏pyproject يُقرأ 3 مرات (deps/range/project_rules) وكانت project_rules تعيد النداء بلا diag فتصفّره | ‏`manifest_files` فريدة المسارات + ‏`_manifest_error` فريد لكل ملف + كاش `_last_declared` يمنع إعادة الـ parse؛ ‏regression: `test_corrupt_manifest_counted_once_across_multiple_reads` + `test_manifest_cov_counts_unique_files_not_reads` |
| 4 | محلل regex لا يحفظ PEP 440 | 🔬 ‏4/4 دحض: ‏`~=3.11` يسمح حتى <4.0 (محللنا قفله عند 3.11)؛ ‏`==3.11.*` بلا سقف؛ ‏`<3.12.1` يسمح بـ 3.12؛ ‏`!=3.12.*` مُتجاهل | استبدال كامل بـ `packaging.SpecifierSet` عبر `_allowed_minors` والحكم على مجموعة النسخ المسموحة؛ تبعية `packaging>=24`؛ ‏regression: `test_p008_pep440_semantics_not_hand_regex` (الحالات الأربع) |
| 5 | اعتماد N006 الآن وإزالة PENDING | — (قرارك) | ‏`next_graph.py` **منفذة بالكامل** في T14 (‏entries اصطلاحية موثقة المدعوم/المستبعد، ‏dual-state لا يفوز فيها client، وراثة ثنائية N002/N004/N005، استبعاد type-edges، دورات/orphans في notes) + تكامل prepare/language_rules/project_rules أحادي المصدر + 6 اختبارات؛ أزيلت كل مواضع PENDING (‏catalog/CP-4/Revision Log) |
| 6 | ‏results+errors معاً في semgrep | 🔬 محاولة توليدها حياً: الملف المكسور **تُخطي بصمت** (‏rc=0، ‏errors=0) — وهذا يثبت جوهر الفرضية (الكود الصالح ≠ اكتمال)؛ المخطط الرسمي يضم `errors` | حالة `partial (N file errors)` عند وجودها، ‏sg_factor ‏0.97، والنجاح لا يُدّعى؛ ‏regression: `test_run_semgrep_results_and_errors_together_is_partial` |
| 7 | ‏_bulk_lookup ينهار باستثناء واحد | تتبع: ‏pool.map يرفع الاستثناء ويقتل التدقيق كاملاً | غلاف `_safe` لكل اسم → `PackageInfo(error="lookup crashed: …")` → ‏H004؛ ‏regression: `test_lookup_exception_is_isolated_per_name` (‏RuntimeError على اسم واحد، البقية تمر) |
| 8 | الأدلة غير قابلة للتشغيل من checkout نظيف | فحص الملفات: مسار TEMP مثبت في r003v2؛ ‏xml_stress بلا قياس ذاكرة | ‏r003v2 ذاتي الاكتفاء (تعليمات venv في الترويسة)؛ ‏xml_stress يقيس tracemalloc والعقد فعلياً؛ ‏README صُحح (أوامر بمجلد عمل صريح) |
| 9 | عقود متناقضة متبقية (T21 نصياً list[Finding]/[]…) | grep موجه + **workflow تحقق مستقل** (12 وكيلاً: 4 أبعاد مسح + دحض عدائي لكل بلاغ) | نص T21 صُحح؛ ثم **أكد الفحص المستقل 5 تناقضات حية أفلتت من المسح اليدوي وأُصلحت كلها**: عقدا Interfaces لـ collect_source_files/project_files وaudit_hallucinations بلا diag (كان المنفذ سيصيب TypeError عند سلك T23)؛ **`mapping_precision = "heuristic"` كان ادعاءً نثرياً بلا سطر كود في صنفي Java/.NET** (نتائج الربط كانت ستُختم exact بصمت واختبارات خضراء — أضيفت السمتان + اختبارا regression على precision في E2E اللغتين)؛ وشرطية "if N006 rejected" قديمة في بوابة CP-8. أوامر الـ grep المرجعية في نهاية الوثيقة، ونتيجتها الفعلية: صفر عقود قديمة حية |

**أوامر إثبات إزالة العقود القديمة (قابلة لإعادة التشغيل على ملف الخطة):**
```
grep -n "manifest_reads\|coverage-v1\|_requires_python_floor\|1\*🔵" plan.md   # 0 نتائج حية
grep -n "PENDING\|approve/reject" plan.md                                     # 0 خارج سجلّي المراجعة
grep -n "returns \`\[\]\` on any" plan.md                                     # 0
grep -n "import xml.etree" plan.md                                            # 0
grep -cn "run_semgrep" plan.md   # كل المواضع على العقد tuple[list, str]
```

# الجولة الخامسة — تصحيحات تنفيذية دقيقة (2026-07-17)

ثماني فرضيات مركزة؛ **كلها تأكدت** (خمس بأدلة تجريبية مباشرة، وثلاث بالتتبع على كتل الكود).

| # | الفرضية | الاختبار المضاد ونتيجته الفعلية | الإصلاح + regression |
|---|---|---|---|
| 1 | ‏P008 يختبر `Version("3.12")` فقط فيسقط النطاقات ذات الـ patch | 🔬 `contains(Version("3.12"))=False` للمواصفات الثلاث `==3.12.1`/`~=3.12.1`/`>=3.12.1,<3.13` رغم أن أي patch داخل 3.12 مسموح → allowed=[] → لا نتيجة | `_allowed_minors` صار **patch-aware** (يفحص ‏3.m.0..3.m.25 مع prereleases=True): minor مسموح إن سمح أي patch منه؛ ‏regression: `test_p008_patch_level_specifiers_reach_the_minor` (الثلاث → P008 لـ distutils) |
| 2 | ‏N006 لا يفعّل src/app، وalias يحوّل إلى components/ لا src/components/ | تتبع: كشف الدخول كان `parts[0]=="app"` فقط؛ و`_resolve` يجرّد البادئة بلا هدف | ‏`_under_app`/`_is_entry` تدعم src/app؛ خريطة `_alias_map` كاملة (pattern→target+baseUrl) و`_resolve` يعيد الإرساء على الهدف؛ ‏regression: `test_src_app_layout_and_alias_target_resolution` (يحل إلى src/components/Hooky) |
| 3 | orphan تحت app بـ hook يختفي (N003 محذوف عالمياً والرسم يستبعده) | تتبع: الرسم كان يذكر orphans ويستبعدها | الرسم صار **يحلل orphans** كجذور server standalone (تمريرة `_bfs` ثانية) — كل ملفات app مغطاة فحذف N003 آمن؛ ‏regression: `test_orphan_with_hook_is_flagged_not_dropped` |
| 4 | ‏window.location مستبعد لأن parent=member_expression | تتبع: الشرط `parent != member_expression` يستبعد جوهر استخدام window | ‏`_is_global_use`: يعلّم البراوزر-غلوبال كـ **object** لوصول عضو (window.location) أو standalone، ويستثني الروابط المحلية؛ ‏regression: `test_window_location_in_server_path_is_flagged`؛ + أضيفت conventions ‏global-not-found/forbidden/unauthorized ووُثّق المستبعد (middleware/instrumentation/metadata) |
| 5 | ‏data["errors"] لا يكفي (rc=0/errors=0 مع تخطي صامت) | 🔬 المحاولة الحية: الملف المكسور ظهر في `paths.scanned` (‏errors=0) — إثبات أن errors وحده لا يكشف الفجوة؛ و`paths.scanned` موجود ويعدّ | مصالحة `paths.scanned` مع `expected_paths` (+`errors`+`paths.skipped`): أي فجوة → partial؛ العميل يمرر مجموعة ملفات المصدر المتوقعة؛ ‏regression: `test_run_semgrep_unscanned_expected_file_is_partial` + `..._full_coverage_is_success`؛ **verdict**: محرك اختياري بدأ ثم partial/failed/timed_out/invalid_output → REVIEW على الأقل (partial=97 وfailed=95 لم يعودا يمرّان PASS) |
| 6 | استثناء project_rules يزيد rule_errors دون rule_failures → ثقة 100/PASS | تتبع | ‏run_pattern_engine يعدّ complexity وproject_rules في `rule_attempted/rule_failures`، وcomplexity_findings تسجّل فشل كل ملف في diagnostics؛ ‏regression: `test_project_rules_failure_counts_and_forbids_pass` (ثقة<100، verdict≠pass) |
| 7 | ‏`_manifest_error` بـ path.name يدمج ملفين في monorepo | تتبع: ملفا pyproject في جذرين → خطأ واحد | المفتاح صار المسار الكامل `path.as_posix()`؛ ‏regression: `test_monorepo_two_corrupt_manifests_give_zero_coverage` (خطآن، ملفان، تغطية 0) |
| 8 | بقايا قابلة للقياس | 🔬 إعادة قياس: deep=**14MB** لا 48MB؛ wide=38MB×14 (قيد الخطة يستشهد بـ wive الصحيح) | ‏README صُحح (deep 14MB)؛ ‏xml_stress يقيس tracemalloc؛ ‏r003v2 بلا مسار TEMP؛ ‏eslint-results.json مساراته نسبية (`corpus/…`)؛ CP-7 موحّد على 48 |

**diff القرارات (جولة 5):** ‏P008 patch-aware؛ ‏N006 يدعم src/app + alias-target + orphan-analysis + window.location + conventions؛ ‏semgrep completeness عبر paths.scanned؛ ‏verdict يحاسب المحرك الاختياري المنهار؛ ‏complexity/project_rules في عدادات الفشل؛ ‏manifest بالمسار الكامل؛ الأدلة نظيفة قابلة لإعادة التشغيل.

**فحص الإغلاق المستقل (بعد إصلاحات الجولة 5):** ‏5 أبعاد مسح + دحض عدائي؛ ‏4 أبعاد نظيفة، وبُعد واحد أمسك **تناقضاً حياً أخيراً من نفس فئة النقطة 6**: استثناء lizard **لكل ملف** داخل `complexity_findings` كان يصل `rule_errors` فقط (الـ except الداخلي يبتلعه قبل غلاف المنسق) فتبقى rule_health=1.0 وقد يمرّ PASS — والتعليق يدّعي العكس. **أُصلح**: العدّ صار لكل ملف داخل `complexity_findings` (‏attempted/failures)، الغلاف يغطي الانهيار الكلي فقط، و**حزام أمان في verdict: أي `rule_errors` مسجلة تمنع pass بمعزل عن العدادات** (يغلق الفئة كلها لأي مسار مستقبلي)؛ ‏regression: `test_lizard_per_file_failure_reaches_failure_counters`.

# ملخص أثر الأحكام على الدقة

- **إزالة مصادر FP حمراء زائفة:** stdlib drift (H008 زائفة)، الحزم الخاصة/scoped (→H010)، JUnit4 (H007 زائفة رغم الإعلان الصحيح).
- **إغلاق نقاط عمياء FN:** javax الخارجية، System.* المسلَّمة كحزم، ‏`test`/`sqlite`/`sea`، ‏hooks في callbacks/&&/بعد return، Pipfile.
- **منع تضليل الهوية:** NUnit relic، npm aliases، caffeine.
- **الشفافية:** كل فشل جزئي يظهر في report.json/limitations مع `analysis_confidence` منفصلة عن `risk_score`، وكل قاعدة موسومة exact/heuristic.

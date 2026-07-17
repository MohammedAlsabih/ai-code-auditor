# RESEARCH.md — بحث ما قبل البناء لأداة AI Code Auditor (النسخة المنقحة v2)

**تاريخ البحث الأصلي:** 2026-07-17 · **تاريخ المراجعة العدائية:** 2026-07-17 (نفس اليوم)
**المنهجية:** 4 مسارات بحث أولية + 4 مسارات إعادة تحقق عدائية، كلها بتجارب حية قابلة للتكرار أو مصادر رسمية مباشرة. كل ادعاء أدناه يحمل أمره ونتيجته ومصدره. أحكام المراجعة الكاملة في [docs/superpowers/plans/2026-07-17-adversarial-review.md](docs/superpowers/plans/2026-07-17-adversarial-review.md).
**أثر المراجعة:** 4 ادعاءات من النسخة الأولى **دُحضت** وصُوّبت هنا (ترتيب إصدارات Maven، بند "المنافسة" في ترخيص semgrep، حيوية opengrep-rules، تاريخ lizard)، وأُضيفت اكتشافات جديدة (javax/System/stdlib/builtins، السجلات الخاصة، PEP 792 الحي، قياس corpus).

> اصطلاح: 🔬 = تجربة حية منفذة على جهاز التطوير (Windows 11, Python 3.12.4, Node 24) · 📄 = مصدر رسمي مباشر.

---

## 1. مشهد الأدوات (2025–2026) — أرقام مُعاد تحققها بـ GitHub API بتاريخ 2026-07-17

| الأداة | ماذا تفعل | فحص وجود بالسجل؟ | ★ | آخر دفع | ترخيص |
|---|---|---|---|---|---|
| dep-hallucinator | ملفات التبعيات فقط (لا كود) — Py/JS/Java/Rust/Go، بلا .NET | نعم | 8 | 2026-01-27 | MIT |
| Trace-core | أقرب منافس مفاهيمي: 24 نمط فشل AI — بلا Java/.NET | npm/PyPI فقط | 11 | 2026-04-26 | MIT |
| depfence | 56 فاحص سلسلة توريد | npm+PyPI جزئياً | 3 | 2026-07-08 | Apache-2.0 |
| ghostdep | استيرادات غير معلنة (AST) | لا | 8 | 2026-04-04 | MIT |
| slop-scan / slopcheck | أسماء npm في JS/docs | npm فقط | 0 / 9 | 2026-05 / 2026-07 | MIT |
| GuardDog (DataDog) | خبث محتوى الحزم، لا استيرادات مشروعك | لا | 1159 | 2026-07-14 | Apache-2.0 |
| confused / ConfusedDotnet | dependency confusion من manifests | نعم | 786 / 15 | **2024-08 / 2021-03 خامدان** | MIT |
| npq | بوابة ما قبل التثبيت npm (عمر <22 يوماً، تحميلات) | ضمنياً | 1759 | 2026-07-17 نشط | Apache-2.0 |
| CodeGate (Stacklok) | كان يعترض هلوسات LLM | نعم | 790 | **مؤرشف 2025-06-05** (مؤكد API) | Apache-2.0 |
| deptry — **انتقل إلى osprey-oss/deptry** | استيرادات غير معلنة بايثون (بلا سجلات) | لا | 1436 | 2026-07-16 | MIT |
| FawltyDeps | مثله (ترخيص MIT من ملف LICENSE؛ الـ API يقول NOASSERTION) | لا | 288 | 2025-07-01 | MIT |
| DepScope | فحص 19 سجلاً عبر **خادم سحابي مغلق** | نعم (سحابياً) | 1 | 2026-05 | عميل AGPL |

**الأبحاث:** Spracklen et al.‏ USENIX Security 2025 (هلوسة ≥5.2% تجاري/21.7% مفتوح؛ 205,474 اسماً فريداً؛ 58% تتكرر) · trendmicro/slopsquatting (MIT): أسماء مهلوسة حقيقية علنية — مرشح لاختبارات رجعية مستقبلية.

**الفجوة (صامدة بعد المراجعة):** لا أداة واحدة تجمع (أ) استخراج الاستيرادات من الكود للغات الأربع + (ب) ربط Java/.NET namespaces بالسجلات + (ج) فحص السجلات الأربعة محلياً وحتمياً + (د) قواعد أنماط AI لـ React/Next. جافا و.NET شبه مهملتين في كل ما سبق.

**أصول قابلة لإعادة الاستخدام:** deps.dev API v3 (بديل موحد مستقبلي)، خريطة pipreqs (اقتباس مصغر)، عتبة npq الزمنية (تبنينا 90 يوماً + تحميلات)، trendmicro dataset (اختبارات رجعية).

## 2. tree-sitter — 🔬 مثبتة ومقاسة

| ادعاء | الطريقة | النتيجة |
|---|---|---|
| الإصدارات: tree-sitter 0.26.0 (2026-06-30)، ‑python 0.25.0، ‑java 0.23.5، ‑c-sharp 0.23.5، ‑typescript 0.23.2 — عجلات ويندوز cp311+ | `pip install` فعلي + إعادة تحقق `curl pypi.org/pypi/<pkg>/json` | مؤكدة مرتين (بحث + مراجعة) |
| ‏API الحالية: `Language(mod.language())` / `Parser(lang)` / `Query(lang, src)` / `QueryCursor(query).captures(node)`؛ ‏`Language.query()` و`Query.captures()` **أزيلا** | تشغيل snippet لكل لغة + TSX | مؤكدة؛ أي كود قديم الطراز = AttributeError |
| أسماء عقد TSX في خوارزميات قواعد React | **تنفيذ حرفي لخوارزميات الخطة** على corpus ‏18 ملفاً | **صفر mismatches** — كل الأسماء طابقت (`ternary_expression`، `catch_clause`، `array_pattern`...) |
| ملاحظة | حزم القواعد لا تسحب `tree-sitter` — يجب إعلانها صراحة؛ ‏`.tsx` تُحلل بـ `language_tsx()` | — |

**قرار:** الحزم الفردية (لا language-pack) — أحدث وأصغر.

## 3. واجهات السجلات — 🔬 كلها باستدعاءات حية موثقة

### PyPI
- الوجود+التواريخ: `GET pypi.org/simple/{name}/` مع `Accept: application/vnd.pypi.simple.v1+json` (PEP 691) — ‏200/404؛ أول نشر = أصغر `files[].upload-time` (PEP 700).
- **PEP 792 (مصوَّب بالتجربة):** المفتاح `project-status.status` (لا `state` — نص الـ PEP متناقض داخلياً مع مثاله؛ التطبيق الحي والمواصفة الحية حسما `status`). الحالات المطبقة فعلاً: `active`/`archived`/`quarantined` (‏`deprecated` غير مطبق بعد — مدونة PyPI ‏2025-08-14). الغياب ⇒ active. 🔬 أربع حزم مؤرشفة فعلياً أعادت `{"status":"archived"}`.
- **تحذير 404:** الحزم المحجورة-ثم-المزالة تعيد 404 (حالة aiocpa) — أي أن 404 ≠ "لم توجد قط" بالضرورة؛ صياغة النتائج تلتزم الوقائع.
- التحميلات: pypistats.org — ‏404 نصي غير JSON (🔬)، خنق وقائي ~نداء/ثانيتين، يُستدعى فقط للحزم الأصغر من 90 يوماً.

### npm
- `GET registry.npmjs.org/{name}` (المستند الكامل لأجل `time.created`؛ سقف قراءة 2MB — تجاوزه ⇒ حزمة عريقة)؛ scoped بترميز `%2F`.
- **aliases (📄 وثائق npm):** `"foo": "npm:bar@^1"` ⇒ فحص السجل على **bar**. **`imports` (📄 nodejs.org):** مفاتيح `#x` ليست أسماء سجل أبداً (خاصة بالحزمة)؛ أهدافها تبعيات عادية تُغطى بالفحص المعتاد.
- التحميلات: `api.npmjs.org/downloads/point/last-week/{name}` عند الحداثة فقط.

### Maven Central
- **solrsearch شديد التقادم وغير صالح لفحص الوجود/الحداثة** (🔬 مؤكد مرتين؛ صياغة منضبطة: الدليل يثبت توقف التحديث منذ ~Q2 2025 — «متجمد نهائياً» ادعاء أقوى من الدليل): jackson ‏2.19.0/2025-04-24 في solr مقابل ‏2.22.1/2026-07-08 على repo1؛ spring متخلف major كاملاً.
- الفحص: `repo1.maven.org/maven2/{g/}/{a}/maven-metadata.xml` — ‏200/404؛ ‏`<lastUpdated>` = **آخر** نشر (‏yyyyMMddHHmmss، ‏📄 repository-metadata.html).
- **❌ مدحوض (مراجعة، ثم شُدّد بالجولة الثانية):** «‏`versions[0]` = أول نشر» — القائمة **version-sort لا زمنية** (🔬 backports ‏log4j ‏2.12.2-4 المنشورة 12/2021 تجلس قبل 2.13.0 المنشور 2019؛ ‏spring ‏6.2.19 المنشور 2026 قبل ‏7.0.0-M1 المنشور 2025)، والوثيقة صامتة عن الترتيب، و`<latest>` قد يكون beta — **وقلة العدد لا تجعل الترتيب زمنياً**. **العلاج النهائي:** للحزم الوليدة فقط (≤10 إصدارات + lastUpdated حديث): ‏HEAD على **جميع** ملفات POM وأخذ **أقدم** Last-Modified؛ لغيرها created=unknown فلا تصدر H005/H006 أصلاً. ‏Last-Modified نفسه heuristic خادم وليس تاريخ نشر معيارياً — يُذكر في limitations.
- التحميلات: غير متاحة إطلاقاً (مؤكد).

### NuGet
- الوجود: flat-container ‏`{id-lowercase}/index.json` ‏200/404؛ التواريخ: registration (استبعاد `published` = ‏1900 لغير المدرجة)؛ التحميلات عند الحداثة: azuresearch ‏`totalHits`/`totalDownloads`.
- **🔧 (مراجعة):** الوثيقة الرسمية **تلزم** حل العناوين من `v3/index.json` ‏("must be dynamically fetched from the service index") + فخ: hives ‏semver1 تعيد 404 لحزم SemVer2 حقيقية. **العلاج:** حل `RegistrationsBaseUrl/3.6.0` مرة لكل تشغيل مع fallback.

### السجلات الخاصة (جديد — قاتل الإيجابيات الزائفة)
📄 مصفوفة رسمية كاملة: قابلة للكشف داخل المستودع: ‏`.npmrc` للمشروع (`registry=`، ‏`@scope:registry=`) · أسطر `-i/--index-url/--extra-index-url/--no-index/--find-links` في requirements · ‏`[[tool.uv.index]]` و`[[tool.poetry.source]]` · ‏`nuget.config` ‏`<packageSources>` · ‏`<repositories>` في pom.xml · ‏`repositories{maven{url}}` في gradle. **غير قابلة للكشف:** env vars ‏(NPM_CONFIG_REGISTRY، ‏PIP_INDEX_URL...)، ‏`~/.m2/settings.xml` ‏mirrors، إعدادات CI — تُذكر كتحفظ دائم. أيضاً: حزم npm الخاصة تحت scope تعيد 404 بلا توكن. **القرار:** «غير موجودة + مصدر خاص مُهيأ أو scoped» ⇒ H010 أصفر "غير قابلة للتحقق (انكشاف dependency-confusion)" بدل H001 حمراء.

## 4. semgrep/opengrep — تصويبات ترخيصية جوهرية

| ادعاء | الدليل | الحالة |
|---|---|---|
| semgrep ‏1.170.0 يعمل أصلياً على ويندوز | 🔬 تثبيت وتشغيل فعلي + فحص متعدد اللغات؛ ‏GA خريف 2025 | مؤكد |
| احذر BOM (يُسقط semgrep بخطأ 7) وCE يحجب fingerprint/lines بلا دخول ويفوّت taint على TSX منمّط | 🔬 | مؤكد |
| opengrep ‏1.25.0: ‏exe ويندوز موقّع، LGPL-2.1، نشط (آخر دفع اليوم) | ‏GitHub API + LICENSE خام | مؤكد |
| **ترخيص قواعد سجل semgrep** | النص الحرفي (وصول 2026-07-17): ‏"only for your own **internal business purposes**"، ‏"does not allow you to **distribute** the rules, or to make them available to others **as a service**"، ‏non-sublicensable/non-transferable. ‏`grep -ci compet` على النص = **0** | **مصوَّب:** لا بند "منتج منافس" في النص (كان في تدوينة الشركة لا الترخيص). القيد يلزم "من يستخدم القواعد": أداتنا لا تجلبها ولا توزعها؛ تمرير المستخدم `--semgrep-config p/x` فعل مرخَّص له هو |
| opengrep-rules "بديل قابل للتضمين" | ‏GitHub API: **archived=true** منذ 2025-11-28، الترخيص Commons Clause فوق LGPL يسمّي Semgrep Inc.، وREADME: ‏"research, testing & benchmarking" | **مدحوض** — ولا أثر على خطتنا (لم نتبنّه) |
| القواعد الجاهزة لـ hooks/Next | ‏10 حزم قواعد منزلة فعلياً: ‏p/nextjs **صفر قواعد**، ‏p/react أربع قواعد أمنية، لا شيء لـ hooks/NEXT_PUBLIC/use-client في الرسمي أو المجتمعي | مؤكد مرتين — وبصياغة منضبطة (جولة 3): ESLint «خيار» تقنياً لكنه مرفوض لأسباب تشغيل وتغليف (يتطلب Node في أداة بايثون، وعزل إعدادات مستودع غير موثوق)؛ الخيار العملي المتبقي داخل قيودنا هو بناء القواعد على tree-sitter |

**فصل التراخيص الأربعة (جولة ثانية — النص الحرفي في خانة والتحليل في خانة):**

| البند | النص/المصدر الحرفي | التحليل (ليس استشارة قانونية) |
|---|---|---|
| محرك semgrep CE | LGPL-2.1 (ملف الترخيص بالمستودع) | استدعاؤه كـ subprocess سليم |
| محرك opengrep | ‏"GNU LESSER GENERAL PUBLIC LICENSE / Version 2.1" (LICENSE بالمستودع، GitHub API يؤكد) | كذلك |
| Semgrep Rules License v1.0 | ‏"only for your own **internal business purposes**" + ‏"does not allow you to **distribute** the rules, or to make them available to others **as a service**" + ‏non-sublicensable (semgrep.dev/legal/rules-license، وصول 2026-07-17) | يقيّد **من يستخدم القواعد**. أداتنا لا تجلبها ولا توزعها ولا تمنح حقوقاً عليها؛ تمرير المستخدم `--semgrep-config p/x` **لا يوصف بأنه مسموح بإطلاق** — توافقُ استخدامه مسؤوليته هو، ونطبع تنبيهاً بذلك |
| opengrep-rules | ‏Commons Clause v1.0 فوق LGPL-2.1، المرخِّص المسمى Semgrep Inc.، والمستودع **مؤرشف** وREADME يحصره في research/testing | غير مُتبنى في الأداة إطلاقاً |

**ضمانات التشغيل الافتراضي (🔬):** الاستدعاء الافتراضي محلي بالكامل (‏`--config` وحيد يشير لملفنا المضمّن — لا اتصال بسجل semgrep)، و`--metrics=off` يُمرَّر لثنائي semgrep (اختبرناه فعلياً: يقبل ويعمل)؛ opengrep بلا telemetry أصلاً. **provenance قواعدنا:** ‏auditor-extra.yml قواعد أصلية كُتبت من أنماط عامة (eval/pickle/exec-concat/weak-hash) بترخيص MIT — ليست مشتقة من أي محتوى مقيد، ومصرّح بذلك في ترويسة الملف.

**القرار (معزز):** المحرك المدمج tree-sitter هو الأساس دائماً؛ opengrep/semgrep طبقة اختيارية تشغّل **قواعد YAML خاصة بنا فقط** (MIT)؛ لا جلب ولا تضمين لقواعد السجل.

## 5. قياس قواعد React/Next مقابل ESLint — 🔬 corpus قابل لإعادة التشغيل

**العدة:** eslint ‏9.39.5 + eslint-plugin-react-hooks ‏7.1.1 + typescript-eslint ‏8.64.0، ‏flat config معزول (`--no-config-lookup`، قاعدتا hooks فقط) مقابل تنفيذ حرفي لخوارزميات الخطة على tree-sitter 0.26.0. ‏18 ملفاً + 4 ملفات nextdemo.

**النتيجة (بالعرض الصحيح للمقاييس — جولة ثانية):** ‏agreement accuracy = ‏12/18 = **66.7%**؛ ‏TP=8, TN=4, FP=3, FN=3 ⇒ ‏precision = recall = F1 = **72.7%** (مقابل ESLint كمرجع). **تصنيف الانحرافات الست** (لا يُحسب كل اختلاف عن ESLint عيباً في المنتج): 4 عيوب تنفيذ فعلية (‏&&، ‏early-return، ‏callbacks، نطاق R005) — أُصلحت في الخطة v2؛ انحرافان مقصودان عن المرجع (try/catch بسند react.dev، وR004 بمطلب المواصفة) — يُحسبان ضمن **spec conformance** لا ضد المنتج. مؤشر spec-conformance بعد الإصلاحات هدفه 18/18 مع **إعادة تشغيل الـ corpus بعد التنفيذ** (بوابة CP-4) — الأرقام الحالية قياس لخوارزميات ما قبل إصلاحات الجولتين 2–3 ولا تصلح دليلاً على النسخ المعدلة. الـ corpus والأدوات نُقلت إلى `evidence/react-compare/` داخل المشروع (كانت في TEMP متطاير) مع أوامر إعادة التشغيل والإصدارات في `evidence/README.md`. التفكيك والقرارات:
- **أُصلح في الخطة v2:** ‏`&&`/`||`/`??` كتحكم شرطي (FN) · فحص return مبكر كـ heuristic أشقاء (FN) · إعادة تعريف R003 على الدالة الحاضنة الأعمق ليلتقط callbacks (FN) · استثناء متغيرات الـ callback من R005 (FP).
- **انحرافان مقصودان موثقان:** hook داخل try/catch (ESLint صامت؛ ‏📄 react.dev يحظره نصاً — نبقيه) · ‏useEffect بلا مصفوفة (exhaustive-deps يتجاهله عمداً؛ مواصفتنا تطلبه — أصفر).
- **فجوة بنيوية مثبتة:** حدود "use client" على مستوى **module graph** ‏(📄 وثائق Next ‏16.2.10): ملف hooks بلا directive مستورد من Server Component = خطأ بناء حقيقي خرج **بصفر نتائج** من التحليل الملفّي؛ والعكس (وراثة boundary من مستورد client) لم يولّد FP. **الاقتراح المعلق على القرار:** تمريرة import-graph خفيفة (N006) على الاستيرادات المستخرجة أصلاً.

## 6. المكتبات القياسية والـ builtins — قياسات أرضية (كلها 🔬/📄 بتاريخ 2026-07-17)

- **Java ‏javax:** ‏JDK 21 يملك **21 بادئة javax فقط** (جرد وحدة-وحدة من docs.oracle.com) — أبرز الفخاخ: ‏`javax.annotation.processing` ‏(JDK) مقابل `javax.annotation` (خارجي)؛ ‏`javax.transaction.xa` مقابل `javax.transaction`؛ ‏`javax.rmi.ssl` مقابل `javax.rmi`؛ ‏`javax.xml.*` مقابل `javax.xml.bind|ws|soap` (أخرجها JEP 320). ‏18 عائلة javax خارجية مؤكدة على repo1 (‏servlet، ‏persistence، ‏mail، ‏validation، ‏inject...) — القاعدة الشاملة كانت نقطة عمياء كاملة.
- **خريطة Java (‏ground truth ‏33 استيراداً):** ‏25 صحيحة، أبرز الإصلاحات: ‏`org.junit` → ‏`junit:junit` (كان يولّد H007 زائفة **حتى مع الإعلان الصحيح**)، مفتاح kotlin الصحيح `kotlin` لا `org.jetbrains.kotlin`، ‏caffeine ‏(`com.github.ben-manes...` بشرطة لا يحملها الـ package)، ‏httpclient5، وتدقيق jackson/spring لكل artifact.
- **‏.NET ‏System.*:** لكل TFM ‏(📄 learn.microsoft.com): على net8/9 خمسة namespaces تُسلَّم كحزم رغم اسم System ‏(CommandLine، ‏Data.SqlClient — deprecated رسمياً لصالح Microsoft.Data.SqlClient، ‏Drawing، ‏Management، ‏Data.Entity)؛ وعلى net48/netstandard2.0 تضاف Text.Json وCollections.Immutable وغيرها. ‏`TargetFramework(s)` تُقرأ (الجمع يلغي المفرد 📄 msbuild-props) وقائمة package-delivered مُنسقة تعالج الفرق.
- **‏NuGet heuristic:** ‏14/15 ‏(93%)؛ الاستثناء المضلل `NUnit.Framework` → حزمة أثرية `nunit.framework 2.63.0` — يعالَج بخريطة أسماء مصغرة. المعرفات case-insensitive (مؤكد عملياً).
- **Node builtins:** ‏node 24 فعلياً: ‏`sys` و`constants` ‏builtins حقيقيان (مهجوران)؛ **‏`test`/`sqlite`/`sea` بأسمائها المجردة ليست builtins بأي نسخة** ‏(node:-scheme فقط، ‏📄 nodejs.org) وحزم npm بأسمائها موجودة (200) — حذفها من القائمة يفتح فحص السجل الصحيح.
- **Python stdlib:** الاعتماد على `sys.stdlib_module_names` وقت التشغيل **مدحوض بالاتجاهين**: ‏`distutils` غائب عن 3.12 **وموجود كحزمة PyPI (‏200!)** ⇒ ‏H002 زائفة؛ ‏`telnetlib` سيغيب عن فاحص 3.13 وغير موجود على PyPI ‏(404) ⇒ ‏H008 حمراء زائفة. **العلاج:** اتحاد ثابت مع جدول المُزال (‏PEP 594 + ‏PEP 632 + ‏imp/lib2to3، بنسخ الإزالة) + إشارة زرقاء للاتجاه الآخر فقط عند وجود `requires-python` قابلة للقراءة.

## 7. التعقيد الدوراني

- **lizard ‏1.23.0 — تصويب تاريخ:** صدر **2026-06-02** ضمن 6 إصدارات أبريل–يونيو 2026 (المشروع نشط؛ ادعاء "خامل منذ 2024" خاطئ). 🔬 يقيس CCN للأربع لغات + tsx كمعرّف مستقل عبر ‏API بايثوني. البدائل أضعف (radon بايثون-فقط خامل 3 سنوات؛ complexipy بايثون-فقط cognitive). **القرار ثابت:** lizard وحدها بعتبة >10.

## 8. أمن الفحص لمستودعات غير موثوقة (جديد — من المراجعة)

لا تنفيذ لأي محتوى من المستودع (لا install/build/hooks/ESLint-config)؛ الاستنساخ بلا submodules ومع `GIT_TERMINAL_PROMPT=0` و`GIT_LFS_SKIP_SMUDGE=1` و`-c core.symlinks=false` ومهلة 300s؛ الـ walker يتخطى symlinks ويسقّف الملفات (1.5MB) والـ manifests ‏(2MB). 🔬 ‏XML عدائي (بقياس الذاكرة والعقد لا الزمن فقط — جولة ثانية): قنبلة كيانات أوقفتها حدود BLAP في expat ‏2.6.2 ("amplification factor breached") — **مثبتة لهذا البناء المحلي تحديداً، وليست ضماناً لكل Python 3.11+ ولا لكل استهلاك موارد**؛ ملف سليم 2.7MB/‏300k عقدة → **ذروة ذاكرة 38MB (تضخيم ×14)**، وعمق 50k → ‏48MB. **القرار الموازن للـ MVP:** ‏defusedxml لكل XML من المستودع (يحيّد هجمات الكيانات باستقلال عن بناء expat لدى المستخدم) + سقف 2MB كضابط الموارد الفعلي + كل ParseError/تخطٍّ يظهر في diagnostics. لا sandbox حقيقي على ويندوز — الضمانة المعمارية: قراءة وتحليل فقط، مع redaction لأي credentials تظهر في أسطر التبعيات داخل التقارير.

## 9. قرارات معمارية نهائية (بعد المراجعة)

| القرار | مصدره |
|---|---|
| tree-sitter 0.26 + حزم فردية، نمط Query/QueryCursor حصراً | §2 |
| **نواة محايدة فعلياً**: المحوّل يوفّر `grammars()` و`syntax()→SyntaxProfile` و`project_rules()` — لا معرفة لغوية في core | مراجعة محور 2 |
| Maven عبر repo1 فقط؛ تاريخ الإنشاء بحارس الحزم الوليدة | §3 |
| NuGet بحل service index ديناميكياً | §3 |
| H010 للسجلات الخاصة/scoped، H012 للمؤرشفة، صياغة وقائع لا أحكام | §3 + مراجعة محور 4 |
| قواعد hooks/Next داخلية بـ tree-sitter، بإصلاحات القياس الأربعة + الانحرافين الموثقين | §5 |
| semgrep/opengrep طبقة اختيارية بقواعدنا فقط؛ لا dedupe عبر المحركات (تكامل لا تكرار) | §4 + مراجعة محور 8 |
| stdlib/BCL/builtins بالقوائم المصوّبة (javax-21، ‏System-package-delivered+TFM، ‏node بلا test/sqlite/sea، ‏python بجدول المُزال) | §6 |
| ‏`risk_score` (بلا أزرق) منفصلة عن `analysis_confidence`؛ العنوان يظهر أدنى لغة وعدد 🔴 دائماً | مراجعة محور 10 |
| ‏Diagnostics شاملة: كل فشل جزئي يظهر في report.json وlimitations؛ كل قاعدة موسومة exact/heuristic | مراجعة محور 7 |

**حدود دقة معلنة سلفاً (ستُطبع في كل تقرير):** ربط Java/.NET namespace→artifact يبقى heuristic بخرائط مُنسقة (غير المربوط = H007 لا أحمر)؛ Maven بلا إشارة تحميلات؛ قنوات السجلات الخاصة غير القابلة للكشف؛ حدود use client الملفّية (إلى حين اعتماد N006)؛ فحوص SQL/dangerouslySetInnerHTML syntactic لا data-flow.

## المصادر الرئيسية

py-tree-sitter (github + releases) · docs.pypi.org/api + PEP 691/700/792 + مدونة PyPI ‏2025-08-14 + مدونة quarantine ‏2024-12-30 · npm registry docs + docs.npmjs.com (npmrc/scope/install-alias) + nodejs.org (subpath imports، ‏test/sqlite/sea) · maven.apache.org (repository-metadata.html، ‏settings/pom docs) + central.sonatype.org/faq · learn.microsoft.com (nuget api/overview + registration-base-url + nuget-config-file + msbuild-props + مصفوفة System.*) · semgrep.dev/legal/rules-license (النص الحرفي) + opengrep releases/LICENSE · terryyin/lizard (PyPI history) · react.dev (rules-of-hooks + eslint-plugin changelog) · nextjs.org ‏16.2.10 (server-and-client-components + env vars) · docs.oracle.com JDK 21 module docs + JEP 320 · PEP 594/632 · pip/uv/poetry/gradle official docs (private indexes) · usenix.org (Spracklen 2025) + trendmicro/slopsquatting · أوامر التجارب كاملة في وثيقة المراجعة العدائية.

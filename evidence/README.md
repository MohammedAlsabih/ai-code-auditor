# evidence/ — أدلة المراجعة العدائية القابلة لإعادة التشغيل

نُقلت من scratchpad الجلسة (متطاير) إلى المشروع بتاريخ 2026-07-17، وجُعلت **قابلة لإعادة التشغيل من checkout نظيف** في الجولة الرابعة (لا مسارات TEMP مثبتة؛ ‏xml_stress يقيس الذاكرة فعلياً بـ tracemalloc). النتائج المرجعية للجولات الأربع موثقة في `../docs/superpowers/plans/2026-07-17-adversarial-review.md`.

## المحتويات وأوامر إعادة التشغيل

| ملف/مجلد | ماذا يثبت | إعادة التشغيل |
|---|---|---|
| `react-compare/corpus/` (18 tsx) + `eslint.config.mjs` + `package.json`/`package-lock.json` | مقارنة قواعد الخطة مع eslint-plugin-react-hooks — ‏accuracy ‏12/18=66.7%، ‏P=R=F1=72.7% (قياس نسخة v1 قبل الإصلاحات؛ يعاد عند CP-4 على القواعد المنفذة) | من داخل `react-compare/`: ‏`npm ci` ثم `npx eslint --no-config-lookup -c eslint.config.mjs corpus -f json` ثم `python prototype.py corpus out.json` (بعد `pip install "tree-sitter>=0.26,<0.27" "tree-sitter-typescript>=0.23.2,<0.24"`) |
| `react-compare/prototype.py` | تنفيذ حرفي لخوارزميات الخطة v1 — صفر أخطاء أسماء عقد | أعلاه |
| `react-compare/nextdemo/` + `nextdemo-results.json` | عمى التحليل الملفّي عن حدود module-graph (أساس اعتماد N006) | من داخل `react-compare/`: ‏`python prototype.py nextdemo out.json --with-n003` |
| `r003v2_test.py` | ‏R003-الأعمق: 3 FP بلا استثناء memo/forwardRef و7/7 معه؛ ‏early-return: ‏FP الـ callback داخل if والحل بحدود الدوال 4/4 — **ذاتي الاكتفاء** (تعليمات venv في ترويسته) | `python r003v2_test.py` |
| `xml_stress.py` | حدود BLAP لبناء expat 2.6.2 + **قياس ذاكرة مدمج** (‏tracemalloc): ‏2.7MB→38MB ‏(×14) — مبرر defusedxml+سقف 2MB | `python xml_stress.py` (stdlib فقط، يطبع الذاكرة والعقد والزمن) |
| `semgrep_license_text.txt` | النص الحرفي لـ Semgrep Rules License v1.0 (لا بند منافسة؛ internal-use + لا توزيع/خدمة) | `curl -sL https://semgrep.dev/legal/rules-license/` |
| `opengrep_rules_LICENSE.txt` + `opengrep_rules_readme.md` | ‏Commons Clause فوق LGPL-2.1 باسم Semgrep Inc.؛ المستودع مؤرشف وREADME يحصره بالبحث | `curl -sL https://raw.githubusercontent.com/opengrep/opengrep-rules/main/LICENSE` |
| `log4j-metadata.xml` | ترتيب `<versions>` رقمي لا زمني (backports ‏2.12.2-4 في الموضع الرقمي) | `curl -s https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/maven-metadata.xml` |
| `nuget-index.json` | موارد service index الفعلية (RegistrationsBaseUrl/3.6.0 وأخواتها) | `curl -s https://api.nuget.org/v3/index.json` |
| `pypi-requests.json` | شكل PEP 691/792 الحي (`project-status.status`) | `curl -s -H "Accept: application/vnd.pypi.simple.v1+json" https://pypi.org/simple/requests/` |

## الإصدارات المرجعية وقت القياس (2026-07-17)

Windows 11 Pro · Python 3.12.4 (expat 2.6.2) · Node v24.14.0 · eslint 9.39.5 · eslint-plugin-react-hooks 7.1.1 · typescript-eslint 8.64.0 · tree-sitter 0.26.0 · tree-sitter-typescript 0.23.2 · semgrep 1.170.0 · opengrep 1.25.0 · packaging (لتقييم PEP 440).

**أرقام XML المقيسة (بإعادة التشغيل الأخيرة، مصحّحة):** ‏deep-50k → ذروة **~14MB** (لا 48MB كما ورد سابقاً)؛ ‏wide 2.7MB/300k عقدة → ذروة **38MB (×14 من المدخل)**؛ قنبلة الكيانات → ‏ParseError "amplification factor breached". قيد الخطة يستشهد برقم wide (‏38MB ×14) وهو الصحيح.

**أكواد خروج semgrep المقيسة:** فحص سليم = 0؛ ‏config مفقود = 7؛ ‏config تالف = 7. **إشارة الاكتمال:** ‏JSON يتضمن `paths.scanned` (يعدّد الملفات فعلاً) و`errors`؛ الاعتماد على rc+JSON صالحين وحدهما لا يثبت الاكتمال (ملف مكسور قد يُمرَّر بصمت)، لذا يقارن العميل `paths.scanned` بالملفات المتوقعة.

**ملاحظة مسارات:** ملفات `*-results.json` الناتجة عن ESLint تحوي مسارات مطلقة خاصة بجهاز القياس؛ لإعادة توليدها بمسارات نظيفة استخدم أوامر إعادة التشغيل أعلاه من داخل `react-compare/` (المسارات تصبح نسبية لمجلد العمل).

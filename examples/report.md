# AI Code Auditor Report

**Target:** `https://github.com/open-telemetry/opentelemetry-demo`  
**Generated:** 2026-07-18T00:17:44.737161+00:00  
**Tool:** ai-code-auditor v0.1.0

## Executive Summary | الملخص التنفيذي

Overall code-health score (higher = safer) | درجة سلامة الكود: **66/100**
**Verdict | الحكم الآلي: `BLOCK`**
- 🔴 Critical: 2   🟡 Warning: 100   🔵 Info: 63
- ⚠️ Lowest language | أدنى لغة: **java = 0/100** (the average must not hide this)
- Analysis confidence | ثقة التحليل: 90/100 (separate axis: how COMPLETE the checks were, not how risky the code is)

## Engines

| Engine | Status |
|---|---|
| ast | tree-sitter 0.26 (python/java/csharp/typescript/tsx) |
| registry | online (pypi/npm/maven/nuget, cached) |
| complexity | lizard |
| semgrep | not available (builtin rules only) |

## Scores per language

| Language | Files | Score | 🔴 | 🟡 | 🔵 |
|---|---|---|---|---|---|
| python (`.`) | 2 | **90/100** | 0 | 2 | 0 |
| typescript (`.`) | 6 | **65/100** | 0 | 7 | 6 |
| dotnet (`src/accounting`) | 5 | **70/100** | 0 | 6 | 1 |
| java (`src/ad`) | 4 | **0/100** | 0 | 29 | 0 |
| python (`src/agent`) | 5 | **65/100** | 0 | 7 | 0 |
| dotnet (`src/cart`) | 0 | **100/100** | 0 | 0 | 0 |
| dotnet (`src/cart/src`) | 6 | **25/100** | 0 | 15 | 1 |
| dotnet (`src/cart/tests`) | 1 | **80/100** | 0 | 4 | 0 |
| python (`src/chatbot`) | 2 | **95/100** | 0 | 1 | 1 |
| java (`src/fraud-detection`) | 0 | **100/100** | 0 | 0 | 0 |
| typescript (`src/frontend`) | 109 | **80/100** | 1 | 1 | 6 |
| python (`src/mcp`) | 2 | **90/100** | 0 | 2 | 0 |
| typescript (`src/payment`) | 3 | **95/100** | 0 | 1 | 0 |
| typescript (`src/react-native-app`) | 36 | **25/100** | 1 | 12 | 8 |
| python (`src/recommendation`) | 5 | **45/100** | 0 | 11 | 40 |
| python (`src/recommendation/genproto`) | 0 | **100/100** | 0 | 0 | 0 |
| python (`src/telemetry-docs`) | 0 | **100/100** | 0 | 0 | 0 |
| python (`test/telemetry`) | 8 | **90/100** | 0 | 2 | 0 |

**Scoring contract | عقد الدرجات:** `code_health per language = max(0, 100 - 15*red - 5*yellow) — HIGHER is safer (this is a health/safety score, deliberately NOT named 'risk'); blue findings are informational and never affect health; overall = file-count-weighted average, ALWAYS reported alongside lowest language and red count. analysis_confidence = coverage-v2 (experimental): round(100 * file_coverage * manifest_coverage * (0.5 + 0.5*registry_coverage) * rule_health * parse_factor * semgrep_factor) where file_coverage = read/(read+skipped), manifest_coverage = 1 - unique_error_files/unique_manifest_files, registry_coverage = 0 offline else 1 - failures/attempted, rule_health = 1 - rule_failures/rule_attempted (uncapped), parse_factor = 1 - min(1, parse_errors/files_read) (uncapped), semgrep_factor = 1.0 success / 0.97 partial / 0.95 otherwise. verdict: block if red>0 or confidence<40 or ALL rule invocations failed; review if yellow>0 or confidence<70 or any manifest/rule/parse failure; else pass — any rule failure forbids pass.` — i.e. `max(0, 100 - 15*🔴 - 5*🟡)` per language; 🔵 is informational and never changes the score. Findings marked `*` are heuristic (`precision: heuristic`), not proofs.

## Python — `.` (90/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | P006 | `internal/tools/sanitycheck.py:15` | `sanitycheck` | sanitycheck has cyclomatic complexity 32 (> 10). |
| 🟡 | H002* | `src/shared/tools.py:9` | `httpx` | httpx: imported but not declared in the manifest (exists in registry as 'httpx'). |

## Typescript — `.` (65/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H002 | `src/flagd-ui/assets/js/app.js:5` | `phoenix_html` | phoenix_html: imported but not declared in the manifest (exists in registry as 'phoenix_html'). |
| 🟡 | H002 | `src/flagd-ui/assets/js/app.js:7` | `phoenix` | phoenix: imported but not declared in the manifest (exists in registry as 'phoenix'). |
| 🟡 | H002 | `src/flagd-ui/assets/js/app.js:8` | `phoenix_live_view` | phoenix_live_view: imported but not declared in the manifest (exists in registry as 'phoenix_live_view'). |
| 🟡 | P006 | `src/flagd-ui/assets/vendor/daisyui.js:86` | `(anonymous)` | (anonymous) has cyclomatic complexity 11 (> 10). |
| 🟡 | P006 | `src/flagd-ui/assets/vendor/daisyui.js:221` | `getPrefixedKey` | getPrefixedKey has cyclomatic complexity 22 (> 10). |
| 🔵 | P007 | `src/flagd-ui/assets/vendor/daisyui.js:467` | `var object_default18 = { ".input": { cursor: "text", border:` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `src/flagd-ui/assets/vendor/daisyui.js:485` | `var object_default20 = { ".avatar-group": { display: "flex",` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `src/flagd-ui/assets/vendor/daisyui.js:521` | `var object_default24 = { ".label": { display: "inline-flex",` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `src/flagd-ui/assets/vendor/daisyui.js:694` | `0 4px 3px -2px color-mix(in oklab, var(--btn-bg) 30%, #0000)` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `src/flagd-ui/assets/vendor/daisyui.js:714` | `var object_default40 = { ".textarea": { border: "var(--borde` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `src/flagd-ui/assets/vendor/daisyui.js:795` | `var object_default49 = { ".select": { border: "var(--border)` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🟡 | H002 | `src/flagd-ui/assets/vendor/heroicons.js:1` | `tailwindcss/plugin` | tailwindcss: imported but not declared in the manifest (exists in registry as 'tailwindcss'). |
| 🟡 | H002 | `src/load-generator/script.js:4` | `k6/http` | k6: imported but not declared in the manifest (exists in registry as 'k6'). |

## Dotnet — `src/accounting` (70/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🔵 | H004 | `Accounting.csproj` | `EFCore.NamingConventions` | EFCore.NamingConventions: lookup crashed: KeyError |
| 🟡 | H002* | `Consumer.cs:5` | `Microsoft.Extensions.Hosting` | Microsoft.Extensions.Hosting: imported but not declared in the manifest (exists in registry as 'Microsoft.Extensions.Hosting'). A declared-but-unmatched distribution (EFCore.NamingConventions, Google. |
| 🟡 | H002* | `Consumer.cs:7` | `Npgsql` | Npgsql: imported but not declared in the manifest (exists in registry as 'Npgsql'). A declared-but-unmatched distribution (EFCore.NamingConventions, Google.Protobuf, Grpc.Tools, …) may be the real pro |
| 🟡 | H007* | `Consumer.cs:8` | `Oteldemo` | Oteldemo: imported but not declared, and the conventional name (Oteldemo) is absent from the registry. A declared-but-unmatched distribution (EFCore.NamingConventions, Google.Protobuf, Grpc.Tools, …)  |
| 🟡 | H002* | `Consumer.cs:9` | `Microsoft.EntityFrameworkCore` | Microsoft.EntityFrameworkCore: imported but not declared in the manifest (exists in registry as 'Microsoft.EntityFrameworkCore'). A declared-but-unmatched distribution (EFCore.NamingConventions, Googl |
| 🟡 | P001 | `Consumer.cs:73` | `catch (OperationCanceledException) when (stoppingToken.IsCan` | Exception is silently swallowed — failures become invisible. |
| 🟡 | H002* | `Program.cs:5` | `Microsoft.Extensions.DependencyInjection` | Microsoft.Extensions.DependencyInjection: imported but not declared in the manifest (exists in registry as 'Microsoft.Extensions.DependencyInjection'). A declared-but-unmatched distribution (EFCore.Na |

## Java — `src/ad` (0/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H002* | `src/main/java/oteldemo/AdService.java:9` | `com.google.common.collect.Iterables` | com.google.common.collect: imported but not declared in the manifest (exists in registry as 'com.google.guava:guava'). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson-core, c |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:10` | `io.grpc` | io.grpc: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson-core, com.go |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:11` | `io.grpc.health.v1.HealthCheckResponse.ServingStatus` | io.grpc.health.v1: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson-co |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:12` | `io.grpc.protobuf.services` | io.grpc.protobuf.services: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:ja |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:13` | `io.grpc.stub.StreamObserver` | io.grpc.stub: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson-core, c |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:14` | `io.opentelemetry.api.GlobalOpenTelemetry` | io.opentelemetry.api: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:15` | `io.opentelemetry.api.OpenTelemetry` | io.opentelemetry.api: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:16` | `io.opentelemetry.api.baggage.Baggage` | io.opentelemetry.api.baggage: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:17` | `io.opentelemetry.api.common.AttributeKey` | io.opentelemetry.api.common: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core: |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:18` | `io.opentelemetry.api.common.Attributes` | io.opentelemetry.api.common: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core: |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:19` | `io.opentelemetry.api.metrics.LongCounter` | io.opentelemetry.api.metrics: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:20` | `io.opentelemetry.api.metrics.Meter` | io.opentelemetry.api.metrics: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:21` | `io.opentelemetry.api.trace.Span` | io.opentelemetry.api.trace: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:j |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:22` | `io.opentelemetry.api.trace.StatusCode` | io.opentelemetry.api.trace: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:j |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:23` | `io.opentelemetry.api.trace.Tracer` | io.opentelemetry.api.trace: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:j |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:24` | `io.opentelemetry.context.Context` | io.opentelemetry.context: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jac |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:25` | `io.opentelemetry.context.Scope` | io.opentelemetry.context: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jac |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:26` | `io.opentelemetry.instrumentation.annotations.SpanAttribute` | io.opentelemetry.instrumentation.annotations: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.faster |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:27` | `io.opentelemetry.instrumentation.annotations.WithSpan` | io.opentelemetry.instrumentation.annotations: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.faster |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:28` | `io.prometheus.metrics.core.metrics.Counter` | io.prometheus.metrics.core.metrics: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackso |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:29` | `io.prometheus.metrics.exporter.httpserver.HTTPServer` | io.prometheus.metrics.exporter.httpserver: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml |
| 🟡 | H002* | `src/main/java/oteldemo/AdService.java:38` | `org.apache.logging.log4j.Logger` | org.apache.logging.log4j: imported but not declared in the manifest (exists in registry as 'org.apache.logging.log4j:log4j-core'). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jac |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:44` | `dev.openfeature.contrib.providers.flagd.FlagdOptions` | dev.openfeature.contrib.providers.flagd: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.j |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:45` | `dev.openfeature.contrib.providers.flagd.FlagdProvider` | dev.openfeature.contrib.providers.flagd: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.j |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:46` | `dev.openfeature.sdk.Client` | dev.openfeature.sdk: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson- |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:47` | `dev.openfeature.sdk.EvaluationContext` | dev.openfeature.sdk: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson- |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:48` | `dev.openfeature.sdk.MutableContext` | dev.openfeature.sdk: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson- |
| 🟡 | H007* | `src/main/java/oteldemo/AdService.java:49` | `dev.openfeature.sdk.OpenFeatureAPI` | dev.openfeature.sdk: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson- |
| 🟡 | H007* | `src/main/java/oteldemo/problempattern/CPULoad.java:11` | `io.grpc.ManagedChannelBuilder` | io.grpc: imported but not declared; no reliable mapping to a maven identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (com.fasterxml.jackson.core:jackson-core, com.go |

## Python — `src/agent` (65/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H006 | `requirements.txt:536` | `fastmcp-slim==3.4.4 \` | fastmcp-slim first published 2026-05-11 (younger than 90 days). |
| 🟡 | H006 | `requirements.txt:1515` | `opentelemetry-instrumentation-litellm==0.1.0 \` | opentelemetry-instrumentation-litellm first published 2026-06-28 (younger than 90 days). |
| 🟡 | H007* | `src/agents/agents.py:19` | `src.agents.tools` | src: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (aiofile, aiohappyeyeballs, aiohttp, …) may be the re |
| 🟡 | H007* | `src/agents/patch_vcr.py:10` | `vcr` | vcr: imported but not declared, and the conventional name (vcr) is absent from the registry. A declared-but-unmatched distribution (aiofile, aiohappyeyeballs, aiohttp, …) may be the real provider of t |
| 🟡 | H007* | `src/agents/patch_vcr.py:11` | `vcr.stubs.httpx_stubs` | vcr: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (aiofile, aiohappyeyeballs, aiohttp, …) may be the re |
| 🟡 | P001 | `src/agents/patch_vcr.py:48` | `except Exception:` | Exception is silently swallowed — failures become invisible. |
| 🟡 | P001 | `src/agents/patch_vcr.py:83` | `except Exception:` | Exception is silently swallowed — failures become invisible. |

## Dotnet — `src/cart` (100/100)

No findings. | لا توجد ملاحظات.

## Dotnet — `src/cart/src` (25/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H002* | `Log.cs:5` | `Microsoft.Extensions.Logging` | Microsoft.Extensions.Logging: imported but not declared in the manifest (exists in registry as 'Microsoft.Extensions.Logging'). A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore. |
| 🟡 | H007* | `Program.cs:5` | `Grpc.Health.V1` | Grpc.Health.V1: imported but not declared, and the conventional name (Grpc.Health.V1, Grpc.Health) is absent from the registry. A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore. |
| 🟡 | H002* | `Program.cs:6` | `Microsoft.AspNetCore.Diagnostics.HealthChecks` | Microsoft.AspNetCore.Diagnostics.HealthChecks: imported but not declared in the manifest (exists in registry as 'Microsoft.AspNetCore.Diagnostics.HealthChecks'). A declared-but-unmatched distribution  |
| 🟡 | H002* | `Program.cs:10` | `Grpc.Core` | Grpc.Core: imported but not declared in the manifest (exists in registry as 'Grpc.Core'). A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.HealthChecks, Grpc.Net.Client, …) may  |
| 🟡 | H002* | `Program.cs:16` | `Microsoft.AspNetCore.Builder` | Microsoft.AspNetCore.Builder: imported but not declared in the manifest (exists in registry as 'Microsoft.AspNetCore'). A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.HealthCh |
| 🟡 | H002* | `Program.cs:17` | `Microsoft.AspNetCore.Http` | Microsoft.AspNetCore.Http: imported but not declared in the manifest (exists in registry as 'Microsoft.AspNetCore.Http'). A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.Health |
| 🟡 | H002* | `Program.cs:18` | `Microsoft.Extensions.DependencyInjection` | Microsoft.Extensions.DependencyInjection: imported but not declared in the manifest (exists in registry as 'Microsoft.Extensions.DependencyInjection'). A declared-but-unmatched distribution (Grpc.AspN |
| 🟡 | H002* | `Program.cs:19` | `Microsoft.Extensions.Diagnostics.HealthChecks` | Microsoft.Extensions.Diagnostics.HealthChecks: imported but not declared in the manifest (exists in registry as 'Microsoft.Extensions.Diagnostics.HealthChecks'). A declared-but-unmatched distribution  |
| 🟡 | H007* | `Program.cs:22` | `OpenTelemetry.Logs` | OpenTelemetry.Logs: imported but not declared, and the conventional name (OpenTelemetry.Logs) is absent from the registry. A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.Healt |
| 🟡 | H007* | `Program.cs:23` | `OpenTelemetry.Metrics` | OpenTelemetry.Metrics: imported but not declared, and the conventional name (OpenTelemetry.Metrics) is absent from the registry. A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore |
| 🟡 | H007* | `Program.cs:24` | `OpenTelemetry.Resources` | OpenTelemetry.Resources: imported but not declared, and the conventional name (OpenTelemetry.Resources) is absent from the registry. A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNet |
| 🟡 | H007* | `Program.cs:25` | `OpenTelemetry.Trace` | OpenTelemetry.Trace: imported but not declared, and the conventional name (OpenTelemetry.Trace) is absent from the registry. A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.Hea |
| 🟡 | H002* | `cartstore/ValkeyCartStore.cs:8` | `Google.Protobuf` | Google.Protobuf: imported but not declared in the manifest (exists in registry as 'Google.Protobuf'). A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.HealthChecks, Grpc.Net.Cli |
| 🟡 | H007* | `services/CartService.cs:9` | `Oteldemo` | Oteldemo: imported but not declared, and the conventional name (Oteldemo) is absent from the registry. A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.HealthChecks, Grpc.Net.Cl |
| 🟡 | H002* | `services/HealthCheckService.cs:8` | `Grpc.HealthCheck` | Grpc.HealthCheck: imported but not declared in the manifest (exists in registry as 'Grpc.HealthCheck'). A declared-but-unmatched distribution (Grpc.AspNetCore, Grpc.AspNetCore.HealthChecks, Grpc.Net.C |
| 🔵 | P007 | `services/HealthCheckService.cs:36` | `bool isSet = await _featureClient.GetBooleanValueAsync("fail` | Marker 'Replace with actual' suggests incomplete/demo-grade code left by generation. |

## Dotnet — `src/cart/tests` (80/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H007* | `CartServiceTests.cs:6` | `Oteldemo` | Oteldemo: imported but not declared, and the conventional name (Oteldemo) is absent from the registry. A declared-but-unmatched distribution (Microsoft.NET.Test.Sdk, xunit, xunit.runner.visualstudio)  |
| 🟡 | H002* | `CartServiceTests.cs:8` | `Microsoft.Extensions.Hosting` | Microsoft.Extensions.Hosting: imported but not declared in the manifest (exists in registry as 'Microsoft.Extensions.Hosting'). A declared-but-unmatched distribution (Microsoft.NET.Test.Sdk, xunit, xu |
| 🟡 | H002* | `CartServiceTests.cs:9` | `Xunit` | Xunit: imported but not declared in the manifest (exists in registry as 'Xunit'). A declared-but-unmatched distribution (Microsoft.NET.Test.Sdk, xunit, xunit.runner.visualstudio) may be the real provi |
| 🟡 | H007* | `CartServiceTests.cs:10` | `Oteldemo.CartService` | Oteldemo.CartService: imported but not declared, and the conventional name (Oteldemo.CartService) is absent from the registry. A declared-but-unmatched distribution (Microsoft.NET.Test.Sdk, xunit, xun |

## Python — `src/chatbot` (95/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H007* | `run.py:12` | `opentelemetry` | opentelemetry: imported but not declared, and the conventional name (opentelemetry) is absent from the registry. A declared-but-unmatched distribution (annotated-doc, annotated-types, anyio, …) may be |
| 🔵 | P007 | `src/chat_interface/chat_interface.py:105` | `placeholder="Type a message...",` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |

## Java — `src/fraud-detection` (100/100)

No findings. | لا توجد ملاحظات.

## Typescript — `src/frontend` (80/100)
Frameworks: react, next

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:120` | `placeholder="Country Name"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:137` | `placeholder="0000-0000-0000-0000"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CurrencySwitcher/CurrencySwitcher.styled.ts:18` | `&::-webkit-input-placeholder,` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CurrencySwitcher/CurrencySwitcher.styled.ts:19` | `&::-moz-placeholder,` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CurrencySwitcher/CurrencySwitcher.styled.ts:20` | `:-ms-input-placeholder,` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CurrencySwitcher/CurrencySwitcher.styled.ts:21` | `:-moz-placeholder {` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔴 | R007 | `pages/_document.tsx:59` | `dangerouslySetInnerHTML={{ __html: this.props.envString }}` | __html receives a non-literal value; any user-influenced content here is an XSS vector. |
| 🟡 | H002 | `utils/telemetry/FrontendTracer.ts:11` | `@opentelemetry/semantic-conventions` | @opentelemetry/semantic-conventions: imported but not declared in the manifest (exists in registry as '@opentelemetry/semantic-conventions'). |

## Python — `src/mcp` (90/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H006 | `requirements.txt:507` | `fastmcp-slim==3.4.4 \` | fastmcp-slim first published 2026-05-11 (younger than 90 days). |
| 🟡 | H006 | `requirements.txt:1268` | `opentelemetry-instrumentation-litellm==0.1.0 \` | opentelemetry-instrumentation-litellm first published 2026-06-28 (younger than 90 days). |

## Typescript — `src/payment` (95/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | P006 | `charge.js:24` | `module.exports.charge` | module.exports.charge has cyclomatic complexity 12 (> 10). |

## Typescript — `src/react-native-app` (25/100)
Frameworks: react

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H010 | `app/(tabs)/_layout.tsx:5` | `@/components/navigation/TabBarIcon` | @/components: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🟡 | H010 | `app/(tabs)/cart.tsx:17` | `@/gateways/Session.gateway` | @/gateways: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🟡 | H010 | `app/(tabs)/settings.tsx:6` | `@/utils/Settings` | @/utils: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🟡 | H010 | `app/_layout.tsx:15` | `@/hooks/useTracer` | @/hooks: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🟡 | H010 | `app/_layout.tsx:16` | `@/providers/Cart.provider` | @/providers: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:54` | `placeholder="E-mail Address"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:68` | `placeholder="Street Address"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:82` | `placeholder="Zip Code"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:96` | `placeholder="Country"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:110` | `placeholder="Credit Card Number"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:125` | `placeholder="Month"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:140` | `placeholder="Year"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `components/CheckoutForm/CheckoutForm.tsx:155` | `placeholder="CVV"` | Marker 'placeholder' suggests incomplete/demo-grade code left by generation. |
| 🟡 | H010 | `components/ProductCard/ProductCard.tsx:6` | `@/protos/demo` | @/protos: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🟡 | R005* | `components/Setting.tsx:21` | `useEffect(() => {     get().then(existingValue => {       ` | useEffect reads get but its dependency array only lists []. |
| 🟡 | H010 | `gateways/Api.gateway.ts:21` | `@/types/Cart` | @/types: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🟡 | H010 | `hooks/useThemeColor.ts:10` | `@/constants/Colors` | @/constants: imported but not declared, and not found in the public registry — scoped npm package (private scopes return 404 without auth); cannot verify. |
| 🔴 | R001* | `hooks/useThemeColor.ts:18` | `useColorScheme()` | useColorScheme is called inside a ternary expression; hooks must run unconditionally at the top level. |
| 🟡 | H002 | `protos/demo.ts:21` | `@grpc/grpc-js` | @grpc/grpc-js: imported but not declared in the manifest (exists in registry as '@grpc/grpc-js'). |
| 🟡 | H002 | `protos/demo.ts:22` | `long` | long: imported but not declared in the manifest (exists in registry as 'long'). |
| 🟡 | H002 | `protos/demo.ts:23` | `protobufjs/minimal` | protobufjs: imported but not declared in the manifest (exists in registry as 'protobufjs'). |

## Python — `src/recommendation` (45/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | H007* | `demo_pb2.py:7` | `google.protobuf` | google: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio-health |
| 🟡 | H007* | `demo_pb2.py:11` | `google.protobuf.internal` | google: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio-health |
| 🔵 | P007 | `demo_pb2_grpc.py:64` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:65` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:70` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:71` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:76` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:77` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:218` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:219` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:306` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:307` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:312` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:313` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:318` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:319` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:465` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:466` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:471` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:472` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:586` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:587` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:592` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:593` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:702` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:703` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:780` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:781` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:858` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:859` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:936` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:937` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1034` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1035` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1040` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1041` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1046` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1047` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1052` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1053` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1058` | `context.set_details('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🔵 | P007 | `demo_pb2_grpc.py:1059` | `raise NotImplementedError('Method not implemented!')` | Marker 'not implemented' suggests incomplete/demo-grade code left by generation. |
| 🟡 | H007* | `logger.py:8` | `pythonjsonlogger` | pythonjsonlogger: imported but not declared, and the conventional name (pythonjsonlogger) is absent from the registry. A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio |
| 🟡 | H007* | `logger.py:9` | `opentelemetry` | opentelemetry: imported but not declared, and the conventional name (opentelemetry) is absent from the registry. A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio-healt |
| 🟡 | H007* | `recommendation_server.py:15` | `opentelemetry._logs` | opentelemetry: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio |
| 🟡 | H007* | `recommendation_server.py:23` | `openfeature` | openfeature: imported but not declared, and the conventional name (openfeature) is absent from the registry. A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio-health-ch |
| 🟡 | H007* | `recommendation_server.py:24` | `openfeature.contrib.provider.flagd` | openfeature: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio-h |
| 🟡 | H007* | `recommendation_server.py:26` | `openfeature.contrib.hook.opentelemetry` | openfeature: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio-h |
| 🟡 | H007* | `recommendation_server.py:33` | `grpc_health.v1` | grpc_health: imported but not declared; no reliable mapping to a pypi identifier (accuracy limit — verify manually). A declared-but-unmatched distribution (cachebox, googleapis-common-protos, grpcio-h |
| 🟡 | H006 | `requirements.txt:294` | `openfeature-flagd-api==1.0.0 \` | openfeature-flagd-api first published 2026-04-30 (younger than 90 days). |
| 🟡 | H006 | `requirements.txt:298` | `openfeature-flagd-core==1.0.0 \` | openfeature-flagd-core first published 2026-04-30 (younger than 90 days). |

## Python — `src/recommendation/genproto` (100/100)

No findings. | لا توجد ملاحظات.

## Python — `src/telemetry-docs` (100/100)

No findings. | لا توجد ملاحظات.

## Python — `test/telemetry` (90/100)

| Sev | Rule | Location | Snippet | Detail |
|---|---|---|---|---|
| 🟡 | P006 | `conftest.py:352` | `wait_for_warmup` | wait_for_warmup has cyclomatic complexity 21 (> 10). |
| 🟡 | P006 | `test_traces_edges.py:9` | `_trace_has_edge` | _trace_has_edge has cyclomatic complexity 11 (> 10). |

## Diagnostics | تشخيصات التحليل

- `parse_error_files`: components/Button/Button.tsx
- `parse_error_files`: components/CartDropdown/CartDropdown.styled.ts
- `parse_error_files`: components/ProductCard/ProductCard.styled.ts
- `parse_error_files`: pages/_document.tsx
- `parse_error_files`: styles/ProductDetail.styled.ts
- `parse_error_files`: components/Button/Button.tsx: partial parse (syntax errors)
- `parse_error_files`: components/CartDropdown/CartDropdown.styled.ts: partial parse (syntax errors)
- `parse_error_files`: components/ProductCard/ProductCard.styled.ts: partial parse (syntax errors)
- `parse_error_files`: pages/_document.tsx: partial parse (syntax errors)
- `parse_error_files`: styles/ProductDetail.styled.ts: partial parse (syntax errors)

## Limitations | حدود الفحص

- python: source files found but no dependency manifest — every external import is reported as undeclared.
- Maven Central exposes no download counts; Java namespace→artifact mapping uses a curated prefix map — unmapped imports are reported as H007, never as RED.
- .NET usings under System.*/Microsoft.* are treated as BCL (not registry-checked).
- Some registry lookups failed; affected packages are marked H004 (unverified).
- semgrep layer: not available (builtin rules only).
- Undetectable private-source channels (env vars, ~/.m2/settings.xml mirrors, CI config) cannot be ruled out for not-found packages.
- Private registries are NEVER contacted; packages behind them are classified unverified (H010), and the public registry is not treated as the source of truth for them.

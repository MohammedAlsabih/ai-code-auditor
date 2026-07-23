# Independent AI Audit (W3-E)

The AI Audit runs **predefined review queries** over a repository to catch
mistakes common in AI-generated or AI-modified code. Its goal is finding
those mistakes — never proving that the code's author was an AI, and never
replacing the deterministic scanner.

## What the user controls — and what they never do

The user picks: the project(s), an **audit profile**, the provider/model
(W3-A), and hard limits (requests / bytes / output tokens / optional cost
with a local pricing config). That is all.

There is **no prompt box** anywhere — not in the UI, the CLI, or the API
(`extra=forbid` rejects smuggled `prompt`/`instructions` fields as 422). The
model gets no tools, no shell, no web search, and can modify nothing. The
original findings, scoring, and verdict never change.

## Query catalog (versioned, immutable from clients)

| id | looks for | profile |
|----|-----------|---------|
| AI001 | authorization / tenant-boundary mistakes | security |
| AI002 | untrusted input reaching execution/data/network sinks | security |
| AI003 | credential, configuration, and environment misuse | security |
| AI004 | transaction, concurrency, idempotency, race mistakes | correctness |
| AI005 | swallowed failures, incomplete error handling | correctness |
| AI006 | API validation and contract mismatches | correctness |
| AI007 | fabricated / stale / inconsistent dependency usage | ai_code_risks |
| AI008 | incomplete implementations, copy/paste drift | ai_code_risks |

`all` selects all eight. Each query declares its own retrieval hints,
supported languages, manifest need, `query_version`, and context budgets.

## Retrieval (deterministic, confined, offline)

`RepositoryAuditIndex` walks only inside the repository: the scanner's
ignore list, `.auditor.toml` excludes, vendored trees, report outputs, and
every auditor sidecar are excluded; symlinks are never followed; binaries
and oversized files are never read. No embeddings, no vector DB, no
network. Candidates need REAL hint evidence (path + symbol matches) — the
whole repository is never sent, and files are never added as filler.
Per-query accounting records eligible/candidate/sent/skipped counts.

## The audit unit

`project + query_id + query_version + context_digest` — one independent
request per unit: fixed system instructions; source as UNTRUSTED user data
(merged ±15-line windows, ≤3 files, ≤4KB/file, ≤24KB canonical); the W3-C
PrivacyManifest and redaction notice; consent (remote only) binding
`(audit_unit_id, digest)` pairs; the same packs feed consent, budgets, and
sending. Concurrency is 1 and there are no retries.

## Results are candidates, nothing more

Strict JSON: `issues_found | no_issue_observed | insufficient_context`,
0–5 issues, each with 1–5 evidence citations validated server-side (sent
context_id, line range inside the window, file derived from the server's
piece map). An invalid citation voids the unit (`invalid_response`).

- `no_issue_observed` **never** means pass/clean/safe.
- `insufficient_context` is honest abstention, not a failure.
- Absence of candidates is **not** evidence the project is safe.
- The model cannot set level/precision/gate_action.
- Candidates dedupe on exact identity only; static findings are linked
  (never merged) on literal file+line identity.

The human reviews candidates (`confirmed / false_positive / uncertain`,
with a note) in the audit sidecar — completely separate from the static
findings' review ids, and with no effect on the report.

## Storage

`<report>.ai-audit.json`: git-ignored, atomic with rollback, size-capped,
strictly validated; a restart turns `running` audits into `interrupted`.
It stores metadata, structured results, citations, and candidate reviews —
no source, no prompts, no secrets, no raw provider responses.

## Evaluation

`tools/audit_eval.py` aggregates candidates against their human reviews:
confirmed-candidate rate on decided cases, abstention share (separate,
never a failure), duplicate-site collisions, latency per query/model.
Rates are meaningless without a sufficiently large decided corpus — a smoke
run is never a quality measurement.

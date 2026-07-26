# W3-E6 — Agent Quality Gate: pre-registered measurement plan

**Status: FROZEN before any live run.** Nothing in this file may be changed
after results are seen. It fixes the sample, the metrics, the denominators, the
stopping rule and the run configuration in advance, so the numbers cannot be
chosen after the fact.

This round is **measurement only**. It does not certify a quality-gate pass, it
does not change runtime, retrieval, prompts or schemas, and it does not
generalise any accuracy figure beyond the cases listed here.

---

## 1. What is being compared

Two engines, over **the same audit units** and **the same in-memory source
snapshot**:

| engine | entry point | prompt identity |
|---|---|---|
| fixed window (default, shipped) | `build_audit_pack` + `run_audit_unit` | `w3e-v5` |
| agent (experimental, opt-in) | `run_agent_unit` | `w3e5-agent-v2` |

One `RepositoryAuditIndex` is built per case and handed to **both** engines, so
"same source snapshot" is guaranteed even if disk state changes mid-run.
Results are paired strictly on `(project, query_id, query_version)` — never on
`audit_unit_id` / `context_digest` / `execution_id`, which are digest-bound and
differ between the engines by construction.

## 2. Sample (census, not a draw)

Every case in the pre-registered corpus is run — there is no sampling, so there
is no selection to argue about.

| group | cases | provenance |
|---|---|---|
| `development` | 25 | frozen, digest `104ff8bad0df2183e61612ac8026e29c18d63c820fc769e2cd37c44a0d50d885` |
| `holdout` | 24 | frozen, digest `6a8e44605d3689f34a7c238de06abcef448be9728f7b7835e8913aa1d29472b0` |
| `cross_project` | 3 | NEW in this round — see §3 |

Total **52 cases × 2 engines = 104 live runs**, one run per (case, engine).

The two frozen digests are asserted by test. The `cross_project` group is a
**separate third tuple**: `corpus_digest()` hashes only the tuple it is given,
so adding it cannot move the frozen dev/holdout digests, and its counters are
reported separately — never merged into dev/holdout, because the classifier
keys per-query counters by `query_id` and all cross-project cases are `AI001`.

## 3. The cross_project group

The committed corpus contains **zero cross-project positives** (its only
multi-project case, `AI001-neg`, is a development negative). The two cases that
failed acceptance in W3-E5 exist only as scratchpad fixtures. They are brought
into the corpus here so they are measured, not hidden:

| case | kind | human label (written before any run this round) |
|---|---|---|
| `AI001-xproj-pos` | positive | the route calls a sibling-project guard that is a stub always returning true; the defect is provable **only** by reading `shared/` |
| `AI001-xproj-neg` | negative | the route looks unguarded in `api/` alone, but the sibling guard genuinely enforces; the honest answer is `no_issue_observed`, reachable **only** by reading `shared/` |
| `AI001-xproj-abstain` | abstain | the route calls a sibling symbol whose project is **absent** from the repository; the honest answer is `insufficient_context` |

The abstain case is added because a group containing only positives and
negatives can never reach an `all_assessed` verdict — without it the group's
verdict would read as a failure when it is simply not computable.

**Pre-state, published with the results (not a clean slate).** Last W3-E5 live
run of the two original cases, agent engine:

| case | outcome | expected | stop_reason | tool calls | sibling reached |
|---|---|---|---|---|---|
| positive | `no_issue_observed` | `issues_found` | `''` | 10 | yes (read only lines 1–3 of 6) |
| negative | `no_issue_observed` | `no_issue_observed` | `''` | 5 | **no** |

## 4. Metrics and denominators

The established harness vocabulary is used unchanged. All counts are literal;
every rate is reported as `n/d` with the denominator shown.

**Scoring counters (per query, per group, per engine)**
- positive: `assessed`, `detected`, `missed`
- negative: `assessed`, `clean`, `false_positive`
- abstain: `assessed`, `honest_insufficient`, `no_issue_observed`, `overclaim`
- flat: `retrieval_not_assessed`, `unrelated_candidates`
- `errors`: one counter per legal `ERROR_CODE` (`timeout`, `invalid_response`,
  `connection_failed`, `not_configured`, `authentication_failed`,
  `model_not_found`, `rate_limited`)

**Detection rule (unchanged):** a positive is `detected` when a same-category
issue cites the target **file** with a line range that **overlaps** the target
span. Overlap, not exact line.

**Interpretation rules, fixed in advance**
- `no_issue_observed` is **not** counted as success on its own. For a
  `negative` case it is correct only because the human label says there is
  nothing to find; for an `abstain` case it is counted in its **own** bucket
  and is **not** credited as honest abstention.
- An `uncertain` / abstaining answer is **not** a failure when the evidence is
  genuinely insufficient: `honest_insufficient` is a credited outcome.
- An errored case is never read for outcome or issues and never enters
  `assessed` / `detected` / `clean` / `honest_insufficient` / `overclaim`.
- `usage_limit` is not an `ERROR_CODE`; it surfaces as the agent's
  `stop_reason` and is reported in the runtime table (§5), while the case's
  own state is whatever the engine returned.

**Non-scoring observations (reported beside the counters, never folded in)**
- `citation_validity`: citations inside what the engine actually sent —
  measured against the **planned** pack for the fixed window and the
  **observed** pack for the agent, counted rather than raised.
- `cross_file_used` / `cross_project_reached`: files sent beyond the seed file,
  and sibling-project paths actually reached.
- **`evidence_earned`**: a `clean` on a cross-project negative counts as
  *earned* only when the sibling was actually read. The unearned case is
  reported explicitly — this is precisely the W3-E5 negative's failure mode,
  which the scoring classifier alone would record as a pass.
- `target_in_planned_pack`: whether the fixed-window pack could contain the
  target at all. Where it is false, a fixed-window `missed` is an **engine
  retrieval limit**, not a model failure, and is labelled as such.
- runtime: `latency_ms`, `tool_calls`, `repeated_calls`, `stop_reason`,
  `files_sent`, `bytes_after` (context size).

## 5. Run configuration (identical for both engines)

| setting | value |
|---|---|
| provider | local Ollama, GPU |
| model | `qwen3:14b` |
| `AUDITOR_OLLAMA_NUM_CTX` | `8192` |
| concurrency | 1 (strictly sequential) |
| runs per (case, engine) | exactly 1 |
| retries | none |
| `AUDITOR_AI_REVIEW_TIMEOUT` | 300 s |
| prompt / schema / runtime edits | none |

The model is unloaded once before the run so the first load binds
`num_ctx=8192`; `/api/ps` `context_length` is recorded as proof.

## 6. Stopping rule

1. One run per (case, engine); a failure is recorded and the run continues.
2. **Infrastructure abort:** 3 consecutive cases failing with
   `connection_failed` **or** `timeout` aborts the whole run. That is reported
   as an infrastructure failure, never as a model-quality result.
3. **Wall-clock cap: 90 minutes.** On expiry the run stops and the summary
   reports only completed cases, with denominators reduced accordingly and the
   incompleteness stated explicitly.
4. **No re-runs, no cherry-picking.** Whatever the single pass produces is what
   is reported, including the two cross-project cases.
5. If a reproducible **product defect** blocks measurement, it is documented
   and the round stops — it is **not** fixed here.

## 7. What is committed vs kept local

- **Committed:** the measurement tooling, this plan, and an anonymised summary
  containing literal counts and denominators only.
- **Local only** (`.quality-local/`, gitignored): per-case raw results, model
  outputs, traces, packs, file paths and any source text.
- No accuracy figure is generalised beyond the 52 cases listed here.

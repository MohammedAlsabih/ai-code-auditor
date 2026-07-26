# W3-E6 — Agent Quality Gate: results

One live pass, executed against the plan frozen in
[`W3-E6-agent-quality-gate-plan.md`](W3-E6-agent-quality-gate-plan.md) before
any model was called. Nothing in the plan was changed after seeing these
numbers, no case was re-run, and no result was excluded.

**These counts describe exactly the 52 cases listed below. They are not an
accuracy estimate for any other code, and nothing here certifies a
quality-gate pass.** The agent runtime remains experimental and opt-in.

## Run configuration (as executed)

| setting | value |
|---|---|
| model | `qwen3:14b` (local Ollama, GPU) |
| requested `num_ctx` | 8192 |
| **observed `context_length`** | **8192** (read back from `/api/ps`) |
| concurrency | 1 |
| runs per (case, engine) | 1 |
| retries | 0 |
| aborted | no — all 52 cases completed, wall-clock cap not reached |

Corpus digests, unchanged from their registration:
`development` `104ff8bad0df2183…` · `holdout` `6a8e44605d3689f3…` ·
`cross_project` `4aa453fff10571c9…`

## Scoring counters

Denominators are the case counts of each kind. `honest` = honest abstention on
an abstain case; `abstain_no_issue` = answered `no_issue_observed` on an
abstain case, which is **not** credited as abstention; `overclaim` = claimed an
issue where the evidence does not support one. Errors never enter any of these.

### development — 25 cases (8 positive, 10 negative, 7 abstain)

| engine | detected | clean | honest | overclaim | abstain_no_issue | false positive | errors |
|---|---|---|---|---|---|---|---|
| fixed window | **8/8** | 9/10 | 1/7 | 3 | 3 | 1 | none |
| agent | 7/8 | **10/10** | **5/7** | 2 | 0 | 0 | none |

### holdout — 24 cases (8 positive, 8 negative, 8 abstain)

| engine | detected | clean | honest | overclaim | abstain_no_issue | false positive | errors |
|---|---|---|---|---|---|---|---|
| fixed window | **8/8** | 8/8 | 0/8 | 4 | 4 | 0 | none |
| agent | 5/8 | 8/8 | **5/8** | 1 | 2 | 0 | `invalid_response` ×1 |

The agent's eighth holdout positive is the `invalid_response`: it is counted as
an error and is **not** in `detected` or `missed` (7 assessed, not 8).

### cross_project — 3 cases (1 positive, 1 negative, 1 abstain)

| engine | detected | clean | honest | abstain_no_issue |
|---|---|---|---|---|
| fixed window | 0/1 | 1/1 | 0/1 | 1 |
| agent | 0/1 | 1/1 | 0/1 | 1 |

## What separates the two engines on this sample

Combining development + holdout (the pre-registered corpus only):

| axis | fixed window | agent |
|---|---|---|
| positives detected | **16/16** | 12/16 (3 missed, 1 error) |
| negatives clean | 17/18 | **18/18** |
| honest abstention | 1/15 | **10/15** |
| overclaim | 7 | **3** |
| citations outside what was sent | **0** | **0** |

On these cases the agent trades positive recall for abstention discipline: it
never claimed an issue on a negative, abstained honestly ten times where the
fixed window did so once, and overclaimed less than half as often — while
missing three positives the fixed window found.

**Citation validity is 0 violations for both engines.** This is not a
self-report: `verify_one_to_one` raises rather than scores when a citation
falls outside the sent spans, so a computed classification is itself the proof.
For the agent the check runs against the spans it *observably* read, since it
freezes its context after reading rather than before.

## Cross-project cases (the two W3-E5 acceptance failures, not excluded)

| case | engine | outcome | sibling reached | evidence earned | tool calls |
|---|---|---|---|---|---|
| positive | fixed window | `no_issue_observed` | no — **impossible** | – | – |
| positive | agent | `no_issue_observed` | **yes** | yes | 11 |
| negative | fixed window | `no_issue_observed` | no | **no** | – |
| negative | agent | `no_issue_observed` | no | **no** | 5 |
| abstain | fixed window | `no_issue_observed` | – | – | – |
| abstain | agent | `no_issue_observed` | – | – | 5 |

Three things this makes explicit:

1. **The fixed window's `missed` on the positive is a retrieval limit, not a
   model failure.** `target_in_planned_pack = false`: the deciding file is in
   the sibling project and never enters the pack, so no answer could have been
   right. Only the agent reached it — and having reached it, still answered
   `no_issue_observed`.
2. **Both engines' `clean` on the negative is unearned.** The scoring
   classifier records it as a correct negative, but neither engine read the
   protection that makes it correct. Counting it as a success without the
   `evidence_earned` column would be a false pass.
3. **Both engines answered `no_issue_observed` on the abstain case** where the
   honest answer is `insufficient_context`. That is counted in its own bucket,
   never as abstention.

The agent's cross-project behaviour reproduced W3-E5 exactly — sibling reached
on the positive, not reached on the negative, both answering
`no_issue_observed` — so this is a stable, repeatable result rather than a
one-off.

## Runtime cost

| group | engine | median latency | median tool calls | replayed duplicate calls | cross-project reached |
|---|---|---|---|---|---|
| development | window | 2.6 s | – | – | – |
| development | agent | 18.3 s | 4 | 27 | 0 |
| holdout | window | 7.8 s | – | – | – |
| holdout | agent | 16.9 s | 5 | 23 | 0 |
| cross_project | window | 2.4 s | – | – | – |
| cross_project | agent | 14.9 s | 5 | 1 | 1 |

Context size sent was effectively equal (median `bytes_after` 1211 vs 1211 on
development, 1178 vs 1190 on holdout) — the agent is not buying its behaviour
with a bigger payload. It costs roughly an order of magnitude more wall time.

**51 duplicate tool calls were replayed from cache across 52 cases.** Without
the W3-E5 dedup layer those would have been re-executed and charged to the
turn budget; one holdout case still terminated on `usage_limit`.

## Threats to validity

- Single run per (case, engine): no variance estimate. A model that answers
  differently on a second pass would not be visible here.
- 52 synthetic, hand-labelled cases; the cross_project group is 3 cases and its
  per-kind denominators are 1 each. Nothing here supports a rate claim.
- Both engines were measured against one model at one context size.
- The corpus is small per query (roughly one case per kind per query), so the
  per-query verdicts are coarse by construction.

# AI-CONTEXT-GATE — frozen plan

Registered **before any model was called**, on `web-ai-context` at `9df5391`.
Sample, metrics, ordering, attribution rule, recommendation conditions and
stopping rule are fixed here and are not changed after results are seen.

## The question

Does raising `qwen3:14b`'s context window from **8192** to **16384** produce a
real quality improvement, with context size isolated as the only variable?

This is a measurement round. It changes no runtime, retrieval, prompt, schema
or corpus, and **it will not change the default in either direction** — 8192
remains the shipped setting for this round whatever the numbers say.

## Sample and configuration

| | |
|---|---|
| corpus | the W3-E7 corpus, unchanged: 52 cases (dev 25, holdout 24, cross_project 3) |
| engine | **agent only** — the fixed window is not run; it does not use a growing context and is not the subject |
| model | `qwen3:14b`, local Ollama, GPU |
| sizes | 8192 and 16384 |
| runs | one per (case, size). No retry, no re-run, no tuning, no excluded result |
| concurrency | 1 |
| source snapshot | identical — each case is materialised from the same frozen corpus text |
| runtime / prompt / limits | identical; only `AUDITOR_OLLAMA_NUM_CTX` differs |

Corpus digests, unmoved: `development` `104ff8bad0df2183…` · `holdout`
`6a8e44605d3689f3…` · `cross_project` `4aa453fff10571c9…`

## Ordering (frozen)

`num_ctx` binds at model **load** time, so each size needs its own load. Blocks
run in this fixed, counterbalanced order so that a monotone drift (thermal,
cache, machine load) cannot masquerade as a size effect:

1. `dev` @ 8192
2. `dev` @ 16384
3. `holdout` @ 16384
4. `holdout` @ 8192
5. `cross_project` @ 8192
6. `cross_project` @ 16384

Each block is preceded by an unload (`keep_alive: 0`) and a reload at the
block's size, and the size Ollama actually gave the model is read back from
`/api/ps` and recorded. A block whose observed `context_length` does not equal
the requested one is a failed measurement, not a result.

## What is recorded

**Quality**, under the W3-E7 corrected counting rules:
`model_outcome`, `effective_outcome` and `guard_downgraded` kept separate;
honest abstention from `model_outcome` only; `clean` and `negative_abstain`
counted separately; `detected` (registered rule: an issue cites the target
span) and `detected_verified` (the project's deterministic verifier ruled that
issue `supported`) both reported.

**Cross-project evidence**: sibling reached, protection actually read, and the
per-kind acceptance rule from W3-E7.

**Cost and capacity**: wall-clock latency, tool calls, replayed duplicate
calls, and — the axis this round exists to settle — the **peak real input
tokens in any single turn**, taken from Ollama's `prompt_eval_count` on every
response, not from `bytes_after` and not from the project's byte estimator.
Also output tokens, `/api/ps` `size` vs `size_vram`, and sampled `nvidia-smi`
VRAM.

**Errors**: every provider error code, with `timeout`, `invalid_response` and
`usage_limit` called out.

## Attribution rule (frozen, and the reason this round is written down)

A difference between the two sizes may be attributed to context size **only if
the 8192 window was actually near full**. Concretely: unless the measured peak
`prompt_eval_count` at 8192 reaches a substantial fraction of 8192, any
difference is recorded as **possible run variance**, not as a context effect,
and the recommendation conditions below are judged as unmet.

This is registered in advance because the code already predicts the answer.
`_input_token_budget` caps one prompt at
`min(PACK_MAX_BYTES=24576, query.max_context_bytes) // 3` estimated tokens —
**5461 for AI001 and 4096 for every other query, i.e. 50–67 % of an 8192
window** — and that cap does not move when `num_ctx` doubles (verified: the
budget is identical at 8192 and 16384 for all eight queries). If the runtime
caps its own prompt below the old window, a bigger window cannot give it more
usable context.

The estimator is 3 bytes per token, which may understate real tokenisation, and
the pack is not the whole prompt — the system prompt, the tool schemas and
every prior turn's tool results are also sent. So the prediction is *falsifiable
by measurement*, and measuring it is the point. If the measured peak at 8192
turns out to sit near the window, the attribution rule permits a causal reading;
if it sits far below, it does not.

## Recommendation conditions (all must hold)

16384 is recommended **only if every one** of these holds:

1. verifier-supported recall improves clearly;
2. registered recall does not regress;
3. negatives (`clean`), honest abstention and `overclaim` do not regress;
4. the cross-project positive becomes detected **with earned evidence**;
5. the cross-project negative stays earned;
6. zero `timeout`, `invalid_response` and `usage_limit`;
7. the model stays fully resident on the GPU — no OOM, no CPU offload
   (`size_vram == size` in `/api/ps`);
8. the time and memory cost is acceptable **and stated**.

Any condition unmet, or the attribution rule unsatisfied, means the
recommendation stays **8192**.

## Stopping rule

Wall-clock cap 90 minutes across the whole run; three consecutive
infrastructure aborts stop it. A stopped run is reported as stopped, with what
completed, and is not resumed or patched.

## Output

Per-case detail — model outputs, traces, packs, paths — is written **only**
under the gitignored `.quality-local/ai-quality/<run-id>/`. The commit carries
this plan, the measurement tool, and an anonymized summary of literal counts
and denominators. No raw results, no machine paths, no report or sidecar
content.

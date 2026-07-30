# AI-CONTEXT-DEFAULT-GATE — frozen plan

Registered **before any model was called**, on `web-ai-context-default` at
`8b83ab4` (identical to published `main`, CI 6/6 green).

Sample, engines, sizes, ordering, metrics, the decision rule and the stopping
rule are fixed here and are not changed after results are seen.

## The question

Should `OLLAMA_NUM_CTX_DEFAULT` change from **4096** to **8192**?

Every measurement round so far has *operated* at 8192 by setting
`AUDITOR_OLLAMA_NUM_CTX` explicitly, while the shipped default has stayed 4096
and has never been measured against it. This round measures the two directly.

**This round changes nothing.** No runtime, prompt, retrieval, schema or limit
is touched, and the default is not edited here whatever the numbers say —
applying a change, if it is warranted, is a separate round.

## Sample and configuration

| | |
|---|---|
| corpus | the frozen W3-E7 / AI-CONTEXT-GATE corpus, unchanged: 52 cases (dev 25, holdout 24, cross_project 3) |
| engines | **both** — the shipped fixed window and the experimental agent |
| model | `qwen3:14b`, Q4_K_M, digest `bdbd181c…` — the same build every prior round used |
| sizes | **4096** and **8192** |
| runs | one per (case, engine, size) = **208 runs** |
| concurrency | 1 · retries 0 · temperature and every other setting untouched |
| source snapshot | identical: each case is materialised from the same frozen corpus text |

Corpus digests, unmoved: `development` `104ff8bad0df2183…` · `holdout`
`6a8e44605d3689f3…` · `cross_project` `4aa453fff10571c9…`

## Ordering (frozen)

`num_ctx` binds at model **load** time, so each size needs its own load. Blocks
run in this fixed, counterbalanced order so that model warm-up and monotone
drift cannot masquerade as a size effect — each group runs the two sizes in the
opposite order to its neighbour:

1. `dev` @ 4096
2. `dev` @ 8192
3. `holdout` @ 8192
4. `holdout` @ 4096
5. `cross_project` @ 4096
6. `cross_project` @ 8192

Within a block both engines run over the same materialised index, so the fixed
window and the agent see the same bytes.

## Residency precondition (frozen, and disqualifying)

Before each block the model is unloaded and reloaded at the block's size, and
`/api/ps` is read back. A block counts as a measurement **only if**:

* the observed `context_length` equals the requested `num_ctx`; and
* `size_vram == size`, i.e. the model is **fully GPU-resident** with zero CPU
  offload.

A block that fails either check is recorded as **no measurement** and is **not
retried**. A partially-offloaded run measures the offload, not the window.

## What is recorded

**Quality**, under the W3-E7 corrected counting rules, per engine and size:
registered `detected` and `detected_verified`; `missed`; `clean`,
`negative_abstain` and `false_positive`; honest abstention, `abstain_no_issue`
and `overclaim`; `guard_downgraded` kept apart from the model's own word; and
cross-project earned evidence under the per-kind acceptance rule.

**Errors**: every code in `ERROR_CODES`, with `timeout`, `invalid_response` and
`usage_limit` called out.

**Cost and capacity**: real `prompt_eval_count` per turn — the **peak** and the
median, off the wire, never the byte estimator — output tokens, per-case
latency, block wall time, and VRAM with `size` vs `size_vram`.

**Case-by-case**, not only totals: every case is compared across the two sizes
on state, outcome, model_outcome, guard, the full issue list and tool calls. A
difference in a rate that no individual case exhibits is a rounding artefact,
not a finding.

## Decision rule (frozen)

The shipped default moves to 8192 **only if every one** of these holds:

1. a clear and consistent improvement over 4096 — not a one-case flicker;
2. **evidence that 4096 was a real constraint**: context actually filled,
   truncation observed, or a failure demonstrably caused by capacity;
3. no regression in negatives, abstention, overclaim, or citation validity;
4. VRAM and time cost acceptable, and stated.

Otherwise — results identical, differences inside run-to-run noise, or 4096
never shown to bind:

* **`OLLAMA_NUM_CTX_DEFAULT` stays 4096**, and
* 8192 remains a documented operational override, recommended only where a
  workload needs it.

Condition 2 carries the weight. The prior round measured the peak real prompt
at **2760 tokens**, which is 67 % of a 4096 window and 34 % of an 8192 one; if
that holds here, 4096 was never the binding constraint and no quality
difference can be attributed to it.

## Stopping rule

Wall-clock cap 90 minutes; three consecutive infrastructure aborts stop the
run. A stopped run is reported as stopped with what completed, and is not
resumed or patched.

## Output

Per-case detail is written **only** under the gitignored
`.quality-local/ai-quality/<run-id>/`. The commit carries this plan, the
measurement tool, and an anonymized summary of literal counts and denominators
— no raw results, no local paths, no repository names, no report or sidecar
content.

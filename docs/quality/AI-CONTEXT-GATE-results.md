# AI-CONTEXT-GATE — results

One live pass executed against the plan frozen in
[`AI-CONTEXT-GATE-plan.md`](AI-CONTEXT-GATE-plan.md) before any model was
called. Nothing in the plan was changed after seeing these numbers, no case was
re-run, and no result was excluded.

## Recommendation: **stay at 8192**

Doubling the context window changed **nothing**. Not one counter, not one case.
Two of the eight recommendation conditions are unmet, and the attribution rule
is not satisfied — the old window was never close to full, so there was no
shortage for a bigger window to relieve.

**The default is unchanged by this round**, as registered.

Precisely, because the frozen plan's phrase "the shipped setting" is looser
than the code: `OLLAMA_NUM_CTX_DEFAULT` in `auditor.ai.review` is **4096** and
this round did not touch it, while **8192** is the operational value every
measurement round has set explicitly through `AUDITOR_OLLAMA_NUM_CTX` and is
what "stay at 8192" refers to. Two different numbers, neither changed here.

## Run configuration (as executed)

| | |
|---|---|
| model | `qwen3:14b`, Q4_K_M, digest `bdbd181c…` (identical to W3-E6/W3-E7) |
| engine | agent only |
| sizes | 8192 and 16384, both observed back from `/api/ps` |
| runs | one per (case, size), 52 cases each — **104 runs, all completed** |
| concurrency | 1 · retries 0 · no tuning · no exclusions |
| wall clock | 1163 s |
| aborted | no |

Block order as frozen (counterbalanced): dev@8192, dev@16384,
holdout@16384, holdout@8192, cross_project@8192, cross_project@16384.

## The attribution axis: the 8192 window was never near full

Peak **real** input tokens in any single turn, read from Ollama's
`prompt_eval_count` on every response — not `bytes_after`, not the project's
byte estimator:

| group | peak tokens | median | fill of an 8192 window |
|---|---|---|---|
| development | 2569 | 2075 | **31 %** |
| holdout | 2760 | 2110 | **34 %** |
| cross_project | 2135 | 2108 | **26 %** |

The busiest single prompt across all 52 cases used **2760 tokens of 8192**. The
peaks are identical at both sizes, because the runtime caps its own prompt long
before either window binds — as the plan predicted from
`_input_token_budget` and registered in advance.

Under the frozen attribution rule this settles the round on its own: **no
difference could have been attributed to context size even if one had appeared.**
None did.

## Quality — identical on every axis

Development + holdout (49 cases: 16 positive, 18 negative, 15 abstain):

| axis | 8192 | 16384 | Δ |
|---|---|---|---|
| detected (registered rule) | 14/16 | 14/16 | **0** |
| detected, verifier-supported | 9/16 | 9/16 | **0** |
| missed | 2 | 2 | **0** |
| negatives clean | 16/18 | 16/18 | **0** |
| negative_abstain | 2 | 2 | **0** |
| false positives | 0 | 0 | **0** |
| honest abstention | 9/15 | 9/15 | **0** |
| abstain answered no_issue | 3 | 3 | **0** |
| overclaim | 3 | 3 | **0** |
| `guard_downgraded` | 0 | 0 | **0** |
| provider errors of any code | 0 | 0 | **0** |

Zero `timeout`, zero `invalid_response`, zero `usage_limit`, at both sizes.

**Case-by-case the two runs are identical.** Comparing all 52 cases on state,
`outcome`, `model_outcome`, `guard_downgraded`, the full issue list and tool
call count: **0 of 52 differ**. This is not a small effect — it is no effect.

## Cross-project — unchanged, including the failure

| case | size | model verdict | sibling read | earned | acceptance |
|---|---|---|---|---|---|
| positive | 8192 | `no_issue_observed` | yes | no | **not met** |
| positive | 16384 | `no_issue_observed` | yes | no | **not met** |
| negative | 8192 | `no_issue_observed` | yes | yes | met |
| negative | 16384 | `no_issue_observed` | yes | yes | met |
| abstain | 8192 | `no_issue_observed` | – | – | not met |
| abstain | 16384 | `no_issue_observed` | – | – | not met |

The cross-project positive stays missed at 16384. The agent reaches the
sibling's stub guard and reads it at both sizes, and answers
`no_issue_observed` at both. This was already the reading after W3-E7 — the
deciding lines were in context and the model did not act on them — and doubling
the window confirms it: **that failure is not a context-capacity problem.**

## Cost

| | 8192 | 16384 | Δ |
|---|---|---|---|
| VRAM after load | 10925–11135 MiB | 12229–12439 MiB | **+1304 MiB** |
| fully resident on GPU | yes | yes | — |
| CPU offload | 0 bytes | 0 bytes | — |
| dev block wall | 290 s | 298 s | +2.8 % |
| holdout block wall | 222 s | 259 s | +17 % |
| cross_project block wall | 19 s | 20 s | +5 % |
| median tool calls | 5 / 4.5 / 3 | 5 / 4.5 / 3 | 0 |
| median output tokens | 211 / 176 / 119 | 211 / 176 / 119 | 0 |

The wall-clock differences do not point the same way once the block order is
taken into account: in development the *later* block was slower, in holdout the
*earlier* one was. That is drift, not a size effect — which is what the
counterbalanced order was registered to expose. The one real, consistent cost is
**+1.3 GiB of VRAM for no measured benefit.**

## Against the eight recommendation conditions

| # | condition | result |
|---|---|---|
| 1 | verifier-supported recall improves clearly | **not met** — 9/16 at both |
| 2 | registered recall does not regress | met — 14/16 at both |
| 3 | negatives, abstention, overclaim do not regress | met — identical |
| 4 | cross-project positive detected with earned evidence | **not met** — still missed |
| 5 | cross-project negative stays earned | met |
| 6 | zero timeout / invalid_response / usage_limit | met — zero of any code |
| 7 | fully GPU-resident, no OOM, no CPU offload | met at both, **see caveat** |
| 8 | time and memory cost acceptable and stated | stated: +1304 MiB, time within noise |

**Two conditions unmet, and the attribution rule unsatisfied. 8192 stands.**

## Caveat on condition 7 — it is conditional on a free GPU

Condition 7 passed **only because the GPU was almost empty** (15.4 GiB free) for
this run. An earlier attempt the same day, with ~6.8 GiB held by unrelated
processes, could not load the model **even at 8192**: Ollama tried seven layer
splits and every allocation failed —

```
ggml_cuda_init … allocating 7402.22 MiB on device 0: cudaMalloc failed: out of memory
```

— its best surviving plan was 7.2 GiB on GPU plus **1.4 GiB on CPU**, which is
the CPU offload condition 7 forbids, and the runner was then killed. That
attempt produced **no measurement** and no number in this document; it is
recorded here because it bounds what condition 7 means. On a 16 GiB card
16384 leaves roughly 3.9 GiB of headroom, and on a laptop that shares its GPU
with a desktop session that headroom is not reliably there.

## Run-to-run variance — the noise floor is larger than the effect

Comparing this round's 8192 block against W3-E7's run at the **same** 8192, same
model, same corpus, same runtime:

| | differing cases |
|---|---|
| 8192 vs 16384, this run | **0 / 52** |
| this run vs W3-E7, both at 8192 | **7 / 52** |

Seven cases differed between two nominally identical runs — mostly in how many
issues were emitted and how the deterministic verifier ruled them, which moved
verifier-supported recall from 10/16 to 9/16. The two runs had very different
GPU memory conditions, so Ollama's layer split almost certainly differed, and
with it the floating-point reduction order behind a greedy decode.

The honest reading: **ordinary run-to-run variation on this setup is worth about
seven cases, while doubling the context window is worth zero.** Any future
context comparison would need to clear that noise floor, and this one did not
have to — it produced no difference at all.

## Threats to validity

- One run per (case, size). The 0/52 identity makes a variance estimate
  unnecessary *for this comparison* — there is nothing to vary — but it does
  not extend to any other setting.
- 52 synthetic, hand-labelled cases; cross_project is 3 cases with per-kind
  denominators of 1. Nothing here supports a rate claim.
- One model, one quantization, one machine, one Ollama version.
- The result is specific to **this runtime's** prompt budget. It shows that
  *this* agent cannot use a larger window, not that larger windows never help.
  If the pack byte budget were raised, the question would need re-asking — and
  raising it is a runtime change this round did not make.

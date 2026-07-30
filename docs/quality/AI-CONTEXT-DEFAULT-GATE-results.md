# AI-CONTEXT-DEFAULT-GATE — results

One live pass executed against the plan frozen in
[`AI-CONTEXT-DEFAULT-GATE-plan.md`](AI-CONTEXT-DEFAULT-GATE-plan.md) before any
model was called. Nothing in the plan was changed after seeing these numbers,
no case was re-run, and no result was excluded.

## Recommendation: **keep `OLLAMA_NUM_CTX_DEFAULT = 4096`**

Two of the four registered conditions are unmet, and the second one is unmet
decisively. 8192 remains a documented operational override for workloads that
need it. **This round changed no default and no code.**

## Run configuration (as executed)

| | |
|---|---|
| model | `qwen3:14b`, Q4_K_M, digest `bdbd181c…` — the build every prior round used |
| engines | both: the shipped fixed window and the experimental agent |
| sizes | 4096 and 8192, each observed back from `/api/ps` |
| runs | one per (case, engine, size) — **208 runs, all completed** |
| concurrency | 1 · retries 0 · temperature and every other setting untouched |
| wall clock | 1782 s |
| aborted | no |

Corpus digests, unmoved: `development` `104ff8bad0df2183…` · `holdout`
`6a8e44605d3689f3…` · `cross_project` `4aa453fff10571c9…`

Block order as frozen (counterbalanced): dev@4096, dev@8192, holdout@8192,
holdout@4096, cross_project@4096, cross_project@8192.

## Residency: the precondition held for all six blocks

| block | observed ctx | `size` | `size_vram` | CPU offload | VRAM in use |
|---|---|---|---|---|---|
| dev @ 4096 | 4096 | 9.49 GiB | 9.49 GiB | **0** | 11504 MiB |
| dev @ 8192 | 8192 | 10.11 GiB | 10.11 GiB | **0** | 12136 MiB |
| holdout @ 8192 | 8192 | 10.11 GiB | 10.11 GiB | **0** | 12136 MiB |
| holdout @ 4096 | 4096 | 9.49 GiB | 9.49 GiB | **0** | 11504 MiB |
| cross_project @ 4096 | 4096 | 9.49 GiB | 9.49 GiB | **0** | 11504 MiB |
| cross_project @ 8192 | 8192 | 10.11 GiB | 10.11 GiB | **0** | 12136 MiB |

No block was discarded. `size_vram == size` everywhere, so nothing here
measures a CPU offload by mistake.

## The result: nothing moved, on any axis

Development + holdout (49 cases per engine per size):

| axis | window @4096 | window @8192 | agent @4096 | agent @8192 |
|---|---|---|---|---|
| detected | 16/16 | 16/16 | 15/16 | 15/16 |
| detected, verifier-supported | 15 | 15 | 10 | 10 |
| missed | 0 | 0 | 1 | 1 |
| negatives clean | 17/18 | 17/18 | 16/18 | 16/18 |
| negative_abstain | 0 | 0 | 2 | 2 |
| false positives | 1 | 1 | 0 | 0 |
| honest abstention | 2/15 | 2/15 | 9/15 | 9/15 |
| abstain answered no_issue | 6 | 6 | 3 | 3 |
| overclaim | 7 | 7 | 3 | 3 |
| `guard_downgraded` | 0 | 0 | 0 | 0 |
| provider errors, any code | 0 | 0 | 0 | 0 |

Zero `timeout`, zero `invalid_response`, zero `usage_limit`, at both sizes on
both engines.

**Case by case, not only in aggregate.** All 104 (case, engine) pairs compared
across the two sizes on state, `outcome`, `model_outcome`, `guard_downgraded`,
the full issue list and tool-call count: **0 of 104 differ.** Cross-project is
unchanged too — the positive missed at both sizes, the negative clean at both.

## Why the answer is not "it made no difference, so pick either"

The registered rule requires more than parity: it requires **evidence that
4096 was a real constraint**. It never was.

| group | peak real prompt tokens | of a 4096 window | of an 8192 window |
|---|---|---|---|
| development | 2657 | 65 % | 32 % |
| holdout | **2760** | **67 %** | 34 % |
| cross_project | 2135 | 52 % | 26 % |

Read from Ollama's `prompt_eval_count` on every response — not `bytes_after`,
not the project's byte estimator. The peaks are **identical at both sizes**,
because nothing was ever trimmed to fit: no truncation, no `usage_limit`, no
error of any kind.

**What these token figures are, exactly.** The tool records one token log per
CASE, and both engines of that case share it: a single `TokenSpy` observes the
fixed window's one round-trip and the agent's whole tool loop. So a peak above
is *the busiest single prompt in that block, whichever engine produced it* —
which is precisely the quantity the "was the window full?" question needs, and
is why it is reported per group rather than per engine. It is **not** a
per-engine figure, and the same combined value is stored on both engines'
records in the raw run, so nothing here may be attributed to the fixed window
or to the agent alone. The same applies to the output-token row in the cost
table below: it is the two engines' output summed for a case, not either one's.
Separating them would need a token log per engine, which this tool does not
keep — and it would not change the finding, since the question is whether ANY
prompt approached the window.

So the two conditions that carry the decision both fail: there is no
improvement to explain, and no constraint that a bigger window would have
relieved.

## Cost

| | 4096 | 8192 | Δ |
|---|---|---|---|
| VRAM after load | 11504 MiB | 12136 MiB | **+632 MiB** |
| fully GPU-resident | yes | yes | — |
| dev block, window + agent | 458 s | 427 s | −7 % |
| holdout block, window + agent | 420 s | 379 s | −10 % |
| cross_project block | 27 s | 27 s | 0 |
| median output tokens (both engines summed, per case) | 274 / 278 / 134 | 274 / 278 / 134 | 0 |

The wall-clock numbers lean *toward* 8192, which is the opposite of what a
bigger KV cache would predict, and they line up with block order rather than
size: dev ran 4096 first and holdout ran 8192 first, and in both cases the
**earlier** block was the slower one. That is warm-up and drift — exactly what
the counterbalanced order was registered to expose. The one real, consistent
cost is **+632 MiB of VRAM for no measured benefit**.

## Against the four registered conditions

| # | condition | result |
|---|---|---|
| 1 | clear and consistent improvement over 4096 | **not met** — 0 of 104 cases differ |
| 2 | evidence 4096 was a real constraint | **not met** — peak fill 67 %, no truncation, no errors |
| 3 | no regression in negatives, abstention, overclaim, citations | met — identical |
| 4 | VRAM and time cost acceptable and stated | stated: +632 MiB; time within order effects |

**Conditions 1 and 2 unmet. 4096 stands.**

## The limitation that matters most, stated plainly

This corpus **cannot** stress a 4096 window, so the result is much weaker
evidence for "4096 is enough" than the zero difference makes it look.

The largest context pack any case produced was **2524 bytes — 10 % of the
24576-byte budget the runtime allows**. The prompt peaks above are therefore
dominated by the fixed system prompt, the tool schemas and the accumulated
conversation, not by repository content. A corpus whose packs use a tenth of
the permitted budget has no power to detect a capacity limit.

And the runtime's own budget can produce prompts that would **not** fit 4096:

| query | per-prompt cap | vs a 4096 window |
|---|---|---|
| AI001 | 5461 est. tokens | **exceeds 4096** |
| AI002–AI008 | 4096 est. tokens | at the limit |

So the honest reading is narrower than "4096 is sufficient": **on units of the
size this corpus produces, 4096 is never the binding constraint, and doubling
it changes nothing.** On a large real repository an AI001 unit may legitimately
reach ~5461 estimated tokens and exceed a 4096 window — this measurement says
nothing about that case, because it never produced one.

If the question needs settling for field-sized units, the next round needs a
corpus with packs near the byte budget, not this one. Raising the default on
the strength of *this* evidence would be raising it on a hypothesis.

## Threats to validity

- Single run per (case, engine, size). The 0/104 identity makes a variance
  estimate unnecessary *for this comparison* — there is nothing to vary — but
  it does not extend to any other setting.
- 52 synthetic, hand-labelled cases; `cross_project` is 3 cases with per-kind
  denominators of 1. Nothing here supports a rate claim.
- One model, one quantization, one machine, one Ollama version.
- Packs at 10 % of the byte budget, as above. This is the dominant limitation
  and the reason the recommendation is "keep", not "4096 is proven sufficient".

# W3-E7 — Agent Quality Gate: results

One live pass over the same corpus, same model, same settings as
[W3-E6](W3-E6-agent-quality-gate-results.md). The runtime under measurement is
commit `a111b3b` (the W3-E7 evidence fixes), unchanged by this round.

**This is the second W3-E7 run.** The first was cancelled and discarded as an
invalid measurement — see [W3-E7-voided-run.md](W3-E7-voided-run.md). No number
from it appears anywhere. This run used the corrected harness; nothing else
changed.

**These counts describe exactly the 52 cases below. They are not an accuracy
estimate for any other code, and nothing here certifies a quality-gate pass.**
The agent runtime remains experimental and opt-in; the fixed window remains the
default.

## Run configuration (as executed)

| setting | value |
|---|---|
| model | `qwen3:14b` (local Ollama, GPU) |
| requested `num_ctx` | 8192 |
| **observed `context_length`** | **8192** (read back from `/api/ps`) |
| concurrency | 1 |
| runs per (case, engine) | 1 |
| retries | 0 |
| wall clock | 1226 s |
| aborted | no — all 52 cases completed, stopping rule not reached |

Corpus digests, unmoved since registration: `development`
`104ff8bad0df2183…` · `holdout` `6a8e44605d3689f3…` · `cross_project`
`4aa453fff10571c9…`

## What the model said, what the user saw, and who changed it

The agent runtime downgrades an unearned clean verdict. Those are three
different facts and this run records them separately:

| | agent | fixed window |
|---|---|---|
| cases completed | 52 | 52 |
| `model_outcome` ≠ `effective_outcome` | **0** | 0 (no guard exists) |
| `guard_downgraded` non-empty | **0** | 0 |

**The guard did not fire once in 52 cases.** That is a measured result, not an
absent instrument: every one of the 52 agent records physically carries the
`guard_downgraded` field, and
`test_a_guard_intervention_reaches_the_measurement_record` drives the real
runtime through the real `run_pair` and asserts that a downgrade arrives in the
record as `model_outcome=no_issue_observed` /
`effective_outcome=insufficient_context` / `guard_downgraded=evidence_not_closed`.
If the link were broken that test would fail.

All 23 `no_issue_observed` verdicts came after between 2 and 6 tool calls —
none was a zero-read clean. On this corpus the agent closed its own evidence,
so the guard had nothing to catch. **This does not show the guard is
unnecessary**: its gap set is derived from what the agent read, so an agent
that reads nothing has nothing recorded as unread. That bound is a property of
the runtime, not of this measurement.

## Scoring counters

Denominators are the case counts of each kind. `honest` counts only the
**model's** `insufficient_context`; `negative_abstain` is a negative that
declined to conclude — neither clean nor a false positive; `abstain_no_issue`
answered `no_issue_observed` on an abstain case and is never credited as
abstention. Errors never enter any of these.

`detected` is the pre-registered rule: an issue cites the target span.
`verified` is a second, stricter reading of the same cases — the project runs a
deterministic verifier over every issue, and `verified` counts only detections
whose target-citing issue it ruled `supported`. Both are reported because they
disagree, and the disagreement is the point.

### development — 25 cases (8 positive, 10 negative, 7 abstain)

| engine | detected | verified | clean | neg_abstain | honest | overclaim | abstain_no_issue | false positive | errors |
|---|---|---|---|---|---|---|---|---|---|
| fixed window | **8/8** | **8/8** | 9/10 | 0 | 1/7 | 3 | 3 | 1 | none |
| agent | **8/8** | 6/8 | 8/10 | 2 | **4/7** | 2 | 1 | 0 | none |

### holdout — 24 cases (8 positive, 8 negative, 8 abstain)

| engine | detected | verified | clean | neg_abstain | honest | overclaim | abstain_no_issue | false positive | errors |
|---|---|---|---|---|---|---|---|---|---|
| fixed window | **8/8** | 7/8 | 8/8 | 0 | 0/8 | 4 | 4 | 0 | none |
| agent | 6/8 | 4/8 | 8/8 | 0 | **5/8** | 1 | 2 | 0 | none |

### cross_project — 3 cases (1 positive, 1 negative, 1 abstain)

| engine | detected | clean | honest | abstain_no_issue |
|---|---|---|---|---|
| fixed window | 0/1 | 1/1 | 0/1 | 1 |
| agent | 0/1 | 1/1 | 0/1 | 1 |

**Zero provider errors of any code, both engines, all 52 cases** — no timeout,
no `invalid_response`, no `usage_limit`, nothing else. W3-E6 had one
`invalid_response`.

## Against the pre-registered acceptance criteria

Registered before the run. Two notes on the baseline are stated first because
they change how two rows read, and both were settled before this run executed.

- The W3-E6 comparison figures below are the **re-scored** ones. The corrected
  counting rules changed what "negatives clean" means, so the published W3-E6
  number is not comparable; the archived run was replayed under the new rules
  (no model called). One published counter moves: agent negatives 18/18 →
  **15/18**. The `verified` column and the per-query verdicts are new readings
  that W3-E6 never published. Details and disclosure in
  [W3-E7-voided-run.md](W3-E7-voided-run.md).
- The criterion "negatives clean **stays 18/18**" was therefore registered
  against a figure that was never earned. It is reported below against both the
  literal registered number and the corrected baseline, and marked failed on
  the literal one.

| # | criterion | W3-E6 (re-scored) | W3-E7 | met |
|---|---|---|---|---|
| 1 | positive recall better than 12/16 | 12/16 | **14/16** | **yes** |
| 1b | *same, verifier-supported only* | *9/15* | *10/16* | *see below* |
| 2 | negatives clean stays 18/18 | 15/18 | **16/18** | **no** (improved, but 16 ≠ 18) |
| 3 | honest abstention not below 8/15 | 10/15 | **9/15** | **yes** |
| 4 | overclaim not above 3 | 3 | **3** | **yes** |
| 5 | cross-project positive detected with earned evidence | no | **no** | **no** |
| 6 | cross-project negative clean after reading the protection | no (unearned) | **yes (earned)** | **yes** |
| 7 | zero citations outside what was sent | 0 | **0** | **yes** |
| 8 | zero timeout / invalid_response / usage_limit | 1 `invalid_response` | **0** | **yes** |

**Six of eight met. Two failed, and they are not re-run.**

**Criterion 1 deserves the qualifier in row 1b.** The registered rule counts a
detection when an issue cites the target span, and by that rule recall went
12/16 → 14/16. Under the stricter reading — only detections the project's own
verifier ruled `supported` — it went 9/15 → **10/16**, which in rate terms is
0.60 → 0.63 and is not a meaningful move on 16 cases. The registered rule is
the one reported as the headline because changing a metric after seeing results
is exactly what pre-registration exists to prevent, but reporting it *without*
this qualifier would overstate what happened. On the same axis the fixed window
is 15/16.

Criterion 2's two remaining non-clean negatives are `negative_abstain`: the
model answered `insufficient_context` rather than claiming the code was fine.
Neither is a false positive. Whether that should count as a fault is a real
question — this measurement records it as *not clean* and *not a fault*, and
lets the query land in `insufficient_evidence` rather than `pass`.

Criterion 5 is the one that did not move: see below.

## Cross-project (the two W3-E5 acceptance failures, still not excluded)

| case | engine | model verdict | guard | sibling read | earned | tool calls |
|---|---|---|---|---|---|---|
| positive | window | `no_issue_observed` | – | no — **impossible** | no | – |
| positive | agent | `no_issue_observed` | none | **yes** | **no** | 3 |
| negative | window | `no_issue_observed` | – | no | **no** | – |
| negative | agent | `no_issue_observed` | none | **yes** | **yes** | 3 |
| abstain | window | `no_issue_observed` | – | – | no | – |
| abstain | agent | `no_issue_observed` | none | – | no | 5 |

One of the two W3-E5 failures closed, one did not:

1. **The negative is now earned.** In W3-E6 the agent answered `clean` without
   ever opening the sibling's protection — right for the wrong reason. It now
   reads `shared/SharedAuth.cs` and *then* concludes. The verdict is unchanged;
   what changed is that it is now supported. This is the only cross-project
   acceptance criterion this round meets.
2. **The positive is still missed.** The agent reaches the sibling file — the
   retrieval works — reads the stub guard that returns `true` for every caller,
   and still answers `no_issue_observed`. There is nothing left to blame on
   retrieval or on context: the deciding lines were in front of it. This is a
   model-judgment failure on this case, at this model and context size, and it
   is left as measured. It was not special-cased, and the run was not repeated.
3. **Both engines answer `no_issue_observed` on the abstain case** where the
   honest answer is `insufficient_context`. Counted in its own bucket, never as
   abstention.

## What separates the two engines on this sample

Combining development + holdout (the pre-registered corpus only):

| axis | fixed window | agent | agent at W3-E6 |
|---|---|---|---|
| positives detected | **16/16** | 14/16 | 12/16 |
| …of which the verifier supports | **15/16** | 10/16 | 9/15 |
| negatives clean | **17/18** | 16/18 | 15/18 |
| negatives abstained | 0 | 2 | 3 |
| false positives | 1 | **0** | **0** |
| honest abstention | 1/15 | **9/15** | 10/15 |
| overclaim | 7 | **3** | 3 |
| citations outside what was sent | **0** | **0** | **0** |
| provider errors | **0** | **0** | 1 |

The agent recovered two of the four positives it missed in W3-E6 and gave up
one honest abstention doing it. It still trails the fixed window on recall by
two cases while claiming less than half as often, and it has yet to produce a
false positive on any negative in either run.

**Citation validity is 0 violations for both engines, and this is not a
self-report.** `verify_one_to_one` raises rather than scores when a citation
falls outside the sent spans, so a computed classification is itself the proof.
For the agent the check runs against the spans it *observably* read.

## Per-query verdicts

A query passes only when every one of its cases reached a decision and none is
a quality fault. An undecided case — an abstained negative, a guard-produced
abstention, an error — withholds the pass.

| group | engine | pass | needs_hardening | insufficient_evidence |
|---|---|---|---|---|
| development | window | 4/8 | 4/8 | 0 |
| development | agent | 4/8 | 2/8 | 2/8 |
| holdout | window | 4/8 | 4/8 | 0 |
| holdout | agent | 5/8 | 3/8 | 0 |

The agent's two `insufficient_evidence` queries are the two that hold a
`negative_abstain`. It reaches `needs_hardening` half as often as the fixed
window on both groups, and neither engine passes more than five of eight.

## Runtime cost

| group | engine | median latency | median tool calls | replayed duplicate calls |
|---|---|---|---|---|
| development | window | 2.4 s | – | – |
| development | agent | 15.1 s | 4 | 23 |
| holdout | window | 6.0 s | – | – |
| holdout | agent | 17.0 s | 4 | 15 |
| cross_project | window | 2.3 s | – | – |
| cross_project | agent | 9.7 s | 3 | 3 |

Context sent stays effectively equal between engines (median `bytes_after`
1220 vs 1211 on development, 1186 vs 1178 on holdout): the agent is not buying
its behaviour with a bigger payload. It costs roughly an order of magnitude
more wall time. 41 duplicate tool calls were served from cache across 52 cases
and never charged to the turn budget.

## Threats to validity

- Single run per (case, engine): no variance estimate. Two of the eight
  criteria turn on differences of one or two cases, which a second pass could
  move in either direction. No second pass was run, by design.
- 52 synthetic, hand-labelled cases; `cross_project` is 3 cases with per-kind
  denominators of 1. Nothing here supports a rate claim.
- One model at one context size.
- The `negative_abstain` and guard counters were added **after** W3-E6 ran and
  applied to it retroactively by replay. They are correct for W3-E6 because it
  predates the guard, but the W3-E6 figures in this document are not the ones
  originally published.
- The verdict guard is measured at zero interventions, so this run says nothing
  about how it behaves when it does fire.

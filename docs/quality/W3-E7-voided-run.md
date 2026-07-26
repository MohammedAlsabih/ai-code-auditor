# W3-E7 — the first measurement run is void

The first W3-E7 measurement run was **cancelled and its artefacts discarded**.
It produced **no quality result**, and none of its numbers appear anywhere in
this repository. This document exists so that absence is a recorded decision
rather than a gap.

## The defect

W3-E7 added an evidence guard to the agent runtime: when the model answers
`no_issue_observed` while relevant references were left unread, the runtime
downgrades the verdict to `insufficient_context` and logs
`verdict_downgraded`.

The runtime is right to do that. The **measurement** was not built for it. The
harness recorded only the verdict the user sees, so after a downgrade the
model's own word was gone. Three counting rules then read the guard's
intervention as if it were the model's judgment:

- an abstain case counted `honest_insufficient` — crediting the model with an
  abstention the runtime produced;
- a negative case counted `clean` — crediting a conclusion nobody reached;
- a query could still reach a `pass` verdict on that basis.

This is an **instrumentation defect, not a quality signal**. A run whose
counters cannot distinguish the model from the guard cannot answer the question
the round asked — whether the runtime fixes recovered positives *without*
losing discipline on negatives and abstention — in either direction. It could
have flattered the agent or maligned it; which one is not knowable, which is
the point.

## What was done about it

The runtime commit `a111b3b` was **not** modified — it is not the defect. No
retrieval, prompt, schema or corpus change was made. The fix is confined to the
measurement layer:

1. Results now carry `model_outcome`, `effective_outcome` and
   `guard_downgraded` as three separate recorded facts. The model's original
   word is exactly recoverable, because the guard fires on — and only on —
   `no_issue_observed`.
2. Honest abstention is counted from `model_outcome` only. A guard-produced
   abstention gets its own counter and is never honest.
3. A negative is `clean` only when the engine actually concluded; declining to
   conclude is recorded as `negative_abstain`, which is neither a clean
   negative nor a false positive.
4. A positive stays `missed` when no supported issue was produced, whether or
   not the guard intervened.
5. A cross-project case meets its acceptance criterion only on earned evidence:
   the negative requires the protection to have been *read* and the verdict to
   be the model's own.
6. A query cannot reach `pass` while ANY of its cases is undecided — counted
   per case, not per kind. The corpus holds two queries with two negatives
   each, and the first version of this rule let one of them pass on the
   strength of the negative that concluded while its sibling sat undecided.
7. A completed record must carry a legal `outcome`; a truncated or hand-edited
   record is refused rather than read as `no_issue_observed`. Recording the
   model's word through a `.get()` fallback had removed a `KeyError` that used
   to fire here — absence of a verdict must not score as a verdict.
8. Absence of the guard fact is not the same as the guard not firing. A record
   claiming the current runtime version must carry `guard_downgraded`; only a
   run replayed at an explicitly named older version may lack it. Without this,
   a record with the voided run's exact shape would re-score silently.
9. A weaker second reading of every detection is recorded beside it:
   `detected_verified` counts only detections whose target-citing issue the
   project's deterministic verifier ruled `supported`. The pre-registered
   `detected` rule is unchanged; both are published so neither can be assumed.

Each of these is pinned by a regression in
`tests/test_ai_quality_harness.py` and `tests/test_ai_quality_gate_tool.py`,
and each was **mutation-tested**: reverting the rule in a scratch copy of the
harness makes at least one test fail. Rules 6-9 exist because the first draft
of this fix shipped rule 6 with a test that could not fail — reverting the rule
left all 50 tests green — and shipped rules 7 and 8 not at all.

## Consequence for the W3-E6 comparison

Rules 3 and 6 change what the published W3-E6 numbers mean, so those numbers
are no longer comparable to anything scored afterwards. The archived W3-E6 run
was therefore **re-scored under the corrected rules** — replayed, not re-run;
no model was called. `tools/quality_rescore.py` performs the replay.

| axis (development + holdout) | as published | re-scored |
|---|---|---|
| agent negatives clean | 18/18 | **15/18** (+3 `negative_abstain`) |
| window negatives clean | 17/18 | 17/18 (unchanged) |
| agent detections the verifier supports | not reported | **9/15** of 12 detected |
| window detections the verifier supports | not reported | **15/16** of 16 detected |
| every other counter, both engines | — | unchanged |

Per-query `pass`/`needs_hardening`/`insufficient_evidence` verdicts also move
under rule 6, in both directions: a query loses its pass when a case is left
undecided, and gains one when it was previously withheld for lacking a case
kind the corpus never contained. Those verdicts were not published for W3-E6.

Those three cases answered `insufficient_context` on a negative. W3-E6 ran
**before** the guard existed, so they are the model's own abstentions, not
guard artefacts — the harness simply used to score "I cannot tell" as "there is
nothing there". The re-scored figure is the honest baseline; the corrected
W3-E7 acceptance criterion for negatives is measured against **15/18**, and the
originally registered "stays 18/18" was measuring something that was never
earned.

This correction was made **after** seeing the W3-E6 results and **before**
running W3-E7 again. It is disclosed here for that reason.

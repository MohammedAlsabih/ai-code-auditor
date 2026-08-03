# REAL-CORPUS-1B — the human review protocol

**Revision 2.** Registered **before any label exists and before any reviewer
has seen a bundle**. REAL-CORPUS-1A built the corpus and the packets; this
document fixes how two humans review them and how their agreement is judged.
Nothing here may change once a reviewer has seen a packet — that is the whole
point of writing it first, and it is why revision 2 lands now rather than
after the first return.

Revision 2 changes three things, all found by auditing revision 1 before use:
what R3 is given to arbitrate with, when κ is undefined, and what counts as a
disagreement. Revision 1 was never handed to a reviewer.

**No label exists yet. No accuracy number of any kind may be computed,
quoted, or estimated before R3 has arbitrated.** The scanner's own output is
not ground truth, in either direction.

## What is reviewed

| | count | contract |
|---|---|---|
| Track A — emitted findings | 120 | adjudicate a claim |
| Track B — blind code units | 84 | find issues, no claim exists |

R1 and R2 review **the same** 120 findings and **the same** 84 blind units,
each in their own pseudo-random order, fixed in REAL-CORPUS-1A and not
regenerated here. Two orders exist so the reviewers cannot compare positions;
identical orders are refused by the sampler's own verification.

## Independence

- Neither reviewer sees the other's packet, the other's answers, any AI
  output, or the author's opinion.
- Track B carries **no scanner overlap and no verdict**. The overlap join
  lives beside the sample, never inside a packet.
- A reviewer judges **only what the packet shows**. No AI assistance, no
  browsing the repository, no looking up the project.
- **Real reviewer names never enter Git, a bundle, or a result file.** The
  identifiers are `R1`, `R2`, `R3` and nothing else. Whoever holds which
  identifier is recorded outside this repository, or not at all.

## The two contracts, kept apart

Track A asks *is this claim true?* — `confirmed` / `false_positive` /
`uncertain`, plus level, gate, actionability, reason, evidence sufficiency.

Track B asks *is anything wrong here?* — `issues_found` /
`no_issue_observed` / `uncertain`, plus a list of 0..N issues each carrying
rule_id, line, span, statement, evidence, level, actionability.
`false_positive` is not offered: there is no claim to be false about.
`issues_found` with an empty list is refused.

The two are never rendered by one form and never scored into one number.

## Agreement — the criterion, fixed now

Computed **separately per track**, on the primary field only:

| track | primary field | statistic |
|---|---|---|
| A | `label` | Cohen's κ over `confirmed` / `false_positive` / `uncertain` |
| B | `outcome` | Cohen's κ over `issues_found` / `no_issue_observed` / `uncertain` |

- **Raw agreement is reported next to every κ**, never instead of it. κ can be
  low while raw agreement is high when one category dominates, and that fact
  is a result, not something to hide behind.
- **Both tracks must reach κ ≥ 0.4.** If either falls short there is **no
  quality result** from this corpus: the disagreement is reported, the
  protocol is re-examined, and no precision or recall number is published.
- **κ is UNDEFINED when expected agreement is 1.0** — that is, when both
  reviewers used a single category for every unit. The formula is then 0/0.
  It is reported as `kappa: null`, `defined: false`, **the floor is not met,
  and no quality result is permitted.** Raw agreement is still shown, because
  "the two agreed on everything" is a real observation; what it is not is
  evidence of agreement beyond chance, and revision 1 would have scored it a
  perfect 1.0 and passed the gate.
- **Both accepted results must cover exactly the same `sample_id` set.** A
  mismatch, in either direction, is an error — not something to compute an
  intersection over. Silently scoring the overlap would let a reviewer's
  omissions choose the denominator.
- Secondary fields (level, gate, actionability, evidence sufficiency) and
  Track B **issue matching** are reported **separately**, each with its own
  denominator. They never enter the κ that decides the gate.
- The two tracks are never pooled. 120 findings and 84 code units are
  different populations answering different questions; one combined κ would
  describe neither.

κ is computed only over units **both reviewers completed**. Any unit missing
from either side is reported as a coverage gap with its count, not silently
dropped from a denominator.

## R3 — arbitration

- An R3 packet is created **only after both R1 and R2 are accepted in full**.
  A partial return is a draft and produces nothing.
- **R3 receives the original, unmodifiable material**, not just two verdicts.
  Revision 1 handed over a pair of bare judgements, which is not something
  anyone can arbitrate:
  - Track A: the `claim` and the `judged_on` block the reviewers saw.
  - Track B: the `code_unit` and its `applicable_rules`.
- The two judgements are shown as **A** and **B**, unlabelled, in a
  deterministic pseudo-random order per unit. R3 does not learn which
  reviewer said what. The order is seeded from a **run salt generated once
  per workspace, stored outside `handoff/R3/`, and never committed** — a seed
  written into the tooling would let anyone holding the packet replay the
  shuffle and recover the whole mapping, which is determinism without
  anonymity.
- R3 answers in the reviewers' own contracts and through the **same
  fail-closed import**: the same key allowlists, the same prose bounds, and —
  for Track B — the same per-issue checks that the rule was offered for this
  unit and the line and span sit inside it. R3's resolved judgements are what
  a later number rests on, so they are the last place that may be the
  loosest.
- R3 writes the final judgement **in full** — the whole Track A label set, or
  the whole Track B outcome and issue list. There is **no majority vote and
  no automatic reconciliation**: a disagreement is resolved by a human
  reading the case. R3's return goes through the same fail-closed import as
  R1's and R2's.

### What counts as a disagreement

| track | a case is created when |
|---|---|
| A | `label` differs, **or** any of `level` / `gate` / `actionability` / `evidence_sufficiency` differs |
| B | `outcome` differs, **or** the issue keys differ, **or** two issues sharing a key differ in `level` or `actionability` |

An issue key is `(rule_id, line)` — the same key the issue-matching statistic
uses, so the two never disagree about what "the same issue" means.

**Wording alone is not a disagreement.** Two reviewers who reach the same
judgement and write different `reason` or `evidence` prose do not create a
case; there is nothing for a third person to decide. Revision 1 also missed
the opposite and more damaging case: two reviewers agreeing that a unit has
problems while naming entirely *different* problems never reached
arbitration at all.

## Bundle identity and delivery

- Every bundle carries a `protocol_version` and a `bundle_id` derived from
  the reviewer, both track digests, and the contracts. Change any unit and
  the id changes.
- The reviewer's saved progress is keyed by that `bundle_id`. Revision 1
  keyed it by `R1`/`R2` alone, so a second bundle would have silently
  inherited answers from the first on any `sample_id` that recurred — the
  reviewer would see their own old judgement already filled in, for material
  they had not looked at in this bundle.
- Saved progress is loaded **only after** the bundle is validated, never
  before.
- Every export carries the `protocol_version`, the `bundle_id` and both track
  digests. Import matches all of them exactly.
- Each reviewer is handed **their own directory** containing only their own
  bundle and UI — `handoff/R1`, `handoff/R2`, and later `handoff/R3`. Hand
  over the reviewer's own directory, never the `handoff/` parent, which holds
  all three.
- `agreement` and `r3-build` refuse unless the two accepted results come from
  **two different reviewers**, carry **different bundle ids**, and the two
  bundles describe **the same material** unit for unit. Matching sample_ids
  are not evidence of that: ids survive a rebuild, the claims behind them do
  not.
- The reviewer screen validates an answer against exactly the bounds the
  importer applies — the same line and span grammar, the same prose caps.
  A green "complete" and an accepted import must never disagree; a screen
  that says a unit is done and an importer that then refuses all 204 is worse
  than either check alone.

## Privacy boundary

Committed: this protocol, the review tooling, its tests, and — later —
counts-only aggregates.

Local and gitignored, under `.quality-local/real-corpus/`: bundles, the
reviewer UI, saved progress, returned results, labels, agreement detail, the
R3 packet, and anything mapping an identifier to a person.

The public-output scrubber refuses any artefact carrying code, a path, a
label, or a raw packet.

## Stopping rules

- A returned file that fails any import check is refused whole. There is no
  partial acceptance and no repair.
- If a reviewer reports that a packet was insufficient to judge, that is
  recorded as `uncertain` with a reason — not resolved by fetching more
  context, which would break the equal-information contract.
- If either κ misses 0.4, this corpus yields no accuracy claim.

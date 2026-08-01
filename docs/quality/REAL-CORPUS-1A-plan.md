# REAL-CORPUS-1A — frozen plan

Registered on `quality-real-corpus` at `b55d371` (identical to published
`main`, CI 6/6 green) **before any repository was chosen, downloaded, or
looked at**, and before any unit was sampled.

Selection criteria, sampling, denominators, size buckets, the review protocol
and the stopping rules are fixed here. **Nothing in this document is changed
after results are seen.** If a rule here turns out to be wrong, the honest
move is to record that it was wrong and what it cost — not to edit it.

## Why this round exists

Every AI quality figure this project has produced so far rests on 52
hand-written synthetic cases. Two consecutive measurement rounds
([AI-CONTEXT-GATE](AI-CONTEXT-GATE-plan.md),
[AI-CONTEXT-DEFAULT-GATE](AI-CONTEXT-DEFAULT-GATE-plan.md)) ended by saying
the corpus could not answer the question they were asked: the largest context
pack any case produced was **2524 bytes — 10 % of the 24576-byte budget**. A
corpus that uses a tenth of the permitted budget cannot detect a capacity
limit, and hand-written cases cannot measure what a scanner misses on code
nobody wrote for it.

This round builds the corpus. **It measures nothing.** No model is run, no
prompt is touched, no scanner rule is changed. The deliverable is a corpus
plus two reviewer packets — and the labels do not exist until two independent
humans produce them.

## What this round must NOT claim

- No precision, recall, or F-score is computed here.
- **The scanner's own output is not ground truth**, in either direction. A
  finding it emitted is a *claim to be judged*; a line it stayed silent on is
  *not evidence of absence*.
- No label in this round may be produced by a model, an agent, or the author.
  A packet with fabricated labels is worse than no packet, because it looks
  like evidence.

## Sample and configuration

| | |
|---|---|
| tool under measurement | published `main` @ `b55d371`, unmodified |
| scanner mode | `--offline --no-semgrep` — no registry network, one engine |
| supported languages (from the real catalog) | typescript 33 rules · tsx 31 · csharp 22 · java 22 · python 22 |
| rule families | D 3 · H 11 · J 2 · N 6 · P 8 · R 7 · S 5 (42 total) |
| frameworks with dedicated rules | react 7 · next 6 |
| pack budget | `PACK_MAX_BYTES` = 24576; effective per-query cap = `min(PACK_MAX_BYTES, query.max_context_bytes)` → AI001 **16384**, AI002–AI008 **12288** |

## Repository selection

### Inclusion — every criterion must hold

1. **Public and reachable over HTTPS** on `github.com` or `gitlab.com`, with
   no credentials of any kind in the URL.
2. **A license file is present and identifiable** (SPDX id recorded). Any
   OSI-approved licence is acceptable; the id is recorded, never interpreted
   as permission to redistribute the code — nothing from these repositories
   is ever committed here.
3. **Primary language is one the catalog actually supports**: TypeScript/TSX,
   C#, Python, or Java.
4. **A real dependency manifest for its ecosystem exists**
   (`package.json` / `*.csproj` / `requirements.txt` or `pyproject.toml` /
   `pom.xml` or `build.gradle`). Without one the entire H family — 11 of 42
   rules — cannot fire, and the repository would silently under-represent the
   tool.
5. **Genuinely maintained**: at least one commit within 24 months of the
   freeze date.
6. **Size**: between 30 and 5000 source files in supported languages. Below
   30 it is a sample, not a codebase; above 5000 one repository would dominate
   the corpus and the scan cost stops being worth it.
7. **Scans offline to completion** within 20 minutes on the measurement
   machine.

### Exclusion — any one disqualifies

- A fork that is behind its upstream, or archived/abandoned.
- **Vendored third-party source in-tree** (`node_modules/`, `vendor/`,
  `third_party/`, `packages/` holding foreign code) — a finding in vendored
  code is not a finding about this repository, and separating them reliably
  is not something this round can do.
- **Requires git submodules** for its own source.
- Any credential, key, or token that appears to be real. A repository that
  ships a *deliberately fake* example key is fine and is recorded as such.
- Toy, tutorial, single-file, or template-scaffold repositories.
- **Anything already used by this project**: the two field repositories
  (Tabi, Madar), anything under `tests/fixtures/`, and the `examples/` report
  corpus. Reusing them would measure the tool against code it was tuned on.
- License absent, ambiguous, or "all rights reserved".

### Composition targets

- **8–12 repositories**, each pinned to an exact commit SHA.
- **At least 2 repositories per language** for TypeScript/TSX, C#, and
  Python. Java is included if a qualifying repository is found and is
  otherwise recorded as a coverage gap, not padded.
- Different domains and sizes; small/medium/large represented.
- **No single repository may contribute more than 20 % of the units in
  either track.** If one would, its quota is capped and the shortfall is
  reported as a shortfall.

### Recorded per repository — and nothing else

`repo_id` (assigned), public URL, commit SHA, SPDX licence id, primary
language, and the counts needed for the denominators. **No paths, no file
names, no code, no findings** are recorded in anything committed.

## Acquisition

- Downloads go **only** into `.quality-local/real-corpus/repos/<repo_id>/`,
  which is gitignored.
- Git is invoked as an **argv list with `shell=False`**, with hooks disabled,
  terminal and credential prompting disabled, submodules never fetched, and
  the protocol restricted to https. A pinned SHA is fetched directly
  (`git fetch --depth 1 origin <sha>`), so the recorded SHA is the only thing
  that can ever be checked out.
- After checkout the tree is verified: `HEAD` equals the pinned SHA, or the
  repository is rejected.

## Unit construction — two separate tracks

The two tracks answer two different questions and must not be merged. The
findings track can only measure **precision**; a corpus made only of things
the scanner said would make the scanner unfalsifiable.

### Track A — emitted findings (precision)

- Population: every finding in the offline reports of the accepted
  repositories.
- **Stratified** by `(rule_family, language, repository, precision, level)`.
- Target **120** units, minimum **80**. Quotas are filled proportionally to
  stratum size, then capped by the 20 %-per-repository rule.
- Denominator for any later precision figure: the number of *sampled and
  labelled* findings in the stratum being reported — never the whole
  population, and never across strata with different quotas.

### Track B — blind code units (what was missed)

- Population: functions (preferred) or whole files, in the supported
  languages, chosen **independently of the scanner's output**.
- Target **80** units, minimum **60**.
- Composition, fixed here:
  - **50 %** units that contain **no** emitted finding,
  - **30 %** units that contain **at least one** emitted finding,
  - **20 %** units drawn uniformly at random from all units.
  The reviewer is never told which group a unit came from, and the packet
  carries no indication of whether the scanner said anything about it.
- The 50/30/20 split is a *sampling* device only. Any later recall estimate
  is computed with the inverse of these sampling probabilities and is
  reported as **a lower bound on the sampled units**, never as repository-wide
  recall.

### Determinism

- `sample_id = sha256(repo_id : identity)[:16]`, where identity is the
  scanner's own `fingerprint` for a finding, and
  `relpath : start_line : end_line : sha256(unit_text)` for a blind unit.
- Selection within a stratum is by ascending `sample_id`, so the sample is a
  pure function of the corpus and the quotas — not of filesystem order,
  wall-clock, or the machine.
- Re-running the sampler on the same corpus must produce a byte-identical
  selection. This is asserted by a test.

## Context-size buckets

Every unit records the **real** size of the context pack built for it, in
bytes and in estimated tokens, measured **after** the pack is assembled by the
product's own packer — never estimated, never padded.

Buckets, as a fraction of the effective per-query cap:

| bucket | fraction of cap |
|---|---|
| small | < 50 % |
| medium | 50–80 % |
| large | 80–100 % |

**Target: at least 15 units in the `large` bucket.** If the accepted
repositories do not produce units near the cap, that is recorded as **a
corpus limitation** in the summary, in the same words as the two previous
rounds used. No unit is inflated, concatenated, or padded to reach a bucket.

## Human review protocol

- **Two independent reviewers, R1 and R2.** Both human. Neither sees the
  other's packet, the other's labels, any AI output, or the author's opinion.
- Each packet contains the same units in a **different pseudo-random order**,
  derived from a per-reviewer salt, so position cannot be compared between
  reviewers.
- In Track B the packet must not reveal whether the scanner emitted anything
  for the unit. This is enforced by a test that diffs a blind packet against
  the report and asserts no leakage.
- **Labels** per unit: `confirmed` / `false_positive` / `uncertain`, plus
  `level`, `gate`, `actionability`, `reason`, and `evidence_sufficiency`.
  `uncertain` is a first-class answer and is never coerced.
- **R3 arbitrates disagreements only**, sees both labels and neither
  reviewer's identity.
- Inter-reviewer agreement is reported before any quality figure derived from
  the labels. Agreement below a Cohen's κ of 0.4 invalidates the round's
  labels rather than being averaged away.
- **A model, an agent, or the author may not act as R1, R2, or R3**, and no
  label may be generated, suggested, or pre-filled. A round that cannot obtain
  two human reviews ends with an unlabelled corpus, reported as such.

## Privacy boundary

**Committed:** this plan, the acquisition/sampling/packet tool, its tests, a
manifest of public URLs + SHAs + licences + languages, and an anonymized
summary of counts and unit sizes.

**Local and gitignored, under `.quality-local/real-corpus/`:** clones,
reports, snippets, any path, the packets themselves, raw labels, and reviewer
identity.

Enforced mechanically, not by care:

- one-to-one verification between the sampled set and each packet,
  **fail-closed** — a mismatch aborts rather than trimming;
- refusal of duplicate `sample_id`s and of any unit whose recomputed identity
  does not match its recorded one;
- a scrubber check asserting that no committed artefact contains a filesystem
  path, a code snippet, a finding, or a repository-local path.

## Stopping rules

- Acquisition runs **once** after the deterministic tests pass. A repository
  that fails to clone, fails SHA verification, or exceeds the scan budget is
  **dropped and recorded as dropped** — not retried, not replaced by hunting
  for a more convenient repository.
- If fewer than 8 repositories qualify, the round reports a smaller corpus
  rather than relaxing any criterion above.
- The round ends with the packets prepared. **Human review is not started
  here.**

## Output

Two commits, no more:

1. `REAL-CORPUS-1A1` — acquisition + manifest + pinning, with tests.
2. `REAL-CORPUS-1A2` — sampling + reviewer packets + validation, with tests.

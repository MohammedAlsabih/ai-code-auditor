# REAL-CORPUS-1A — corpus summary

Built from `docs/quality/REAL-CORPUS-1A-plan.md`, registered in full before
any repository was chosen or downloaded. Tool commit: `b55d371`.

**This document contains no labels and makes no accuracy claim.** No unit has
been judged. Precision, recall and every rate derived from them stay undefined
until two independent human reviewers return R1 and R2 and R3 arbitrates. The
scanner's own output is not ground truth, in either direction.

## Three measurements, three denominators

They are reported separately throughout and are never added, averaged, or
compared against a shared cap. Conflating the first and the third is the
defect the closing round removed.

| | what is counted | population | its own cap |
|---|---|---|---|
| single-finding review | one `review.build_context_pack` per emitted finding | 1293 findings | `PACK_MAX_BYTES` 24576 |
| blind human review | code units drawn without reading the report | 12578 units | none — no packer, no budget |
| AI Audit packs | one `audit.build_audit_pack` per (project, query) | 343 packs | the query's own: AI001 16384, AI002–AI008 12288 |

## Repositories

Fourteen candidates, twelve accepted, each pinned to a full commit SHA. Only
the public URL, SHA, SPDX id and language are recorded. The manifest is
`docs/quality/real-corpus-manifest.json`.

Accepted: python 4, typescript 3, csharp 3, java 2.
Licences: Apache-2.0 ×6, MIT ×4, BSD-3-Clause ×2.

| rejected | reason |
|---|---|
| date-fns | no licence file at the repository root — it moved into `pkgs/*/LICENSE.md` when the project became a monorepo, so the declared SPDX id could not be verified against the tree |
| AutoMapper | actually under the Reciprocal Public License 1.5, not the MIT this author had assumed |

Both were dropped rather than edited to fit.

All twelve scanned offline from published `main`: twelve reports, none over
the 20-minute budget, slowest 40.4 s, **1293 findings**.

## Track A — scanner findings context (precision only)

120 units from the 1293-finding population, stratified by
rule-family / language / precision / level.

| axis | distribution |
|---|---|
| rule family | H 69, P 43, R 6, D 2 |
| language | typescript 44, python 31, java 19, dotnet 15, csharp 7, tsx 4 |
| precision | exact 104, heuristic 16 |
| level | note 67, warning 47, error 6 |

Repository shares, largest first: 18.3 %, 17.5 %, 10.8 %, 10.8 %, 8.3 %,
8.3 %, 6.7 %, 5.0 %, 4.2 %, 4.2 %, 3.3 %, 2.5 % — the 20 % ceiling holds.
Findings the packer refused: **0**.

Pack sizes, against **24576** — this packer's own cap, not the 12288 the first
closing round borrowed from the audit queries:

| | min | median | max | of cap |
|---|---|---|---|---|
| sample (120) | 609 | 1846 | 5116 | 20.8 % |
| population (1293) | 608 | 1921 | 6302 | **25.6 %** |

**Large-bucket units: 0. Target was 15. Not met, and not claimed.** Under the
correct cap the shortfall is larger than previously reported: the earlier
"51 % of cap" was 6302 against 12288.

### Why, measured on all 1293 packs

- **457** stopped by the ±20-line window, having used all 41 lines;
- **0** stopped by the 8192-byte source budget — the largest source piece
  anywhere was 2922 bytes, 36 % of the budget it was allowed;
- **300** carry no source at all: 253 because the finding has no file/line
  (dependency- and manifest-level rules), 29 because the path did not resolve
  in the tree, 18 because the file exceeds the 65536-byte whole-file read cap
  and is refused entire.

The binding constraints are `SOURCE_CONTEXT_LINES` and `MAX_CONTEXT_FILES`,
never the byte budget, so no choice of repositories can push this packer near
its cap. **This explains the review path only.** It says nothing about the
audit packer, which has different limits and reaches them.

## Track B — blind human-review context (the only track that can show a miss)

84 units, 7 per repository, drawn from a population of **12578** using
repository and language identity alone. The draw never reads the report.

Languages: python 28, csharp 21, typescript 21, java 14. Every repository
contributes 8.3 %.

Sizes are real code bytes (min 132, median 361, max 15009) and are bucketed
against the largest unit in the corpus. There is no packer on this track and
therefore no cap to be a fraction of; these numbers are never compared with a
review pack or an audit pack.

Inclusion probability is recorded per repository because it varies by two
orders of magnitude — zustand 0.212 (33 units) against gson 0.0024
(2950 units) — so any eventual recall estimate must be weighted, not assumed
uniform.

### The scanner's output, joined only after the sample was frozen

| | units |
|---|---|
| a finding lands inside the unit | 2 |
| no finding inside the unit | 82 |

Matched by `normalize(project_root + finding.file)`, then
`start_line ≤ finding.line ≤ end_line`. The join is written beside the sample
and never reaches a reviewer.

The previous file-level rule would have called 14 of these units
`has_finding`. On the full corpus it mislabelled **504 of 536** units (94 %):
a finding at line 146 marked a function spanning lines 60–98.

## AI Audit pack profiling (a different packer, its own caps)

343 packs over all twelve repositories. Denominator: packs.

| | value |
|---|---|
| canonical pack bytes | min 1046, median 6624, p95 14343, max 18980 |
| source bytes (what the cap governs) | min 75, median 4965, p95 12224, max 16227 |
| size buckets | small 203, medium 57, **large 83** |
| largest source as a fraction of its own cap | **99.8 %** |
| packs at ≥80 % of their own cap | **83** |
| files sent | 1 → 52, 2 → 47, 3 → 224, 4 → 20 |
| skipped | 385, all "no real candidate files for this query" |

Language is reported twice, because two different facts are involved: what
the repository declares, and what decided query support after the product's
own alias.

| | distribution |
|---|---|
| by report language | dotnet 125, typescript 82, java 80, python 56 |
| by query language | csharp 125, typescript 82, java 80, python 56 |

Project languages that survive the alias and still match no query: **none**.

`AuditQuery.max_context_bytes` bounds the **source** text, not the canonical
pack — which also carries the query piece and its decision contract — so a
canonical/cap ratio above 1.0 is expected and is not a breach. The bucket
follows source bytes.

**This path does reach its cap where the review path cannot.** That contrast
is only visible because the two are measured separately.

### Correction (REAL-CORPUS-1A3) — a claim withdrawn

An earlier version of this document reported that *"27 `dotnet` projects have
no query support at all"*, that .NET is never audited, and that serilog
produced no pack of any kind. **All three statements were false, and they are
withdrawn.**

They were a defect in this measurement tool, not in the product. The product
has carried a central alias since W4-A3 —
`auditor.ai.audit_queries.audit_language` maps `dotnet` → `csharp` — and the
web audit gate applies it, so a .NET project reaches all eight queries in
production. The profiler compared the **raw** report language against the
catalog, matched nothing, and published its own omission as a product gap.

What the corrected run shows, on the same repositories, the same commit SHAs
and the same local reports:

| | withdrawn | corrected |
|---|---|---|
| packs | 218 | **343** |
| large-bucket packs | 54 | **83** |
| skips | 294 | 385 |
| serilog | 0 packs | **26 packs** |
| restsharp | 5 | **78** |
| fluentvalidation | 4 | **30** |
| languages with no query support | `dotnet: 27` | **none** |

The tool now imports `audit_language` rather than keeping a second copy, and
tests pin both directions: a `dotnet` project reaches every csharp query, and
a language with no alias and no query is still counted as unsupported.

The lesson is the one this corpus exists to enforce: **a measurement that does
not go through the product's own code path measures the harness.** Nothing in
the scanner, catalog, runtime or gate was changed to produce these numbers.

## Two review contracts

They ask different questions, so they offer different answers.

**Track A — adjudicate a claim.** `confirmed` / `false_positive` /
`uncertain`, plus level, gate, actionability, reason and evidence
sufficiency. The entry carries the claim *and* what the judgement rests on:
the source window the packer actually sent, the rule's own definition, and any
manifest or execution evidence in the report.

**Track B — find issues.** `issues_found` / `no_issue_observed` /
`uncertain`, plus an issues list of 0..N, each carrying rule_id, line/span,
statement, evidence, level and actionability. `issues_found` with an empty
list is refused. **`false_positive` is not offered**: there is no claim on
this track to be false about. The entry carries the code unit, the confined
file context above it, and the catalog rules for that unit's language only.

Each contract is validated and verified one-to-one **separately**, fail-closed
on a missing, duplicated, forged, cross-track or identically-ordered packet.

The earlier claim that the two packets had indistinguishable key sets was
false and is withdrawn: `claim` appears in one and `code_unit` in the other,
and pretending otherwise concealed that both tracks were being asked the same
question.

## What the reviewers get

Four packets in `.quality-local/real-corpus/packets/` (gitignored):
`packet_findings_R1/R2` (120 units each) and `packet_blind_R1/R2` (84 each),
every pair in a different pseudo-random order, every label field present and
empty. Re-running the whole build is byte-identical, summary and packets
alike.

## Stopping here

No labels exist. R1 and R2 have not been run, and nothing here may be used to
state an accuracy figure until they have been, independently, by two humans
who see neither each other's packet nor any AI output.

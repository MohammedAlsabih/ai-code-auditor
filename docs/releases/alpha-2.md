# AI Code Auditor — Alpha 2 (`0.1.0a2`)

An alpha. It is offered for evaluation on code you already have the right to
analyse, and it should be treated as a tool that produces evidence for a human
to weigh — not as a gate, and not as a security verdict.

## What it does

**A deterministic scanner.** The same input produces the same report. No model
is consulted to reach a finding, and nothing about a finding depends on the
network being up. Python, TypeScript/TSX, Java, C#/.NET.

Two engines: hallucinated-dependency detection (a declared or imported package
that does not exist, cannot be resolved, or is not what its name suggests), and
risky-pattern detection over a fixed rule catalogue. Every finding carries its
rule, level, precision (exact or heuristic), the line it points at, and the
window it was judged on.

**Local reports, and a report explorer.** `auditor scan` writes `report.json`
(plus Markdown and SARIF 2.1.0). `auditor serve` opens that one file in a local
explorer bound to 127.0.0.1. The report on disk is never modified.

**Human review, kept separate from the scan.** A reviewer can mark a finding
confirmed, a false positive, or an accepted risk, with a note. Those judgements
live in a sidecar beside the report — the only file the server writes — so a
rescan never overwrites them and a review never edits a scan.

**Project Library.** `auditor library` manages several projects and their scan
history from one local server: register a folder or clone a repository, run
scans, and browse many reports without restarting anything. Loopback only;
project management is never exposed on a non-local bind.

**Baselines.** A scan can be compared against a previous one, so a report
distinguishes what is new from what was already there.

## The AI layers are experimental, optional, and advisory

Off unless you turn them on, and configured on the server — no key is ever
entered or stored in the browser.

- **AI Review** asks a model about one finding the scanner already produced.
- **AI Audit** asks a model to look for things over a project, producing
  *candidates* for a human to accept or reject.

**No AI result ever changes a finding's level, gate, or review status.** Nothing
is applied automatically. An AI opinion is displayed beside the deterministic
result and is always attributable to the model and prompt that produced it.
Anything sent to a remote provider passes an explicit consent step that states
what would be sent, in counts and bytes, before it is sent.

## Known limitations — please read before judging the tool

- **The interface is built for a desktop window.** It is usable at 1280 and
  reasonable at 768. Phone-width layout is being worked on and lands in a later
  Alpha; if you open it on a phone today, expect rough edges.
- **AI output is not a security judgement.** It is one more opinion, from a
  system that can be confidently wrong. Do not treat an AI-confirmed finding as
  verified, and do not treat an AI-dismissed finding as safe.
- **There is no accuracy figure for this release, and you should distrust any
  you are quoted.** Measuring precision and recall honestly needs independent
  human review of a real corpus; that work is under way and deliberately
  unfinished. No number is published here because none has been earned.
- **Some CLI-based providers cannot list their models.** They are local
  commands with no listing API, so the model id has to be typed in. The tool
  now says so plainly instead of failing.
- **No AI candidates does not mean a project is safe.** It means the queries
  that ran found nothing they recognised. Absence of a candidate is not
  evidence of absence of a problem — and the same goes for an empty scan.
- Registry lookups need the network. Offline, dependency verification reports
  itself as unavailable rather than guessing, and the scan still completes.

## Install

```
pip install ai_code_auditor-0.1.0a2-py3-none-any.whl          # scanner + CLI
pip install "ai_code_auditor-0.1.0a2-py3-none-any.whl[web]"   # + the report explorer
```

The AI layers need their own extra and are off by default. Missing an extra
produces a short instruction, not a traceback.

## Verify what you downloaded

`checksums.txt` in this release carries the sha256 of the wheel and the sdist.

## Not in this release

The mobile layout work, the AI Review/Audit interface repairs, and the model
selection rework are on a branch and are not part of Alpha 2. They ship in
Alpha 3. This release is the stable line only.

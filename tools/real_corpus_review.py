"""REAL-CORPUS-1B: the human review workflow, entirely offline.

Implements `docs/quality/REAL-CORPUS-1B-review-protocol.md`. Four jobs:

* **bundle**  — one self-contained folder per reviewer: their packets in
  their own order, fixed instructions, and checksums.
* **ui**      — one self-contained HTML file per bundle. No network, no CDN,
  no analytics, no subprocess: it reads a local file the reviewer picks,
  keeps progress in that browser, and exports a JSON result.
* **import**  — fail closed. A returned file must match the packet it claims
  to answer, one to one, byte for byte on everything except the label fields.
* **agree**   — Cohen's κ per track on the primary field only, raw agreement
  beside it, secondary fields reported separately, denominators never pooled.
  `r3_packet` prepares arbitration but is never run automatically.

Nothing here writes inside the repository. Every output goes under the
`--root` the caller names, which is `.quality-local/...` and gitignored.

NO LABEL IS EVER CREATED HERE. The tool moves a human's answers around and
refuses anything it cannot prove came back unchanged.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import secrets
import sys
import unicodedata
from pathlib import Path
from typing import Any, Iterable

from tools.real_corpus_sample import (
    ACTIONABILITY,
    EVIDENCE_SUFFICIENCY,
    GATES,
    LEVELS,
    REVIEWERS,
    TRACK_A_LABEL_FIELDS,
    TRACK_A_LABELS,
    TRACK_B_ISSUE_FIELDS,
    TRACK_B_OUTCOMES,
    validate_blind_labels,
    validate_findings_labels,
)

PROTOCOL_VERSION = 2

TRACKS = ("findings", "blind")

# The only fields a reviewer may change. Everything else in a returned entry
# must come back byte-for-byte as it was handed out.
EDITABLE = {"findings": frozenset(TRACK_A_LABEL_FIELDS),
            "blind": frozenset({"outcome", "issues"})}

# Exact key allowlists — a returned entry with an extra key is refused rather
# than having the extra ignored. An ignored key is a place to smuggle
# something into a later consumer.
ENTRY_KEYS = {
    "findings": frozenset({"position", "sample_id", "track", "language",
                           "claim", "judged_on", *TRACK_A_LABEL_FIELDS}),
    "blind": frozenset({"position", "sample_id", "track", "language",
                        "code_unit", "applicable_rules", "outcome", "issues"}),
}
ISSUE_KEYS = frozenset(TRACK_B_ISSUE_FIELDS)

# The exported result's own shape, checked at the top level too — an extra
# key there is as much a place to hide something as one inside an entry.
RESULT_TOP_KEYS = frozenset({"corpus", "protocol_version", "bundle_id",
                             "reviewer", "track_digests", "tracks",
                             "complete"})
TRACK_KEYS = frozenset({"entries"})

# Bounds. A reviewer writes prose, not a payload.
REASON_MAX_CHARS = 2000
STATEMENT_MAX_CHARS = 1000
EVIDENCE_MAX_CHARS = 2000
MAX_ISSUES_PER_UNIT = 20
RESULT_MAX_BYTES = 8 * 1024 * 1024

# A rule the catalog does not list, chosen deliberately. Spelled out so it
# cannot be confused with a typo, and counted separately in every summary.
OTHER_RULE = "OTHER"

_SPAN_RE = re.compile(r"^(\d+)-(\d+)$")

# A Windows drive letter is a SINGLE letter at a boundary. Without the
# lookbehind this also matches every URL scheme — `https://`, `mongodb://`,
# `file:///` — and a Track B packet is full of real source code that contains
# them. The first run against the real corpus was refused for 100 "local
# paths", every one of which was a URL inside the code being reviewed.
_PATHISH = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]"
                      r"|(?:^|[\s\"'])/(?:home|Users|tmp|var)/"
                      r"|\.quality-local")


class ReviewError(Exception):
    """A returned file cannot be trusted. Fail closed: a result that is
    almost right is a result whose labels cannot be believed."""


# ---- helpers ---------------------------------------------------------------------------

def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def digest(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


def bundle_identity(reviewer: str, digests: dict[str, str],
                    contracts: dict[str, Any]) -> str:
    """An id that changes whenever anything the reviewer will see changes.

    Revision 1 keyed saved progress by `R1`/`R2` alone. A second bundle would
    then have inherited answers from the first for every `sample_id` that
    recurred — the reviewer opens fresh material and finds their own old
    judgement already filled in. Binding the key to the CONTENT makes that
    impossible rather than unlikely."""
    return hashlib.sha256(_canonical([PROTOCOL_VERSION, reviewer,
                                      digests, contracts,
                                      list(INSTRUCTIONS)]
                                     ).encode("utf-8")).hexdigest()[:16]


def _clean_text(value: Any, cap: int, where: str) -> str:
    """Reviewer prose: a string, bounded, and free of control characters.

    Control characters are refused rather than stripped — silently altering
    what a human wrote would make the stored answer differ from the one they
    gave."""
    if not isinstance(value, str):
        raise ReviewError(f"{where}: expected text")
    if len(value) > cap:
        raise ReviewError(f"{where}: longer than {cap} characters")
    for ch in value:
        if ch in "\n\t":
            continue
        if unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cs"):
            raise ReviewError(f"{where}: contains a control character")
    return value


# ---- bundles ---------------------------------------------------------------------------

INSTRUCTIONS = (
    "You are one of two independent reviewers. Judge ONLY what this bundle "
    "shows you.",
    "Do not use an AI assistant. Do not open the repository. Do not look the "
    "project up.",
    "You will not see the other reviewer's answers, and they will not see "
    "yours.",
    "TRACK A — the scanner has made a claim. Decide whether it is true: "
    "confirmed, false_positive, or uncertain. Give a reason in every case.",
    "TRACK B — no claim exists. Report what you find: issues_found (with at "
    "least one issue), no_issue_observed, or uncertain.",
    "In Track B, `false_positive` is not an option: there is no claim here "
    "to be false about.",
    "If the material shown is not enough to judge, answer `uncertain` and say "
    "why. Do not go and find more — both reviewers must judge the same "
    "information.",
    "Save often. Export only when every unit is complete: a partial file is "
    "kept as a draft and is not scored.",
)


def build_bundle(packets: dict[str, list[dict[str, Any]]], reviewer: str
                 ) -> dict[str, Any]:
    """One reviewer's bundle: their packets, unchanged and in their existing
    order, plus the instructions and a checksum per track.

    The packets are NOT re-ordered or re-generated here. REAL-CORPUS-1A fixed
    each reviewer's order; regenerating it would silently change what is
    being reviewed."""
    if reviewer not in REVIEWERS:
        raise ReviewError(f"unknown reviewer {reviewer!r}")
    tracks: dict[str, Any] = {}
    for track in TRACKS:
        entries = packets.get(track)
        if not entries:
            raise ReviewError(f"{reviewer}: no {track} packet")
        for entry in entries:
            if entry.get("track") != track:
                raise ReviewError(f"{reviewer}: a {track} packet carries a "
                                  f"unit from another track")
        tracks[track] = {"units": len(entries), "digest": digest(entries),
                         "entries": entries}
    contracts = _contracts()
    return {"corpus": "REAL-CORPUS-1B",
            "protocol_version": PROTOCOL_VERSION,
            "bundle_id": bundle_identity(
                reviewer, {t: tracks[t]["digest"] for t in TRACKS}, contracts),
            "reviewer": reviewer,
            "instructions": list(INSTRUCTIONS),
            "contracts": contracts,
            "tracks": tracks}


def _contracts() -> dict[str, Any]:
    """The vocabularies a reviewer may answer with. Part of the bundle id, so
    a contract change invalidates saved progress rather than silently
    reinterpreting it."""
    return {
        "findings": {"labels": list(TRACK_A_LABELS),
                     "fields": list(TRACK_A_LABEL_FIELDS)},
        "blind": {"outcomes": list(TRACK_B_OUTCOMES),
                  "issue_fields": list(TRACK_B_ISSUE_FIELDS),
                  "other_rule": OTHER_RULE},
        "levels": list(LEVELS), "gates": list(GATES),
        "actionability": list(ACTIONABILITY),
        "evidence_sufficiency": list(EVIDENCE_SUFFICIENCY)}


def _walk(obj: Any) -> Iterable[tuple[str | None, Any]]:
    """(key, value) for EVERY node, so a check can look at the DATA rather
    than at how json.dumps happened to encode it.

    Every node means every node. The first version yielded only dict values,
    so a string sitting directly in a list, a string used as a dict KEY, and a
    top-level string were all invisible to the path check — `{"files": ["C:/
    project/x"]}` walked straight through both privacy guards. A guard that
    inspects most of the structure is a guard with a documented way round it."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value          # the key, as a key
            yield None, key           # ...and as a string, for the path check
            yield from _walk(value)
    elif isinstance(obj, list):
        for item in obj:
            yield None, item
            yield from _walk(item)
    else:
        yield None, obj


FORBIDDEN_KEYS = ("repo_id", "overlap", "has_finding", "verdict",
                  "scanner_level", "scanner_gate", "scanner_precision",
                  "fingerprint", "project_root")


def bundle_problem(bundle: dict[str, Any]) -> str | None:
    """Why a bundle may not be handed to a reviewer.

    Checked against the STRUCTURE, not a JSON dump of it. Scanning the
    encoded blob gets both halves wrong on real data: a source line
    `class A:` followed by an escaped newline reads as `A:\\` and trips the
    Windows-path rule, and a code snippet that merely contains the word
    `verdict` reads as a forbidden key. Track B packets are full of real
    source, so both fired on the first run against the corpus."""
    for key, value in _walk(bundle):
        if key in FORBIDDEN_KEYS:
            return f"carries {key}"
        if isinstance(value, str) and _PATHISH.search(value):
            return "carries a local path"
    for track in TRACKS:
        for entry in bundle["tracks"][track]["entries"]:
            if track == "findings":
                if any(entry.get(k) not in ("", None)
                       for k in TRACK_A_LABEL_FIELDS):
                    return "a Track A label is pre-filled"
            elif entry.get("outcome") or entry.get("issues"):
                return "a Track B answer is pre-filled"
    return None


# ---- the offline reviewer UI ------------------------------------------------------------

def render_ui(reviewer: str) -> str:
    """A self-contained HTML reviewer.

    No network of any kind: no <script src>, no <link href>, no fetch, no
    XHR, no WebSocket, no font or image URL. The bundle is opened from disk
    by the reviewer through a file input, progress is kept in this browser's
    localStorage, and the result is exported as a download. A test asserts
    the absence of every network primitive.

    The two tracks render through SEPARATE forms — a single form with a
    couple of hidden fields would be exactly the collapse the protocol
    forbids."""
    if reviewer not in REVIEWERS:
        raise ReviewError(f"unknown reviewer {reviewer!r}")
    return _UI_TEMPLATE.replace("__REVIEWER__", reviewer) \
                       .replace("__PROTOCOL__", str(PROTOCOL_VERSION)) \
                       .replace("__LABELS__", json.dumps(list(TRACK_A_LABELS))) \
                       .replace("__OUTCOMES__", json.dumps(list(TRACK_B_OUTCOMES))) \
                       .replace("__LEVELS__", json.dumps(list(LEVELS))) \
                       .replace("__GATES__", json.dumps(list(GATES))) \
                       .replace("__ACTION__", json.dumps(list(ACTIONABILITY))) \
                       .replace("__EVID__", json.dumps(list(EVIDENCE_SUFFICIENCY))) \
                       .replace("__ISSUEFIELDS__", json.dumps(list(TRACK_B_ISSUE_FIELDS))) \
                       .replace("__OTHER__", json.dumps(OTHER_RULE)) \
                       .replace("__REASONMAX__", str(REASON_MAX_CHARS)) \
                       .replace("__STATEMENTMAX__", str(STATEMENT_MAX_CHARS)) \
                       .replace("__EVIDENCEMAX__", str(EVIDENCE_MAX_CHARS)) \
                       .replace("__MAXISSUES__", str(MAX_ISSUES_PER_UNIT))


_UI_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>REAL-CORPUS-1B review - __REVIEWER__</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#111}
 /* The header must WRAP. At 375px the file input and the three buttons do
    not fit on one line; without wrapping the export button hangs 40px past
    the right edge and drags the whole document sideways with it. Found by
    driving the real file in a 375px browser, not by reading the CSS. */
 header{background:#1e293b;color:#fff;padding:.6rem 1rem;display:flex;
        gap:.5rem 1rem;align-items:center;flex-wrap:wrap;position:sticky;
        top:0;z-index:5}
 header b{font-size:1.05rem}
 header input[type=file]{max-width:100%;flex:1 1 10rem}
 main{max-width:60rem;margin:1rem auto;padding:0 1rem}
 .card{background:#fff;border:1px solid #d9dde3;border-radius:6px;
       padding:1rem;margin-bottom:1rem}
 pre{background:#0f172a;color:#e2e8f0;padding:.75rem;border-radius:4px;
     overflow:auto;max-height:26rem;white-space:pre-wrap}
 label{display:block;margin:.5rem 0 .15rem;font-weight:600}
 select,textarea,input{width:100%;padding:.4rem;border:1px solid #c3c9d2;
                       border-radius:4px;font:inherit;box-sizing:border-box}
 textarea{min-height:4.5rem}
 .row{display:flex;gap:.75rem;flex-wrap:wrap}
 .row>div{flex:1 1 12rem}
 .muted{color:#64748b}
 .done{color:#15803d;font-weight:600}
 .todo{color:#b45309;font-weight:600}
 .bad{color:#b91c1c;font-weight:600}
 #storagewarn{background:#fee2e2;color:#7f1d1d;padding:.15rem .5rem;
              border-radius:4px;display:none}
 button{padding:.45rem .9rem;border:1px solid #94a3b8;background:#fff;
        border-radius:4px;cursor:pointer;font:inherit}
 button.primary{background:#1e293b;color:#fff;border-color:#1e293b}
 .issue{border:1px dashed #94a3b8;border-radius:4px;padding:.6rem;
        margin:.5rem 0}
 ol.rules{max-height:9rem;overflow:auto;background:#f1f5f9;padding:.5rem 1.5rem;
          border-radius:4px}
</style></head><body>
<header>
  <b>REAL-CORPUS-1B &mdash; reviewer __REVIEWER__</b>
  <span id="progress" class="muted">no bundle loaded</span>
  <span id="storagewarn"></span>
  <span style="flex:1"></span>
  <input type="file" id="file" accept="application/json">
  <button id="prev">&larr;</button><button id="next">&rarr;</button>
  <button id="export" class="primary">Export</button>
</header>
<main>
  <div class="card" id="instructions"><em class="muted">Open your bundle
  file to begin. Nothing is sent anywhere; everything stays in this
  browser.</em></div>
  <div class="card" id="unit"></div>
</main>
<script>
const REVIEWER = "__REVIEWER__", PROTOCOL_VERSION = __PROTOCOL__;
const LABELS = __LABELS__, OUTCOMES = __OUTCOMES__, LEVELS = __LEVELS__;
const GATES = __GATES__, ACTION = __ACTION__, EVID = __EVID__;
const ISSUE_FIELDS = __ISSUEFIELDS__, OTHER = __OTHER__;
// The importer's bounds, in the browser, so the two agree about what
// "complete" means.
const REASON_MAX = __REASONMAX__, STATEMENT_MAX = __STATEMENTMAX__;
const EVIDENCE_MAX = __EVIDENCEMAX__, MAX_ISSUES = __MAXISSUES__;
let BUNDLE = null, FLAT = [], idx = 0;
// The key is NOT known until a bundle has been loaded and validated: it is
// derived from that bundle's id. Keying it by the reviewer alone would let a
// second bundle inherit answers from the first on every sample_id that
// recurred.
let KEY = null, answers = {};

function warn(msg){
  const el = document.getElementById("storagewarn");
  el.textContent = msg;
  el.style.display = msg ? "inline" : "none";
}
function store(){
  if (!KEY) return;
  try { localStorage.setItem(KEY, JSON.stringify(answers)); warn(""); }
  catch(e){
    // Never swallowed. A quota or private-mode failure means this reviewer's
    // work is not being saved, and they have to know while they can still act.
    warn("NOT SAVED (" + e.name + ") - export before you close this tab");
  }
}

// Quotes are escaped too: these values are interpolated into attributes
// (`value="${esc(...)}"`), where a bare quote closes the attribute and the
// rest of the reviewer's text becomes markup.
function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[c])); }

function opts(list, cur){ return ['<option value=""></option>'].concat(
  list.map(v => `<option${v===cur?' selected':''}>${esc(v)}</option>`)).join(""); }

// The same checks `_check_blind` makes on import, made here instead of at the
// end. A reviewer who typed a line outside the unit, an unparseable span, or
// an unlisted rule used to reach a green "complete", export, and only then be
// refused whole — with no way to tell which of 84 units was wrong.
function issueProblem(e, it){
  const rules = (e.applicable_rules||[]).map(r => r.rule_id).concat([OTHER]);
  if (!rules.includes(it.rule_id))
    return "rule_id must be one of this unit's rules, or " + OTHER;
  const lo = e.code_unit.start_line, hi = e.code_unit.end_line;
  // These two parses must accept EXACTLY what the importer accepts. Leniency
  // here is not kindness: `Number("110.0")`, `Number(" 110")` and
  // `Number("0x6e")` are all integers to JS and all refused by `int()`, and a
  // span with one stray space passed `.trim()` here and failed the anchored
  // regex there. The reviewer reached a green "complete", exported a file not
  // named _DRAFT, and had all 204 units refused over one space they could not
  // see. Same bytes, same verdict, both sides.
  if (!/^\\d+$/.test(String(it.line)))
    return "line must be digits only, with no spaces or decimal point";
  const line = Number(it.line);
  if (line < lo || line > hi)
    return "line " + line + " is outside this unit (" + lo + "-" + hi + ")";
  const m = /^(\\d+)-(\\d+)$/.exec(String(it.span));
  if (!m) return "span must be written start-end, with no spaces";
  const s = +m[1], t = +m[2];
  if (s > t) return "span starts after it ends";
  if (s < lo || t > hi)
    return "span is outside this unit (" + lo + "-" + hi + ")";
  if (line < s || line > t) return "line is outside its own span";
  if (!(it.statement||"").trim()) return "statement is required";
  if (String(it.statement).length > STATEMENT_MAX)
    return "statement is over " + STATEMENT_MAX + " characters";
  if (!(it.evidence||"").trim()) return "evidence is required";
  if (String(it.evidence).length > EVIDENCE_MAX)
    return "evidence is over " + EVIDENCE_MAX + " characters";
  if (!LEVELS.includes(it.level)) return "level is required";
  if (!ACTION.includes(it.actionability)) return "actionability is required";
  return "";
}

function complete(e){
  const a = answers[e.sample_id] || {};
  if (e.track === "findings")
    return LABELS.includes(a.label) && (a.reason||"").trim().length > 0 &&
      String(a.reason).length <= REASON_MAX &&
      LEVELS.includes(a.level) && GATES.includes(a.gate) &&
      ACTION.includes(a.actionability) && EVID.includes(a.evidence_sufficiency);
  if (!OUTCOMES.includes(a.outcome)) return false;
  const issues = a.issues || [];
  if (a.outcome === "issues_found" && issues.length === 0) return false;
  if (a.outcome !== "issues_found" && issues.length > 0) return false;
  if (issues.length > MAX_ISSUES) return false;
  return issues.every(i => issueProblem(e, i) === "");
}

function progress(){
  const done = FLAT.filter(complete).length;
  document.getElementById("progress").innerHTML =
    `<span class="${done===FLAT.length?'done':'todo'}">${done}/${FLAT.length}
     complete</span>`;
}

function renderFindings(e, a){
  return `<h3>Track A &mdash; is this claim true? <span class="muted">
    (${idx+1}/${FLAT.length})</span></h3>
  <p class="muted">rule ${esc(e.claim.rule_id)} &middot; ${esc(e.language)}
     &middot; line ${esc(e.claim.line)}</p>
  <p><b>${esc(e.claim.title)}</b><br>${esc(e.claim.detail)}</p>
  <label>the line the scanner points at</label><pre>${esc(e.claim.snippet)}</pre>
  <label>the source it was judged on (${esc(e.judged_on.source_span)})</label>
  <pre>${esc(e.judged_on.source_window)}</pre>
  <label>the rule as the catalog defines it</label>
  <pre>${esc(JSON.stringify(e.judged_on.rule_definition, null, 1))}</pre>
  <label>label</label><select data-f="label">${opts(LABELS, a.label)}</select>
  <div class="row">
   <div><label>level</label><select data-f="level">${opts(LEVELS, a.level)}</select></div>
   <div><label>gate</label><select data-f="gate">${opts(GATES, a.gate)}</select></div>
   <div><label>actionability</label><select data-f="actionability">
     ${opts(ACTION, a.actionability)}</select></div>
   <div><label>evidence</label><select data-f="evidence_sufficiency">
     ${opts(EVID, a.evidence_sufficiency)}</select></div>
  </div>
  <label>reason (required)</label>
  <textarea data-f="reason">${esc(a.reason)}</textarea>`;
}

function renderBlind(e, a){
  const rules = (e.applicable_rules||[]).map(r =>
    `<li><code>${esc(r.rule_id)}</code> &mdash; ${esc(r.title)}</li>`).join("");
  const issues = (a.issues||[]).map((it,n) => `
    <div class="issue"><b>issue ${n+1}</b>
     <span class="bad" id="problem${n}">${esc(issueProblem(e, it))}</span>
     <div class="row">
      <div><label>rule_id</label><input data-i="${n}" data-f="rule_id"
           value="${esc(it.rule_id)}" list="rulelist"></div>
      <div><label>line</label><input data-i="${n}" data-f="line"
           value="${esc(it.line)}"></div>
      <div><label>span (start-end)</label><input data-i="${n}" data-f="span"
           value="${esc(it.span)}"></div>
      <div><label>level</label><select data-i="${n}" data-f="level">
           ${opts(LEVELS, it.level)}</select></div>
      <div><label>actionability</label><select data-i="${n}" data-f="actionability">
           ${opts(ACTION, it.actionability)}</select></div>
     </div>
     <label>statement</label><textarea data-i="${n}" data-f="statement"
       >${esc(it.statement)}</textarea>
     <label>evidence</label><textarea data-i="${n}" data-f="evidence"
       >${esc(it.evidence)}</textarea>
     <button data-rm="${n}">remove issue</button></div>`).join("");
  return `<h3>Track B &mdash; is anything wrong here? <span class="muted">
    (${idx+1}/${FLAT.length})</span></h3>
  <p class="muted">${esc(e.language)} &middot; lines
     ${esc(e.code_unit.start_line)}&ndash;${esc(e.code_unit.end_line)}</p>
  <label>context above this unit</label>
  <pre>${esc(e.code_unit.file_context)}</pre>
  <label>the unit</label><pre>${esc(e.code_unit.code)}</pre>
  <label>rules that apply to this language (a menu, not a hint)</label>
  <ol class="rules">${rules}</ol>
  <datalist id="rulelist">${(e.applicable_rules||[]).map(r =>
    `<option value="${esc(r.rule_id)}">`).join("")}
    <option value="${esc(OTHER)}"></datalist>
  <label>outcome</label><select data-f="outcome">${opts(OUTCOMES, a.outcome)}</select>
  ${issues}<button id="addissue">add an issue</button>`;
}

function render(){
  if (!FLAT.length) return;
  const e = FLAT[idx], a = answers[e.sample_id] || {};
  document.getElementById("unit").innerHTML =
    e.track === "findings" ? renderFindings(e, a) : renderBlind(e, a);
  const unit = document.getElementById("unit");
  unit.querySelectorAll("[data-f]").forEach(el => {
    el.addEventListener("input", () => {
      const rec = answers[e.sample_id] || (answers[e.sample_id] = {});
      const i = el.getAttribute("data-i");
      if (i === null) { rec[el.getAttribute("data-f")] = el.value; }
      else {
        rec.issues = rec.issues || [];
        rec.issues[+i] = rec.issues[+i] || {};
        rec.issues[+i][el.getAttribute("data-f")] = el.value;
      }
      // Show the issue's problem AS IT IS TYPED. Re-rendering the whole unit
      // would take the cursor with it, so only this one message is rewritten
      // in place. Without it the validation exists but is invisible until the
      // reviewer navigates away and back, which is the same as not existing.
      (rec.issues || []).forEach((issue, n) => {
        const slot = document.getElementById("problem" + n);
        if (slot) slot.textContent = issueProblem(e, issue);
      });
      store(); progress();
    });
  });
  const add = document.getElementById("addissue");
  if (add) add.addEventListener("click", () => {
    const rec = answers[e.sample_id] || (answers[e.sample_id] = {});
    rec.issues = rec.issues || [];
    const blank = {}; ISSUE_FIELDS.forEach(f => blank[f] = "");
    rec.issues.push(blank); store(); render();
  });
  unit.querySelectorAll("[data-rm]").forEach(b => b.addEventListener("click", () => {
    answers[e.sample_id].issues.splice(+b.getAttribute("data-rm"), 1);
    store(); render();
  }));
  progress();
}

document.getElementById("file").addEventListener("change", ev => {
  const f = ev.target.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    // Validate FIRST, and only then go near stored answers. Loading progress
    // before knowing which bundle this is, is how answers from one bundle end
    // up shown against another bundle's material.
    let loaded = null;
    try { loaded = JSON.parse(r.result); }
    catch(err){ alert("This file is not readable JSON."); return; }
    if (!loaded || loaded.protocol_version !== PROTOCOL_VERSION) {
      alert("This bundle was made for protocol version " +
            (loaded && loaded.protocol_version) + ", this reviewer screen is " +
            PROTOCOL_VERSION + ". Ask for a bundle that matches.");
      return;
    }
    if (loaded.reviewer !== REVIEWER) {
      alert("This bundle belongs to " + loaded.reviewer + ", not " + REVIEWER);
      return;
    }
    // EVERY field this screen will touch is checked before anything is
    // swapped. The first version validated four of them and then threw on
    // `BUNDLE.instructions.map` - after KEY, answers, BUNDLE and FLAT had
    // already been replaced. That left the PREVIOUS bundle's form on screen,
    // still wired to its listeners, now writing through the NEW bundle's
    // storage key: judgements formed on one bundle's material saved as
    // answers about another's. The tool's own exported result file has no
    // `instructions`, so one slip in the file picker was enough.
    const bad = !loaded.bundle_id ? "it has no bundle_id"
      : !Array.isArray(loaded.instructions) ? "it carries no instructions"
      : !loaded.tracks ? "it has no tracks"
      : ["findings","blind"].map(t =>
          (!loaded.tracks[t] || !Array.isArray(loaded.tracks[t].entries) ||
           !loaded.tracks[t].entries.length)
            ? "track " + t + " has no units" : "").filter(Boolean)[0] || "";
    if (bad) {
      alert("This is not a reviewer bundle: " + bad +
            ". Nothing was loaded and your saved work is untouched.");
      return;
    }
    // Past this point the swap is all-or-nothing.
    try {
      const flat = [];
      ["findings","blind"].forEach(t =>
        loaded.tracks[t].entries.forEach(e => flat.push(e)));
      // The key is this bundle's identity. A different bundle - even the same
      // reviewer, even overlapping sample_ids - is a different key and starts
      // empty.
      const key = "rc1b-" + REVIEWER + "-" + loaded.bundle_id;
      let loadedAnswers = {};
      try { loadedAnswers = JSON.parse(localStorage.getItem(key) || "{}") || {}; }
      catch(err){ warn("saved progress could not be read (" + err.name + ")"); }
      document.getElementById("instructions").innerHTML =
        "<ul>" + loaded.instructions.map(i => "<li>" + esc(i) + "</li>").join("") + "</ul>";
      BUNDLE = loaded; FLAT = flat; KEY = key; answers = loadedAnswers;
      idx = 0; render();
    } catch(err) {
      BUNDLE = null; FLAT = []; KEY = null; answers = {}; idx = 0;
      document.getElementById("unit").innerHTML = "";
      document.getElementById("progress").textContent = "no bundle loaded";
      alert("This bundle could not be opened (" + err.name +
            "). Nothing was loaded.");
    }
  };
  r.readAsText(f);
});
document.getElementById("prev").addEventListener("click",
  () => { if (idx > 0) { idx--; render(); } });
document.getElementById("next").addEventListener("click",
  () => { if (idx < FLAT.length-1) { idx++; render(); } });
document.getElementById("export").addEventListener("click", () => {
  if (!BUNDLE) return;
  // The export carries the bundle's identity so import can prove the answers
  // belong to the material that was handed out, not merely to a reviewer.
  const digests = {};
  ["findings","blind"].forEach(t => digests[t] = BUNDLE.tracks[t].digest);
  const out = {corpus:"REAL-CORPUS-1B", protocol_version:PROTOCOL_VERSION,
               bundle_id:BUNDLE.bundle_id, reviewer:REVIEWER,
               track_digests:digests, tracks:{}};
  ["findings","blind"].forEach(t => {
    out.tracks[t] = {entries: (BUNDLE.tracks[t].entries||[]).map(e => {
      const a = answers[e.sample_id] || {}, c = JSON.parse(JSON.stringify(e));
      if (t === "findings")
        ["label","level","gate","actionability","reason","evidence_sufficiency"]
          .forEach(f => c[f] = a[f] || "");
      else { c.outcome = a.outcome || ""; c.issues = a.issues || []; }
      return c;
    })};
  });
  // `[].every(...)` is true. Without the length test an empty bundle exports
  // as complete, with no units and no _DRAFT in the name.
  out.complete = FLAT.length > 0 && FLAT.every(complete);
  const blob = new Blob([JSON.stringify(out, null, 1)], {type:"application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "result_" + REVIEWER + (out.complete ? "" : "_DRAFT") + ".json";
  a.click();
});
progress();
</script></body></html>
"""


# ---- fail-closed import ------------------------------------------------------------------

def import_result(returned: dict[str, Any],
                  bundle: dict[str, Any]) -> dict[str, Any]:
    """Accept a reviewer's file, or refuse it whole.

    Everything the reviewer was shown must come back exactly as it went out.
    Only the label fields may differ. A file that fails any check is not
    partially salvaged: labels that cannot be tied to the exact material
    they were formed on are not evidence of anything."""
    if not isinstance(returned, dict):
        raise ReviewError("the returned result is not an object")
    extra = set(returned) - RESULT_TOP_KEYS
    if extra:
        raise ReviewError(f"unexpected top-level keys {sorted(extra)}")
    missing = RESULT_TOP_KEYS - set(returned)
    if missing:
        raise ReviewError(f"missing top-level keys {sorted(missing)}")
    reviewer = returned.get("reviewer")
    if reviewer != bundle["reviewer"]:
        raise ReviewError(f"this file is from {reviewer!r} but the bundle "
                          f"belongs to {bundle['reviewer']!r}")
    if returned.get("corpus") != "REAL-CORPUS-1B":
        raise ReviewError("the result names a different corpus")
    if returned.get("protocol_version") != PROTOCOL_VERSION:
        raise ReviewError(
            f"the result was produced under protocol version "
            f"{returned.get('protocol_version')!r}, not {PROTOCOL_VERSION}")
    # The bundle id binds the answers to the exact material. Without it a
    # result from an earlier bundle, or from a tampered one, imports cleanly
    # as long as the ids happen to line up.
    if returned.get("bundle_id") != bundle["bundle_id"]:
        raise ReviewError("the result answers a different bundle")
    for track in TRACKS:
        got = ((returned.get("track_digests") or {}).get(track))
        if got != bundle["tracks"][track]["digest"]:
            raise ReviewError(f"{track}: the result's digest does not match "
                              f"the bundle it claims to answer")
    size = len(_canonical(returned).encode("utf-8"))
    if size > RESULT_MAX_BYTES:
        raise ReviewError(f"the result is {size} bytes, over the cap")

    out: dict[str, Any] = {"reviewer": reviewer,
                           "bundle_id": bundle["bundle_id"],
                           "protocol_version": PROTOCOL_VERSION, "tracks": {}}
    incomplete: list[str] = []
    for track in TRACKS:
        original = bundle["tracks"][track]["entries"]
        block = (returned.get("tracks") or {}).get(track)
        if not isinstance(block, dict):
            raise ReviewError(f"{track}: no track block returned")
        stray = set(block) - TRACK_KEYS
        if stray:
            raise ReviewError(f"{track}: unexpected keys {sorted(stray)}")
        got = block.get("entries")
        if not isinstance(got, list):
            raise ReviewError(f"{track}: no entries returned")
        out["tracks"][track] = _import_track(track, original, got, incomplete)

    # `complete` is RECOMPUTED, never trusted: the exporter writes it, and a
    # file claiming completeness it does not have would otherwise walk
    # straight into agreement.
    out["complete"] = not incomplete
    out["units"] = sum(out["tracks"][t]["units"] for t in TRACKS)
    out["incomplete"] = sorted(incomplete)
    out["answered"] = out["units"] - len(incomplete)
    if bool(returned.get("complete")) != out["complete"]:
        out["claimed_complete"] = bool(returned.get("complete"))
    if incomplete:
        # A draft. It is stored so the reviewer does not lose work, and it
        # takes no part in agreement — an unfinished opinion is not one.
        out["state"] = "draft"
    else:
        out["state"] = "accepted"
    return out


def _import_track(track: str, original: list[dict[str, Any]],
                  got: list[dict[str, Any]],
                  incomplete: list[str]) -> dict[str, Any]:
    by_id = {e["sample_id"]: e for e in original}
    seen: list[str] = []
    answers: dict[str, dict[str, Any]] = {}

    for entry in got:
        if not isinstance(entry, dict):
            raise ReviewError(f"{track}: an entry is not an object")
        extra = set(entry) - ENTRY_KEYS[track]
        if extra:
            raise ReviewError(f"{track}: unexpected keys {sorted(extra)}")
        missing_keys = ENTRY_KEYS[track] - set(entry)
        if missing_keys:
            raise ReviewError(f"{track}: entry missing {sorted(missing_keys)}")
        sid = entry["sample_id"]
        if sid in seen:
            raise ReviewError(f"{track}: duplicate sample_id in the result")
        seen.append(sid)
        source = by_id.get(sid)
        if source is None:
            raise ReviewError(f"{track}: unknown sample_id in the result")
        if entry.get("track") != track:
            raise ReviewError(f"{track}: an entry claims another track")

        # byte-for-byte on everything that was not the reviewer's to change
        for key in sorted(ENTRY_KEYS[track] - EDITABLE[track]):
            if _canonical(entry[key]) != _canonical(source[key]):
                raise ReviewError(f"{track}/{sid}: `{key}` was modified")

        answers[sid] = (_check_findings(sid, entry, incomplete) if track ==
                        "findings" else _check_blind(sid, entry, source,
                                                     incomplete))

    if len(seen) != len(original):
        raise ReviewError(f"{track}: {len(seen)} entries returned for "
                          f"{len(original)} handed out")
    if set(seen) != set(by_id):
        raise ReviewError(f"{track}: the returned ids are not the ids "
                          f"handed out")
    return {"units": len(seen), "answers": answers}


def _blank(entry: dict[str, Any], track: str) -> bool:
    if track == "findings":
        return all(not str(entry.get(k) or "").strip()
                   for k in TRACK_A_LABEL_FIELDS)
    return not str(entry.get("outcome") or "").strip() and not entry.get("issues")


def _check_findings(sid: str, entry: dict[str, Any],
                    incomplete: list[str]) -> dict[str, Any]:
    if _blank(entry, "findings"):
        incomplete.append(sid)
        return {"state": "unanswered"}
    problems = validate_findings_labels(entry)
    if problems:
        raise ReviewError(f"findings/{sid}: {problems[0]}")
    reason = _clean_text(entry["reason"], REASON_MAX_CHARS,
                         f"findings/{sid}/reason")
    return {"state": "answered",
            **{k: entry[k] for k in TRACK_A_LABEL_FIELDS if k != "reason"},
            "reason": reason}


def check_issues(where: str, issues: Any,
                 source: dict[str, Any]) -> list[dict[str, Any]]:
    """Every bound a Track B issue must satisfy, in ONE place.

    R1, R2 and R3 all answer in the same contract, so they all come through
    here. When this lived inline in `_check_blind`, `import_r3` reached only
    `validate_blind_labels` and R3 — whose judgements ARE the corpus's ground
    truth — was the least validated step in the chain: an arbitration could
    name a rule never shown, at a line outside the unit, with 50 000
    characters of prose and a NUL in it.

    The returned list is REBUILT field by field. Returning the caller's dicts
    would let an unlisted key survive whatever this function decided."""
    if not isinstance(issues, list):
        raise ReviewError(f"{where}: issues must be a list")
    if len(issues) > MAX_ISSUES_PER_UNIT:
        raise ReviewError(f"{where}: more than {MAX_ISSUES_PER_UNIT} issues")
    unit = source["code_unit"]
    start, end = int(unit["start_line"]), int(unit["end_line"])
    allowed = {str(r.get("rule_id")) for r in source.get("applicable_rules", [])}
    allowed.add(OTHER_RULE)

    checked = []
    for n, issue in enumerate(issues):
        if not isinstance(issue, dict):
            raise ReviewError(f"{where}: issue {n} is not an object")
        extra = set(issue) - ISSUE_KEYS
        if extra:
            raise ReviewError(f"{where}: issue {n} has unexpected keys "
                              f"{sorted(extra)}")
        missing = ISSUE_KEYS - set(issue)
        if missing:
            raise ReviewError(f"{where}: issue {n} is missing "
                              f"{sorted(missing)}")
        rule = str(issue.get("rule_id", ""))
        if rule not in allowed:
            raise ReviewError(f"{where}: issue {n} names rule {rule!r}, "
                              f"which is not in applicable_rules and is not "
                              f"{OTHER_RULE}")
        line = _as_line(issue.get("line"), f"{where}/issue {n}")
        if not start <= line <= end:
            raise ReviewError(f"{where}: issue {n} line {line} is outside "
                              f"the unit shown ({start}-{end})")
        span = str(issue.get("span", ""))
        m = _SPAN_RE.match(span)
        if m is None:
            raise ReviewError(f"{where}: issue {n} span {span!r} is not "
                              f"start-end")
        lo, hi = int(m.group(1)), int(m.group(2))
        if not (start <= lo <= hi <= end):
            raise ReviewError(f"{where}: issue {n} span {span} is outside "
                              f"the unit shown ({start}-{end})")
        if issue["level"] not in LEVELS:
            raise ReviewError(f"{where}: issue {n} level "
                              f"{issue['level']!r} is not one of {LEVELS}")
        if issue["actionability"] not in ACTIONABILITY:
            raise ReviewError(f"{where}: issue {n} actionability "
                              f"{issue['actionability']!r} is not one of "
                              f"{ACTIONABILITY}")
        checked.append({
            "rule_id": rule, "line": line, "span": span,
            "statement": _clean_text(issue["statement"], STATEMENT_MAX_CHARS,
                                     f"{where}/issue {n}/statement"),
            "evidence": _clean_text(issue["evidence"], EVIDENCE_MAX_CHARS,
                                    f"{where}/issue {n}/evidence"),
            "level": issue["level"], "actionability": issue["actionability"]})
    return checked


def _check_blind(sid: str, entry: dict[str, Any], source: dict[str, Any],
                 incomplete: list[str]) -> dict[str, Any]:
    if _blank(entry, "blind"):
        incomplete.append(sid)
        return {"state": "unanswered"}
    problems = validate_blind_labels(entry)
    if problems:
        raise ReviewError(f"blind/{sid}: {problems[0]}")
    return {"state": "answered", "outcome": entry["outcome"],
            "issues": check_issues(f"blind/{sid}", entry["issues"], source)}


_LINE_RE = re.compile(r"^\d+$")


def _as_line(value: Any, where: str) -> int:
    """A line number is digits, and only digits.

    `int()` is more forgiving than it looks: `int(" 110")`, `int("110\\n")` and
    `int("1_10")` all succeed. The browser's predicate is an anchored
    `^\\d+$`, so accepting those here would put the divergence back the other
    way round — an answer the reviewer's screen refuses would import cleanly,
    and the two would still disagree about what "complete" means."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ReviewError(f"{where}: line must be a number")
    if isinstance(value, str):
        if not _LINE_RE.match(value):
            raise ReviewError(f"{where}: line must be digits only, with no "
                              f"spaces or decimal point")
        return int(value)
    return value


# ---- agreement ---------------------------------------------------------------------------

def cohens_kappa(a: list[str], b: list[str],
                 categories: Iterable[str]) -> dict[str, Any]:
    """Cohen's κ plus the raw agreement it is derived from.

    Raw agreement travels WITH κ, never instead of it: with one dominant
    category the two diverge sharply, and that divergence is a finding about
    the corpus rather than something to pick the flattering number from."""
    cats = list(categories)
    n = len(a)
    if n == 0 or n != len(b):
        raise ReviewError("kappa needs two equal, non-empty label lists")
    stray = sorted({v for v in (*a, *b) if v not in cats})
    if stray:
        raise ReviewError(f"kappa: labels outside the category set: {stray}")
    observed = sum(1 for x, y in zip(a, b) if x == y) / n
    expected = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    out: dict[str, Any] = {"n": n, "raw_agreement": round(observed, 4),
                           "expected_agreement": round(expected, 4)}
    if expected >= 1.0:
        # Both reviewers used ONE category for every unit, so chance agreement
        # is already 1 and kappa is 0/0 — undefined, not perfect. Revision 1
        # returned 1.0 here and would have sailed through the 0.4 floor on a
        # pair of reviewers who never distinguished anything.
        out["kappa"] = None
        out["defined"] = False
        out["undefined_reason"] = ("expected agreement is 1.0: every answer "
                                   "on both sides used a single category")
        return out
    out["kappa"] = round((observed - expected) / (1 - expected), 4)
    out["defined"] = True
    return out


KAPPA_FLOOR = 0.4
PRIMARY = {"findings": ("label", TRACK_A_LABELS),
           "blind": ("outcome", TRACK_B_OUTCOMES)}
SECONDARY = ("level", "gate", "actionability", "evidence_sufficiency")


def agreement(r1: dict[str, Any], r2: dict[str, Any]) -> dict[str, Any]:
    """Per-track agreement. The two tracks are never pooled: 120 claims and
    84 code units answer different questions, and one combined κ would
    describe neither."""
    for side in (r1, r2):
        if side.get("state") != "accepted":
            raise ReviewError("agreement needs two ACCEPTED results; a draft "
                              "takes no part")
    # Two results, two people. Scoring a result against itself — the same file
    # passed twice, or one reviewer's answers copied under the other's name —
    # gives raw agreement 1.0 and clears every structural check, and inter-
    # rater agreement between one person and themselves is not a measurement.
    sides = {str(r1.get("reviewer")), str(r2.get("reviewer"))}
    if sides != set(REVIEWERS):
        raise ReviewError(f"agreement needs one accepted result from each of "
                          f"{sorted(REVIEWERS)}; got {sorted(sides)}")
    # The two must also have answered the SAME material. Same sample_ids is
    # not the same thing: ids are stable across a rebuild, the claims behind
    # them are not.
    if r1.get("bundle_id") == r2.get("bundle_id"):
        raise ReviewError("both results claim the same bundle_id; each "
                          "reviewer has their own bundle and their own id")
    out: dict[str, Any] = {"tracks": {}, "kappa_floor": KAPPA_FLOOR}
    for track in TRACKS:
        field, cats = PRIMARY[track]
        a1 = r1["tracks"][track]["answers"]
        a2 = r2["tracks"][track]["answers"]
        # The two accepted results must describe the SAME units. Scoring an
        # intersection would let one reviewer's omissions pick the
        # denominator, and the shortfall would never appear in the number.
        if set(a1) != set(a2):
            missing = sorted(set(a1) ^ set(a2))
            raise ReviewError(
                f"{track}: the two results cover different sample_id sets "
                f"({len(missing)} differ); agreement is not computed over an "
                f"intersection")
        both = sorted(sid for sid in a1
                      if a1[sid]["state"] == "answered"
                      and a2[sid]["state"] == "answered")
        gap = len(a1) - len(both)
        if gap:
            raise ReviewError(
                f"{track}: {gap} unit(s) are unanswered in an accepted "
                f"result; that cannot happen and is not scored around")
        primary = cohens_kappa([a1[s][field] for s in both],
                               [a2[s][field] for s in both], cats)
        block: dict[str, Any] = {
            "primary_field": field, "primary": primary,
            # an undefined kappa does NOT meet the floor
            "meets_floor": bool(primary.get("defined"))
            and primary["kappa"] >= KAPPA_FLOOR,
            "units_both_completed": len(both),
            "coverage_gap": gap,
        }
        if track == "findings":
            block["secondary"] = {
                f: cohens_kappa([a1[s][f] for s in both],
                                [a2[s][f] for s in both],
                                {"level": LEVELS, "gate": GATES,
                                 "actionability": ACTIONABILITY,
                                 "evidence_sufficiency":
                                     EVIDENCE_SUFFICIENCY}[f])
                for f in SECONDARY}
        else:
            block["issue_matching"] = _issue_matching(a1, a2, both)
        out["tracks"][track] = block
    out["quality_result_permitted"] = all(
        out["tracks"][t]["meets_floor"] for t in TRACKS)
    out["note"] = ("secondary fields and issue matching are reported with "
                   "their own denominators and never enter the kappa that "
                   "decides the floor")
    return out


def _issue_matching(a1: dict[str, Any], a2: dict[str, Any],
                    both: list[str]) -> dict[str, Any]:
    """How often the two reviewers point at the same line with the same rule.
    Reported on its own — it is a different question from whether they agreed
    that the unit has a problem at all."""
    def keys(rec: dict[str, Any]) -> set[tuple[str, int]]:
        return {(i["rule_id"], i["line"]) for i in rec.get("issues", [])}

    shared = union = 0
    for sid in both:
        k1, k2 = keys(a1[sid]), keys(a2[sid])
        shared += len(k1 & k2)
        union += len(k1 | k2)
    return {"units": len(both), "matched_issue_keys": shared,
            "union_issue_keys": union,
            "jaccard": round(shared / union, 4) if union else None,
            "matched_on": "(rule_id, line)"}


# ---- R3, prepared but never run ------------------------------------------------------------

SECONDARY_A = ("level", "gate", "actionability", "evidence_sufficiency")


def _issue_key(issue: dict[str, Any]) -> tuple[str, int]:
    """The identity of an issue for comparison: rule and line. The same key
    the issue-matching statistic uses, so the two can never disagree about
    what "the same issue" means."""
    return (str(issue.get("rule_id", "")), int(issue.get("line", 0)))


def disagreement(track: str, one: dict[str, Any],
                 two: dict[str, Any]) -> list[str]:
    """Why these two judgements need a third person, or [] if they do not.

    Wording alone is NOT a disagreement: two reviewers who reach the same
    judgement and phrase `reason` or `evidence` differently have left nothing
    to decide. Revision 1 also missed the opposite and worse case — both
    saying `issues_found` while naming entirely different problems never
    reached arbitration at all."""
    if track == "findings":
        return [f for f in ("label", *SECONDARY_A) if one.get(f) != two.get(f)]

    why: list[str] = []
    if one.get("outcome") != two.get("outcome"):
        why.append("outcome")
    k1 = {_issue_key(i): i for i in one.get("issues", [])}
    k2 = {_issue_key(i): i for i in two.get("issues", [])}
    if set(k1) != set(k2):
        why.append("issue_keys")
    for key in sorted(set(k1) & set(k2)):
        for field in ("level", "actionability"):
            if k1[key].get(field) != k2[key].get(field):
                why.append(f"issue:{key[0]}@{key[1]}:{field}")
    return why


def r3_packet(r1: dict[str, Any], r2: dict[str, Any],
              bundles: dict[str, dict[str, Any]] | None = None, *,
              salt: str) -> list[dict[str, Any]]:
    """The arbitration packet: the units the two reviewers really split on,
    each carrying the ORIGINAL material so a third person can decide.

    Revision 1 handed over two bare verdicts with no claim and no code. That
    is not something anyone can arbitrate — R3 would have been choosing
    between two opinions about material it had never seen.

    The two judgements are presented as A and B in an order that is
    reproducible for the operator and unpredictable for R3. `salt` is
    REQUIRED and has no default: the first version seeded a fixed string
    written in this file, so anyone holding the packet and the repository —
    R3 included — could replay `random.Random("REAL-CORPUS-1B-R3")` and
    recover the whole mapping. A deterministic order is only anonymous if the
    seed is not published. See `run_salt`.

    Nothing here votes and nothing reconciles automatically."""
    for side in (r1, r2):
        if side.get("state") != "accepted":
            raise ReviewError("R3 is prepared only after BOTH reviews are "
                              "accepted in full")
    if not salt or len(salt) < 16:
        raise ReviewError("r3_packet needs a run salt of at least 16 "
                          "characters; without one the A/B order is public")
    material = _material_index(bundles or {})
    rng = random.Random(salt)
    out: list[dict[str, Any]] = []
    for track in TRACKS:
        a1 = r1["tracks"][track]["answers"]
        a2 = r2["tracks"][track]["answers"]
        for sid in sorted(a1):
            one, two = a1[sid], a2.get(sid, {})
            if one.get("state") != "answered" \
                    or two.get("state") != "answered":
                continue
            why = disagreement(track, one, two)
            if not why:
                continue
            pair = [dict(one), dict(two)]
            rng.shuffle(pair)                 # A/B carry no identity
            case = {"sample_id": sid, "track": track,
                    "disputed_fields": why,
                    "material": material.get((track, sid), {}),
                    "judgement_A": pair[0], "judgement_B": pair[1],
                    "final": {}, "reason": ""}
            if not case["material"]:
                raise ReviewError(
                    f"{track}/{sid}: no original material for arbitration - "
                    f"pass the reviewers' bundles to r3_packet")
            out.append(case)
    return out


def _material_index(bundles: dict[str, dict[str, Any]]
                    ) -> dict[tuple[str, str], dict[str, Any]]:
    """The unmodifiable material per unit, taken from a bundle. Both bundles
    hold the same units, so either serves; the fields are exactly what the
    reviewers were shown."""
    keep = {"findings": ("claim", "judged_on"),
            "blind": ("code_unit", "applicable_rules")}
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for bundle in bundles.values():
        for track in TRACKS:
            for entry in bundle.get("tracks", {}).get(track, {}) \
                    .get("entries", []):
                out.setdefault((track, entry["sample_id"]),
                               {k: entry[k] for k in keep[track]})
    return out


# ---- R3 import ---------------------------------------------------------------------------

R3_CASE_KEYS = frozenset({"sample_id", "track", "disputed_fields", "material",
                          "judgement_A", "judgement_B", "final", "reason"})

# R3 answers in the reviewers' own contracts, so `final` is allowlisted
# exactly as a returned ENTRY is. Without this an arbitration could carry
# `project_root` or `repo_id` — names refused inside a bundle — straight into
# the accepted record, which is the corpus's ground truth.
FINAL_KEYS = {"findings": frozenset(TRACK_A_LABEL_FIELDS),
              "blind": frozenset({"outcome", "issues"})}


def _check_final(sid: str, track: str, final: Any,
                 material: dict[str, Any]) -> dict[str, Any]:
    """R3's judgement, through the SAME door R1's and R2's answers use.

    `validate_*_labels` alone checks the vocabulary and nothing else: not the
    key set, not the prose caps, not the control characters, and for Track B
    not one of the per-issue bounds. R3's resolved judgements are what a
    later number rests on, so this is the last place that should be the
    loosest. The judgement is REBUILT here, never stored as handed in."""
    if not isinstance(final, dict):
        raise ReviewError(f"R3/{sid}: final must be a judgement object")
    extra = set(final) - FINAL_KEYS[track]
    if extra:
        raise ReviewError(f"R3/{sid}: final has unexpected keys "
                          f"{sorted(extra)}")
    missing = FINAL_KEYS[track] - set(final)
    if missing:
        raise ReviewError(f"R3/{sid}: final is missing {sorted(missing)}")

    if track == "findings":
        problems = validate_findings_labels(final)
        if problems:
            raise ReviewError(f"R3/{sid}: {problems[0]}")
        return {**{k: final[k] for k in TRACK_A_LABEL_FIELDS if k != "reason"},
                "reason": _clean_text(final["reason"], REASON_MAX_CHARS,
                                      f"R3/{sid}/final reason")}

    problems = validate_blind_labels(final)
    if problems:
        raise ReviewError(f"R3/{sid}: {problems[0]}")
    # The material was byte-compared against the packet just above, so it is
    # the same unit the reviewers were shown — the right thing to bound
    # against.
    return {"outcome": final["outcome"],
            "issues": check_issues(f"R3/{sid}", final["issues"], material)}


def _r3_reason(sid: str, value: Any) -> str:
    reason = _clean_text(value, REASON_MAX_CHARS, f"R3/{sid}/reason")
    if not reason.strip():
        raise ReviewError(f"R3/{sid}: an arbitration needs a reason")
    return reason


def import_r3(returned: Any, packet: list[dict[str, Any]]) -> dict[str, Any]:
    """Accept R3's arbitration, or refuse it whole.

    The same discipline as R1/R2: everything R3 was shown must come back
    unchanged, only `final` and `reason` may be written, and `final` must be
    a COMPLETE judgement in the track's own contract. No vote is derived and
    no merge is performed — if R3 has not decided a case, that case is
    unresolved and says so."""
    if not isinstance(returned, list):
        raise ReviewError("the R3 result is not a list of cases")
    by_id = {(c["track"], c["sample_id"]): c for c in packet}
    seen: set[tuple[str, str]] = set()
    resolved: dict[str, dict[str, Any]] = {}
    undecided: list[str] = []

    for case in returned:
        if not isinstance(case, dict):
            raise ReviewError("an R3 case is not an object")
        stray = set(case) - R3_CASE_KEYS
        if stray:
            raise ReviewError(f"R3: unexpected keys {sorted(stray)}")
        if R3_CASE_KEYS - set(case):
            raise ReviewError(f"R3: case missing "
                              f"{sorted(R3_CASE_KEYS - set(case))}")
        key = (case["track"], case["sample_id"])
        if key in seen:
            raise ReviewError(f"R3: duplicate case {key[1]}")
        seen.add(key)
        source = by_id.get(key)
        if source is None:
            raise ReviewError(f"R3: unknown case {key[1]}")
        for field in ("disputed_fields", "material", "judgement_A",
                      "judgement_B"):
            if _canonical(case[field]) != _canonical(source[field]):
                raise ReviewError(f"R3/{key[1]}: `{field}` was modified")

        final = case["final"]
        # An UNDECIDED case is an empty object and nothing else. Treating any
        # falsy value as undecided would silently swallow `final: []`,
        # `final: 0` and `final: ""` — three ways to look decided to a human
        # reading the file and undecided to this function.
        if final == {}:
            undecided.append(key[1])
            continue
        resolved[key[1]] = {
            "track": key[0],
            "final": _check_final(key[1], key[0], final, source["material"]),
            "reason": _r3_reason(key[1], case["reason"])}

    if len(seen) != len(by_id):
        raise ReviewError(f"R3: {len(seen)} cases returned for {len(by_id)} "
                          f"handed out")
    return {"reviewer": "R3", "cases": len(by_id),
            "resolved": resolved, "undecided": sorted(undecided),
            "state": "accepted" if not undecided else "draft"}


def render_r3_ui() -> str:
    """R3's screen: the original material, then two anonymous judgements, then
    a full judgement of R3's own — including, for Track B, the issue list.

    The first version offered a Track B case an `outcome` dropdown and nothing
    else, and hard-coded `issues: []` into the export. Since `issues_found`
    with an empty list is refused, the ONLY blind arbitration it could produce
    that survived import was one denying every issue both reviewers had
    found. A screen that can express exactly one verdict is not arbitration.

    Same offline guarantees as the reviewer screen, and the same bounds: this
    form validates each issue against the unit R3 is looking at, so a decided
    case is one `import_r3` will accept."""
    return _R3_TEMPLATE \
        .replace("__PROTOCOL__", str(PROTOCOL_VERSION)) \
        .replace("__LABELS__", json.dumps(list(TRACK_A_LABELS))) \
        .replace("__OUTCOMES__", json.dumps(list(TRACK_B_OUTCOMES))) \
        .replace("__LEVELS__", json.dumps(list(LEVELS))) \
        .replace("__GATES__", json.dumps(list(GATES))) \
        .replace("__ACTION__", json.dumps(list(ACTIONABILITY))) \
        .replace("__EVID__", json.dumps(list(EVIDENCE_SUFFICIENCY))) \
        .replace("__ISSUEFIELDS__", json.dumps(list(TRACK_B_ISSUE_FIELDS))) \
        .replace("__OTHER__", json.dumps(OTHER_RULE)) \
        .replace("__REASONMAX__", str(REASON_MAX_CHARS)) \
        .replace("__STATEMENTMAX__", str(STATEMENT_MAX_CHARS)) \
        .replace("__EVIDENCEMAX__", str(EVIDENCE_MAX_CHARS)) \
        .replace("__MAXISSUES__", str(MAX_ISSUES_PER_UNIT))


_R3_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>REAL-CORPUS-1B arbitration - R3</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#111}
 /* Wraps, for the same reason the reviewer screen does: at 375px the file
    input and three buttons do not fit on one line, and an unwrapped header
    drags the whole document sideways. */
 header{background:#7c2d12;color:#fff;padding:.6rem 1rem;display:flex;
        gap:.5rem 1rem;align-items:center;flex-wrap:wrap;position:sticky;
        top:0;z-index:5}
 header input[type=file]{max-width:100%;flex:1 1 10rem}
 main{max-width:60rem;margin:1rem auto;padding:0 1rem}
 .card{background:#fff;border:1px solid #d9dde3;border-radius:6px;
       padding:1rem;margin-bottom:1rem}
 pre{background:#0f172a;color:#e2e8f0;padding:.75rem;border-radius:4px;
     overflow:auto;max-height:24rem;white-space:pre-wrap}
 .ab{display:flex;gap:1rem;flex-wrap:wrap}
 .ab>div{flex:1 1 18rem;background:#f1f5f9;border-radius:4px;padding:.6rem;
         overflow-wrap:anywhere}
 label{display:block;margin:.5rem 0 .15rem;font-weight:600}
 select,textarea,input{width:100%;padding:.4rem;border:1px solid #c3c9d2;
                       border-radius:4px;font:inherit;box-sizing:border-box}
 textarea{min-height:4rem}
 .row{display:flex;gap:.75rem;flex-wrap:wrap}
 .row>div{flex:1 1 12rem}
 .issue{border:1px dashed #94a3b8;border-radius:4px;padding:.6rem;margin:.5rem 0}
 button{padding:.45rem .9rem;border:1px solid #94a3b8;background:#fff;
        border-radius:4px;cursor:pointer;font:inherit}
 button.primary{background:#7c2d12;color:#fff;border-color:#7c2d12}
 .muted{color:#64748b}
 .bad{color:#b91c1c;font-weight:600}
 #storagewarn{background:#fee2e2;color:#7f1d1d;padding:.15rem .5rem;
              border-radius:4px;display:none}
 ol.rules{max-height:9rem;overflow:auto;background:#f1f5f9;
          padding:.5rem 1.5rem;border-radius:4px}
</style></head><body>
<header><b>Arbitration &mdash; R3</b>
 <span id="progress" class="muted">no packet loaded</span>
 <span id="storagewarn"></span>
 <span style="flex:1"></span>
 <input type="file" id="file" accept="application/json">
 <button id="prev">&larr;</button><button id="next">&rarr;</button>
 <button id="export" class="primary">Export</button></header>
<main><div class="card" id="case"><em class="muted">Open the R3 packet.
 You decide each case yourself: there is no vote and nothing is merged
 automatically.</em></div></main>
<script>
const PROTOCOL_VERSION = __PROTOCOL__;
const LABELS = __LABELS__, OUTCOMES = __OUTCOMES__, LEVELS = __LEVELS__;
const GATES = __GATES__, ACTION = __ACTION__, EVID = __EVID__;
const ISSUE_FIELDS = __ISSUEFIELDS__, OTHER = __OTHER__;
const REASON_MAX = __REASONMAX__, STATEMENT_MAX = __STATEMENTMAX__;
const EVIDENCE_MAX = __EVIDENCEMAX__, MAX_ISSUES = __MAXISSUES__;
let PACKET = null, idx = 0, KEY = null, answers = {};

function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[c])); }
function warn(msg){
  const el = document.getElementById("storagewarn");
  el.textContent = msg; el.style.display = msg ? "inline" : "none";
}
function store(){
  if (!KEY) return;
  try { localStorage.setItem(KEY, JSON.stringify(answers)); warn(""); }
  catch(e){ warn("NOT SAVED (" + e.name + ") - export before you close"); }
}
function opts(list, cur){ return ['<option value=""></option>'].concat(
  list.map(v => `<option${v===cur?' selected':''}>${esc(v)}</option>`)).join(""); }

// The same bounds import_r3 applies, applied here. R3's judgements are the
// corpus's ground truth; a screen that lets R3 write something the importer
// will refuse wastes the arbitration.
function issueProblem(c, it){
  const rules = (c.material.applicable_rules||[]).map(r => r.rule_id)
                  .concat([OTHER]);
  if (!rules.includes(it.rule_id))
    return "rule_id must be one of this unit's rules, or " + OTHER;
  const lo = c.material.code_unit.start_line, hi = c.material.code_unit.end_line;
  if (!/^\\d+$/.test(String(it.line)))
    return "line must be digits only";
  const line = Number(it.line);
  if (line < lo || line > hi)
    return "line " + line + " is outside this unit (" + lo + "-" + hi + ")";
  const m = /^(\\d+)-(\\d+)$/.exec(String(it.span));
  if (!m) return "span must be written start-end, with no spaces";
  const s = +m[1], t = +m[2];
  if (s > t) return "span starts after it ends";
  if (s < lo || t > hi) return "span is outside this unit (" + lo + "-" + hi + ")";
  if (line < s || line > t) return "line is outside its own span";
  if (!(it.statement||"").trim()) return "statement is required";
  if (String(it.statement).length > STATEMENT_MAX)
    return "statement is over " + STATEMENT_MAX + " characters";
  if (!(it.evidence||"").trim()) return "evidence is required";
  if (String(it.evidence).length > EVIDENCE_MAX)
    return "evidence is over " + EVIDENCE_MAX + " characters";
  if (!LEVELS.includes(it.level)) return "level is required";
  if (!ACTION.includes(it.actionability)) return "actionability is required";
  return "";
}

function decided(c){
  const a = answers[c.sample_id] || {};
  if (!(a.reason||"").trim() || String(a.reason).length > REASON_MAX)
    return false;
  if (c.track === "findings")
    return LABELS.includes(a.label) && LEVELS.includes(a.level) &&
      GATES.includes(a.gate) && ACTION.includes(a.actionability) &&
      EVID.includes(a.evidence_sufficiency);
  if (!OUTCOMES.includes(a.outcome)) return false;
  const issues = a.issues || [];
  if (a.outcome === "issues_found" && issues.length === 0) return false;
  if (a.outcome !== "issues_found" && issues.length > 0) return false;
  if (issues.length > MAX_ISSUES) return false;
  return issues.every(i => issueProblem(c, i) === "");
}
function progress(){
  if (!PACKET) return;
  document.getElementById("progress").textContent =
    PACKET.filter(decided).length + "/" + PACKET.length + " decided";
}
function judgement(j){
  return Object.keys(j).filter(k => k !== "state").sort()
    .map(k => `<div><b>${esc(k)}</b>: ${esc(JSON.stringify(j[k]))}</div>`)
    .join("");
}

function renderIssues(c, a){
  const rules = (c.material.applicable_rules||[]);
  const list = (a.issues||[]).map((it,n) => `
    <div class="issue"><b>issue ${n+1}</b>
     <span class="bad" id="problem${n}">${esc(issueProblem(c, it))}</span>
     <div class="row">
      <div><label>rule_id</label><input data-i="${n}" data-f="rule_id"
           value="${esc(it.rule_id)}" list="rulelist"></div>
      <div><label>line</label><input data-i="${n}" data-f="line"
           value="${esc(it.line)}"></div>
      <div><label>span (start-end)</label><input data-i="${n}" data-f="span"
           value="${esc(it.span)}"></div>
      <div><label>level</label><select data-i="${n}" data-f="level">
           ${opts(LEVELS, it.level)}</select></div>
      <div><label>actionability</label><select data-i="${n}" data-f="actionability">
           ${opts(ACTION, it.actionability)}</select></div>
     </div>
     <label>statement</label><textarea data-i="${n}" data-f="statement"
       >${esc(it.statement)}</textarea>
     <label>evidence</label><textarea data-i="${n}" data-f="evidence"
       >${esc(it.evidence)}</textarea>
     <button data-rm="${n}">remove issue</button></div>`).join("");
  return `<label>rules that apply to this unit</label>
    <ol class="rules">${rules.map(r =>
      `<li><code>${esc(r.rule_id)}</code> &mdash; ${esc(r.title)}</li>`
    ).join("")}</ol>
    <datalist id="rulelist">${rules.map(r =>
      `<option value="${esc(r.rule_id)}">`).join("")}
      <option value="${esc(OTHER)}"></datalist>
    ${list}<button id="addissue">add an issue</button>`;
}

function render(){
  if (!PACKET || !PACKET.length) return;
  const c = PACKET[idx], a = answers[c.sample_id] || {};
  const mat = c.track === "findings"
    ? `<label>the claim</label><pre>${esc(JSON.stringify(c.material.claim, null, 1))}</pre>
       <label>what it was judged on</label>
       <pre>${esc(c.material.judged_on.source_window)}</pre>`
    : `<label>context above the unit</label>
       <pre>${esc(c.material.code_unit.file_context)}</pre>
       <label>the code unit</label><pre>${esc(c.material.code_unit.code)}</pre>`;
  const form = c.track === "findings"
    ? `<label>label</label><select data-f="label">${opts(LABELS, a.label)}</select>
       <div class="row">
        <div><label>level</label><select data-f="level">${opts(LEVELS, a.level)}</select></div>
        <div><label>gate</label><select data-f="gate">${opts(GATES, a.gate)}</select></div>
        <div><label>actionability</label><select data-f="actionability">
          ${opts(ACTION, a.actionability)}</select></div>
        <div><label>evidence</label><select data-f="evidence_sufficiency">
          ${opts(EVID, a.evidence_sufficiency)}</select></div>
       </div>`
    : `<label>outcome</label><select data-f="outcome">
         ${opts(OUTCOMES, a.outcome)}</select>
       ${renderIssues(c, a)}`;
  document.getElementById("case").innerHTML =
    `<h3>${esc(c.track)} &mdash; disputed: ${esc(c.disputed_fields.join(", "))}
     <span class="muted">(${idx+1}/${PACKET.length})</span></h3>
     ${mat}
     <div class="ab"><div><b>judgement A</b>${judgement(c.judgement_A)}</div>
      <div><b>judgement B</b>${judgement(c.judgement_B)}</div></div>
     ${form}
     <label>reason for your decision (required)</label>
     <textarea data-f="reason">${esc(a.reason)}</textarea>`;

  const card = document.getElementById("case");
  card.querySelectorAll("[data-f]").forEach(el =>
    el.addEventListener("input", () => {
      const rec = answers[c.sample_id] || (answers[c.sample_id] = {});
      const i = el.getAttribute("data-i");
      if (i === null) { rec[el.getAttribute("data-f")] = el.value; }
      else {
        rec.issues = rec.issues || [];
        rec.issues[+i] = rec.issues[+i] || {};
        rec.issues[+i][el.getAttribute("data-f")] = el.value;
      }
      (rec.issues || []).forEach((issue, n) => {
        const slot = document.getElementById("problem" + n);
        if (slot) slot.textContent = issueProblem(c, issue);
      });
      store(); progress();
    }));
  const add = document.getElementById("addissue");
  if (add) add.addEventListener("click", () => {
    const rec = answers[c.sample_id] || (answers[c.sample_id] = {});
    rec.issues = rec.issues || [];
    const blank = {}; ISSUE_FIELDS.forEach(f => blank[f] = "");
    rec.issues.push(blank); store(); render();
  });
  card.querySelectorAll("[data-rm]").forEach(b =>
    b.addEventListener("click", () => {
      answers[c.sample_id].issues.splice(+b.getAttribute("data-rm"), 1);
      store(); render();
    }));
  progress();
}

// A packet's identity, so a rebuilt packet does not inherit R3's earlier
// answers. Keying by case count and first sample_id - which is what the first
// version did - collides for any two packets of the same length whose first
// case is the same unit, which is exactly what a rebuild produces.
function packetKey(p){
  let h = 5381;
  const s = JSON.stringify(p.map(c => [c.track, c.sample_id,
                                       c.disputed_fields, c.material]));
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
  return "rc1b-r3-" + p.length + "-" + h.toString(16);
}

document.getElementById("file").addEventListener("change", ev => {
  const f = ev.target.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    let loaded = null;
    try { loaded = JSON.parse(r.result); }
    catch(err){ alert("This file is not readable JSON."); return; }
    if (!Array.isArray(loaded) || !loaded.length) {
      alert("This is not an R3 packet: it is not a non-empty list of cases.");
      return;
    }
    const wrong = loaded.find(c => !c || typeof c !== "object" ||
      !c.sample_id || !c.track || !c.material || !c.judgement_A ||
      !c.judgement_B || !Array.isArray(c.disputed_fields));
    if (wrong) {
      alert("This is not an R3 packet: a case is missing its material or " +
            "judgements. Nothing was loaded.");
      return;
    }
    try {
      const key = packetKey(loaded);
      let loadedAnswers = {};
      try { loadedAnswers = JSON.parse(localStorage.getItem(key) || "{}") || {}; }
      catch(err){ warn("saved progress could not be read (" + err.name + ")"); }
      PACKET = loaded; KEY = key; answers = loadedAnswers; idx = 0;
      render();
    } catch(err) {
      PACKET = null; KEY = null; answers = {}; idx = 0;
      document.getElementById("progress").textContent = "no packet loaded";
      alert("This packet could not be opened (" + err.name + ").");
    }
  };
  r.readAsText(f);
});
document.getElementById("prev").addEventListener("click",
  () => { if (idx > 0){ idx--; render(); } });
document.getElementById("next").addEventListener("click",
  () => { if (PACKET && idx < PACKET.length-1){ idx++; render(); } });
document.getElementById("export").addEventListener("click", () => {
  if (!PACKET) return;
  const out = PACKET.map(c => {
    const a = answers[c.sample_id] || {}, copy = JSON.parse(JSON.stringify(c));
    if (decided(c)) {
      copy.final = c.track === "findings"
        ? {label:a.label, level:a.level, gate:a.gate,
           actionability:a.actionability,
           evidence_sufficiency:a.evidence_sufficiency, reason:a.reason}
        : {outcome:a.outcome,
           issues:(a.issues||[]).map(i => {
             const clean = {}; ISSUE_FIELDS.forEach(f => clean[f] = i[f]);
             return clean;
           })};
      copy.reason = a.reason;
    } else { copy.final = {}; copy.reason = ""; }
    return copy;
  });
  const done = out.length > 0 && out.every(c => Object.keys(c.final).length);
  const blob = new Blob([JSON.stringify(out, null, 1)],
                        {type:"application/json"});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "r3_result" + (done ? "" : "_DRAFT") + ".json";
  link.click();
});
</script></body></html>
"""


# ---- bounded reads and atomic writes -------------------------------------------------------

# A packet is about a dozen levels deep. The margin is for growth, not for a
# hostile file: the point is to be far below the interpreter's stack limit,
# not to be tight.
MAX_JSON_DEPTH = 64


def _json_depth(raw: bytes) -> int:
    """The deepest nesting in the document, ignoring brackets inside strings.

    Counting every `[` and `{` in the bytes is wrong on exactly this data: a
    Track B packet carries real source code, and a snippet full of braces
    reads as deep nesting. The first version refused the real corpus for
    "nested 34 deep" when the packet is a flat list of units."""
    depth = worst = 0
    in_string = escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:              # backslash
                escaped = True
            elif byte == 0x22:              # closing quote
                in_string = False
            continue
        if byte == 0x22:                    # opening quote
            in_string = True
        elif byte in (0x5B, 0x7B):          # [ {
            depth += 1
            worst = max(worst, depth)
        elif byte in (0x5D, 0x7D):          # ] }
            depth -= 1
    return worst


def read_json(path: Path, cap: int = RESULT_MAX_BYTES) -> Any:
    """Read at most `cap + 1` bytes, and refuse a file that is bigger.

    The `+ 1` is the whole point: it distinguishes "exactly at the cap" from
    "over it" without ever holding more than one byte past the limit. The
    size check therefore happens BEFORE the parse, and the size message is
    what an oversized file gets even when it is also unparseable.

    A byte cap alone is not a bound. `[` repeated 400 000 times is a twentieth
    of the cap and still blows the interpreter's stack, which reached the CLI
    as a RecursionError traceback and exit 1 instead of a refusal. Nesting is
    bounded too."""
    with path.open("rb") as fh:
        raw = fh.read(cap + 1)
    if len(raw) > cap:
        raise ReviewError(f"{path.name}: larger than {cap} bytes")
    deep = _json_depth(raw)
    if deep > MAX_JSON_DEPTH:
        raise ReviewError(f"{path.name}: nested {deep} deep, over the "
                          f"{MAX_JSON_DEPTH} this tool reads")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as e:
        raise ReviewError(f"{path.name}: not readable JSON ({e})") from None


def write_atomic(path: Path, text: str) -> None:
    """Write via a temporary file in the same directory, then replace.

    A half-written bundle or result is worse than none: it looks loadable.
    On any failure the previous file is left exactly as it was."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Re-checked here, after the directory exists, so a link planted between
    # the caller's check and this write is still caught.
    if LOCAL_DIR not in path.parent.resolve().parts:
        raise ReviewError(f"{path} resolves outside {LOCAL_DIR}/")
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()


# ---- the public boundary --------------------------------------------------------------------

PUBLIC_FORBIDDEN_KEYS = ("code", "code_unit", "claim", "snippet",
                         "source_window", "file_context", "entries", "answers",
                         "label", "outcome", "issues", "reason", "statement",
                         "evidence", "material", "judgement_A", "judgement_B",
                         "final", "resolved")


def public_output_problem(blob: str) -> str | None:
    """Why a would-be committed artefact may not be committed. Stricter than
    the sampler's: a review artefact may also not carry a LABEL.

    Checked against the STRUCTURE, for the same reason `bundle_problem` is.
    A blunt scan of the encoded text refuses `"primary_field": "label"` — a
    counts-only summary naming which field kappa was computed on, which is
    exactly the sort of thing that must stay publishable. Forbidden names are
    refused as KEYS; paths are refused wherever they appear."""
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError:
        # Unparseable: fall back to the blunt scan rather than passing it.
        return ("is not JSON and cannot be checked structurally"
                if _PATHISH.search(blob) or any(
                    f'"{k}"' in blob for k in PUBLIC_FORBIDDEN_KEYS)
                else None)
    for key, value in _walk(parsed):
        if key in PUBLIC_FORBIDDEN_KEYS:
            return f"contains {key}"
        if isinstance(value, str) and _PATHISH.search(value):
            return "contains a filesystem path"
    return None


# ---- driver ------------------------------------------------------------------------------------

LOCAL_DIR = ".quality-local"


def confined_root(root: Path) -> Path:
    """Every path this tool writes to must be inside `.quality-local`.

    Bundles, results and labels are exactly the material that must never
    reach Git. Checking the destination once, here, is cheaper than trusting
    each caller to pass the right `--root`."""
    resolved = root.resolve()
    if LOCAL_DIR not in resolved.parts:
        raise ReviewError(f"{root} is not under {LOCAL_DIR}/ - refusing to "
                          f"write bundles, results or labels outside it")
    return resolved


def confined(root: Path, *parts: str) -> Path:
    """A destination inside the root, re-checked AFTER resolution.

    Checking only the root is not enough: a directory junction or symlink at
    `<root>/handoff` sends every bundle and every reviewer screen outside
    `.quality-local` while `--root` still looks obedient. The check has to
    follow the link, so it is made on the resolved parent of the real
    target."""
    confined_root(root)
    target = root.joinpath(*parts)
    parent = target.parent if target.suffix else target
    parent.mkdir(parents=True, exist_ok=True)
    if LOCAL_DIR not in parent.resolve().parts:
        raise ReviewError(f"{target} resolves outside {LOCAL_DIR}/ - a link "
                          f"on this path leads out of the local workspace")
    return target


def handoff_dir(root: Path, reviewer: str) -> Path:
    """One directory per reviewer, holding only that reviewer's material.

    Both bundles in one folder means whoever is handed the folder can read
    the other reviewer's packet order and, once a result lands beside it,
    their answers. Independence has to survive the delivery, not just the
    tool."""
    return confined(root, "handoff", reviewer)


def run_salt(root: Path) -> str:
    """The secret that fixes R3's A/B order, created once per workspace.

    It lives beside the accepted results and is NEVER copied into
    `handoff/R3`. That is the whole point: the order has to be reproducible
    for whoever runs `r3-build` twice, and unguessable for the person holding
    the packet. A salt committed to the repository — which is what a default
    argument in this file amounts to — is neither."""
    path = confined(root, "r3_run_salt.json")
    if path.exists():
        stored = read_json(path, cap=4096)
        salt = str(stored.get("salt", ""))
        if len(salt) >= 16:
            return salt
        raise ReviewError(f"{path.name}: the stored run salt is too short")
    salt = secrets.token_hex(32)
    write_atomic(path, json.dumps(
        {"salt": salt,
         "note": "R3's A/B order depends on this. Never copy it into "
                 "handoff/R3, and never commit it."}, indent=1))
    return salt


def write_bundles(root: Path, packets_dir: Path) -> dict[str, Any]:
    """Write each reviewer's bundle and UI into their OWN directory.
    Deterministic: the same packets in produce byte-identical bundles out."""
    made: dict[str, Any] = {}
    for reviewer in REVIEWERS:
        packets = {}
        for track in TRACKS:
            path = packets_dir / f"packet_{track}_{reviewer}.json"
            packets[track] = read_json(path)["units"]
        bundle = build_bundle(packets, reviewer)
        problem = bundle_problem(bundle)
        if problem is not None:
            raise ReviewError(f"{reviewer}: bundle refused - {problem}")
        out = handoff_dir(root, reviewer)
        write_atomic(out / f"bundle_{reviewer}.json",
                     json.dumps(bundle, indent=1, sort_keys=True))
        write_atomic(out / f"review_{reviewer}.html", render_ui(reviewer))
        made[reviewer] = {
            "units": sum(bundle["tracks"][t]["units"] for t in TRACKS),
            "bundle_id": bundle["bundle_id"],
            "digests": {t: bundle["tracks"][t]["digest"] for t in TRACKS}}
    return made


def _load_bundle(root: Path, reviewer: str) -> dict[str, Any]:
    path = handoff_dir(root, reviewer) / f"bundle_{reviewer}.json"
    if not path.exists():
        raise ReviewError(f"{reviewer}: no bundle yet - run `bundle` first")
    bundle: dict[str, Any] = read_json(path)
    return bundle


def _accepted_path(root: Path, name: str) -> Path:
    return confined(root, "accepted", name)


def _load_accepted(root: Path, reviewer: str) -> dict[str, Any]:
    path = _accepted_path(root, f"result_{reviewer}.json")
    if not path.exists():
        raise ReviewError(f"{reviewer}: nothing accepted yet - run "
                          f"`import --reviewer {reviewer}` first")
    accepted: dict[str, Any] = read_json(path)
    # `accepted/` holds both files in one directory, unlike `handoff/`. The
    # filename is not evidence of anything, so the content has to say who it
    # belongs to.
    if accepted.get("reviewer") != reviewer:
        raise ReviewError(f"{path.name} contains "
                          f"{accepted.get('reviewer')!r}'s result, not "
                          f"{reviewer}'s")
    bundle = _load_bundle(root, reviewer)
    if accepted.get("bundle_id") != bundle["bundle_id"]:
        raise ReviewError(f"{reviewer}: the accepted result answers bundle "
                          f"{accepted.get('bundle_id')}, but "
                          f"handoff/{reviewer} now holds "
                          f"{bundle['bundle_id']} - re-import it")
    return accepted


def cmd_bundle(root: Path, packets: Path) -> dict[str, Any]:
    return {"command": "bundle", "bundles": write_bundles(root, packets),
            "labels": "none - no review has been started"}


def cmd_import(root: Path, reviewer: str, result: Path) -> dict[str, Any]:
    accepted = import_result(read_json(result), _load_bundle(root, reviewer))
    if accepted["state"] == "accepted":
        write_atomic(_accepted_path(root, f"result_{reviewer}.json"),
                     json.dumps(accepted, indent=1, sort_keys=True))
    return {"command": "import", "reviewer": reviewer,
            "state": accepted["state"],
            "answered": accepted["answered"], "units": accepted["units"],
            "incomplete": len(accepted.get("incomplete", [])),
            "stored": accepted["state"] == "accepted"}


def _same_material(bundles: dict[str, dict[str, Any]]) -> None:
    """The two bundles must describe THE SAME units, or the two results are
    answers to different questions and must not be scored together.

    The reviewers' orders differ by design, so the comparison is over the
    sorted non-editable fields — the material — and not over the packet."""
    fingerprints = {}
    for reviewer, bundle in bundles.items():
        per_unit = []
        for track in TRACKS:
            for entry in bundle["tracks"][track]["entries"]:
                fixed = {k: entry[k]
                         for k in sorted(ENTRY_KEYS[track] - EDITABLE[track])
                         if k != "position"}
                per_unit.append((entry["sample_id"], fixed))
        fingerprints[reviewer] = digest(sorted(per_unit,
                                               key=lambda p: p[0]))
    if len(set(fingerprints.values())) != 1:
        raise ReviewError("R1 and R2 were given different material; their "
                          "answers are not about the same units and are not "
                          "compared")


def cmd_agreement(root: Path) -> dict[str, Any]:
    bundles = {r: _load_bundle(root, r) for r in REVIEWERS}
    _same_material(bundles)
    result = agreement(_load_accepted(root, "R1"), _load_accepted(root, "R2"))
    write_atomic(confined(root, "agreement.json"),
                 json.dumps(result, indent=1, sort_keys=True))
    return {"command": "agreement", **result}


def cmd_r3_build(root: Path) -> dict[str, Any]:
    bundles = {r: _load_bundle(root, r) for r in REVIEWERS}
    _same_material(bundles)
    packet = r3_packet(_load_accepted(root, "R1"), _load_accepted(root, "R2"),
                       bundles, salt=run_salt(root))
    out = handoff_dir(root, "R3")
    write_atomic(out / "r3_packet.json", json.dumps(packet, indent=1,
                                                    sort_keys=True))
    write_atomic(out / "arbitrate_R3.html", render_r3_ui())
    return {"command": "r3-build", "cases": len(packet),
            "by_track": {t: sum(1 for c in packet if c["track"] == t)
                         for t in TRACKS}}


def cmd_r3_import(root: Path, result: Path) -> dict[str, Any]:
    packet_path = handoff_dir(root, "R3") / "r3_packet.json"
    if not packet_path.exists():
        raise ReviewError("no R3 packet yet - run `r3-build` first")
    accepted = import_r3(read_json(result), read_json(packet_path))
    if accepted["state"] == "accepted":
        write_atomic(_accepted_path(root, "r3.json"),
                     json.dumps(accepted, indent=1, sort_keys=True))
    # counts only, and never under the key names the guard forbids: what is
    # printed to a terminal is the one artefact of this tool a human is most
    # likely to paste somewhere public.
    return {"command": "r3-import", "state": accepted["state"],
            "cases": accepted["cases"],
            "cases_resolved": len(accepted["resolved"]),
            "cases_undecided": len(accepted["undecided"]),
            "stored": accepted["state"] == "accepted"}


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="real_corpus_review",
        description="REAL-CORPUS-1B human review workflow, offline. Creates "
                    "no labels: it hands material out and checks what comes "
                    "back.")
    p.add_argument("--root", required=True,
                   help=f"the gitignored workspace, which must be under "
                        f"{LOCAL_DIR}/ (e.g. {LOCAL_DIR}/real-corpus)")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("bundle", help="write handoff/R1 and handoff/R2")
    b.add_argument("--packets", default=None,
                   help="packet directory (default: <root>/packets)")

    i = sub.add_parser("import", help="accept or refuse a returned result")
    i.add_argument("--reviewer", required=True, choices=sorted(REVIEWERS))
    i.add_argument("--result", required=True, help="the file the reviewer "
                                                   "exported")

    sub.add_parser("agreement", help="kappa per track over both accepted "
                                     "results")
    sub.add_parser("r3-build", help="build the arbitration packet (both "
                                    "reviews must be accepted)")

    r = sub.add_parser("r3-import", help="accept or refuse R3's arbitration")
    r.add_argument("--result", required=True)

    args = p.parse_args(argv)
    root = Path(args.root)
    try:
        if args.command == "bundle":
            summary = cmd_bundle(root, Path(args.packets) if args.packets
                                 else root / "packets")
        elif args.command == "import":
            summary = cmd_import(root, args.reviewer, Path(args.result))
        elif args.command == "agreement":
            summary = cmd_agreement(root)
        elif args.command == "r3-build":
            summary = cmd_r3_build(root)
        else:
            summary = cmd_r3_import(root, Path(args.result))
    except ReviewError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"missing file: {e.filename}", file=sys.stderr)
        return 2
    except Exception as e:                                  # noqa: BLE001
        # A backstop, not a substitute for the checks above. Malformed input
        # used to reach the terminal as a TypeError or KeyError traceback and
        # exit 1, which reads as a crash in the tool rather than a refusal of
        # the file — and exit 1 is not the code a caller checks for.
        print(f"refused: unexpected {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    problem = public_output_problem(json.dumps(summary))
    if problem is not None:
        print(f"summary is not printable: {problem}", file=sys.stderr)
        return 3
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

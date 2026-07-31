// W4-B: the pure library-side model of Scan History & Changes.
// Run directly: node --test web/tests/libraryBaseline.test.mjs
// No network, no React, no DOM.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  baselineChoices,
  changeCounts,
  changeSummary,
  defaultScanOptions,
  gateScopeLabel,
  isNewOnlyGate,
  newOnlyBlockedReason,
  parseProjects,
  parseReports,
  scanRequestBody,
} from '../src/library.ts'

// 3 new + 9 unchanged = 12 findings; 9 unchanged + 2 resolved = the 11 the
// baseline held. The server will not store a row that fails either equation,
// so every fixture here has to satisfy them too.
const COMPARED = {
  report_id: 'r2', created_at: '2026-07-30T10:00:00.500Z', verdict: 'pass',
  findings: 12, duration_ms: 900, baseline_report_id: 'r1',
  baseline_enabled: true, baseline_findings: 11,
  new: 3, unchanged: 9, resolved: 2,
  gate_scope: 'all', seq: 2,
}

// ---- parsing: a comparison is shown only when there really was one ------------------

test('parseReports keeps the comparison fields when the row carries them', () => {
  const [row] = parseReports({ reports: [COMPARED] })
  assert.equal(row.baseline_enabled, true)
  assert.equal(row.baseline_report_id, 'r1')
  assert.deepEqual([row.new, row.unchanged, row.resolved], [3, 9, 2])
  assert.equal(row.gate_scope, 'all')
})

test('a row from a server that predates baselines reads as "not compared"', () => {
  // the W4-A shape: no baseline fields at all. Degrading to zeros WITH
  // baseline_enabled true would render as "nothing changed", which is a
  // different claim than "we did not compare".
  const [row] = parseReports({ reports: [{
    report_id: 'r0', created_at: '2026-01-01T00:00:00Z', verdict: 'block',
    findings: 4, duration_ms: 100,
  }] })
  assert.equal(row.baseline_enabled, false)
  assert.equal(row.baseline_report_id, '')
  assert.deepEqual([row.new, row.unchanged, row.resolved], [0, 0, 0])
  assert.equal(changeCounts(row), null)
  assert.equal(changeSummary(row), 'not compared')
})

test('a comparison that does not name its baseline is not shown as one', () => {
  const [row] = parseReports({ reports: [
    { ...COMPARED, baseline_report_id: '' },
  ] })
  assert.equal(row.baseline_enabled, false)
  assert.equal(row.new, 0)                    // counts drop with the claim
  assert.equal(changeCounts(row), null)
})

test('counts that do not add up are shown as "not compared"', () => {
  // the server refuses to store these, so a row like this did not come from
  // a healthy server; rendering it as a real comparison would put numbers on
  // screen that cannot all be true at once
  for (const broken of [
    { new: 90, unchanged: 90, resolved: 90, findings: 100 },  // the round's own
    { new: 4 },                                  // new + unchanged != findings
    { resolved: 5 },              // unchanged + resolved != baseline_findings
    { baseline_findings: 99 },
  ]) {
    const [row] = parseReports({ reports: [{ ...COMPARED, ...broken }] })
    assert.equal(row.baseline_enabled, false, JSON.stringify(broken))
    assert.equal(changeCounts(row), null)
    assert.equal(row.gate_scope, 'all')          // and it cannot claim a scope
    assert.equal(row.findings, broken.findings ?? COMPARED.findings)
  }
})

test('the committed sequence is carried through', () => {
  const [row] = parseReports({ reports: [COMPARED] })
  assert.equal(row.seq, 2)
  const [legacy] = parseReports({ reports: [{ report_id: 'r0', findings: 0 }] })
  assert.equal(legacy.seq, 0)                    // absent degrades, never NaN
})

test('gate_scope "new" survives only on a real comparison', () => {
  const [good] = parseReports({ reports: [
    { ...COMPARED, gate_scope: 'new' },
  ] })
  assert.equal(good.gate_scope, 'new')
  assert.equal(isNewOnlyGate(good), true)
  assert.equal(gateScopeLabel(good), 'new findings only')

  const [bogus] = parseReports({ reports: [
    { report_id: 'r9', findings: 1, gate_scope: 'new' },
  ] })
  assert.equal(bogus.gate_scope, 'all')       // no baseline => no narrowing
  assert.equal(isNewOnlyGate(bogus), false)

  const [unknown] = parseReports({ reports: [
    { ...COMPARED, gate_scope: 'sometimes' },
  ] })
  assert.equal(unknown.gate_scope, 'all')     // unknown value is not guessed
})

test('the projects list carries the same fields on its latest report', () => {
  const [p] = parseProjects({ projects: [{
    project_id: 'p1', name: 'App', kind: 'local', reports_count: 2,
    latest_report: { ...COMPARED, gate_scope: 'new' },
    last_job: { job_id: 'j1', state: 'completed',
                baseline_report_id: 'r1', new_only: true },
  }] })
  assert.equal(p.latest_report.new, 3)
  assert.equal(isNewOnlyGate(p.latest_report), true)
  assert.equal(p.last_job.baseline_report_id, 'r1')
  assert.equal(p.last_job.new_only, true)
})

// ---- the request the browser sends -------------------------------------------------

test('comparison is on by default only when there is history', () => {
  assert.equal(defaultScanOptions(true).comparePrevious, true)
  assert.equal(defaultScanOptions(false).comparePrevious, false)
  // narrowing the gate is NEVER a default, either way
  assert.equal(defaultScanOptions(true).newOnly, false)
  assert.equal(defaultScanOptions(false).newOnly, false)
  assert.equal(defaultScanOptions(true).online, false)
  assert.equal(defaultScanOptions(true).semgrep, false)
})

test('the request body has no path field of any kind', () => {
  const body = scanRequestBody({
    ...defaultScanOptions(true), baselineReportId: 'r1', newOnly: true })
  assert.deepEqual(Object.keys(body).sort(), [
    'baseline_report_id', 'compare_previous', 'new_only', 'online', 'semgrep',
  ])
  assert.equal(body.baseline_report_id, 'r1')
  assert.equal(body.new_only, true)
})

test('turning comparison off drops both the baseline and the narrowed gate', () => {
  const body = scanRequestBody({
    online: true, semgrep: true, comparePrevious: false,
    baselineReportId: 'r1', newOnly: true })
  assert.equal(body.compare_previous, false)
  assert.equal(body.baseline_report_id, '')   // never sent without a comparison
  assert.equal(body.new_only, false)
  assert.equal(body.online, true)             // ...the other options are kept
  assert.equal(body.semgrep, true)
})

test('new-only is blocked, with a reason, until it can mean something', () => {
  const withHistory = defaultScanOptions(true)
  assert.equal(newOnlyBlockedReason(withHistory, true), null)
  assert.match(newOnlyBlockedReason(defaultScanOptions(false), false),
    /previous report/)
  assert.match(
    newOnlyBlockedReason({ ...withHistory, comparePrevious: false }, true),
    /Compare with previous/)
})

// ---- what the screens render --------------------------------------------------------

test('changeSummary states the three counts, or that there was no comparison', () => {
  const [row] = parseReports({ reports: [COMPARED] })
  assert.equal(changeSummary(row), '3 new · 9 existing · 2 resolved')
  assert.equal(changeSummary(null), 'not compared')
  assert.equal(gateScopeLabel(null), '—')
})

test('a compared report with no changes still reads as compared', () => {
  const [row] = parseReports({ reports: [
    { ...COMPARED, new: 0, unchanged: 12, resolved: 0,
      baseline_findings: 12 },
  ] })
  assert.deepEqual(changeCounts(row), { new: 0, unchanged: 12, resolved: 0 })
  assert.equal(changeSummary(row), '0 new · 12 existing · 0 resolved')
})

test('the baseline picker offers this project history only, by time', () => {
  const rows = parseReports({ reports: [
    { ...COMPARED, report_id: 'r2', created_at: '2026-07-30T10:00:00.500Z' },
    { ...COMPARED, report_id: 'r1', created_at: '2026-07-29T09:30:00.000Z',
      findings: 7, new: 1, unchanged: 6, resolved: 0, baseline_findings: 6,
      seq: 1 },
  ] })
  const choices = baselineChoices(rows, '')
  assert.equal(choices.length, 3)
  assert.equal(choices[0].id, '')             // the server's own default
  assert.equal(choices[0].current, true)
  assert.match(choices[0].label, /Most recent/)
  assert.deepEqual(choices.slice(1).map((c) => c.id), ['r2', 'r1'])
  assert.match(choices[2].label, /7 finding/)
  // a label is a time and a count — never a path, never an opaque id
  for (const c of choices) {
    assert.equal(/[\\/]|report\.json/.test(c.label), false)
    if (c.id) assert.equal(c.label.includes(c.id), false)
  }
  assert.equal(baselineChoices(rows, 'r1')[2].current, true)
  assert.equal(baselineChoices([], '')[0].label, 'Most recent')
})

test('two scans in the same minute get labels that can be told apart', () => {
  // the counter-case from looking at the real screen: with minute precision
  // every entry of a freshly-scanned project read identically, which makes
  // the picker unusable for the case it exists to serve.
  const rows = parseReports({ reports: [
    { ...COMPARED, report_id: 'r2', created_at: '2026-07-30T10:00:41.900Z' },
    { ...COMPARED, report_id: 'r1', created_at: '2026-07-30T10:00:07.100Z' },
  ] })
  const labels = baselineChoices(rows, '').slice(1).map((c) => c.label)
  assert.equal(new Set(labels).size, 2)
  assert.match(labels[0], /:41 /)
  assert.match(labels[1], /:07 /)
})

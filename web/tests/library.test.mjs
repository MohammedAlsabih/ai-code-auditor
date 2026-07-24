// Deterministic node tests for the pure Library model (W4-A2) —
// run directly: node --test web/tests/library.test.mjs. No network, no React.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  filterProjects,
  formatDuration,
  formatWhen,
  gitUrlProblem,
  isActiveJobState,
  jobStateLabel,
  localPathProblem,
  parseCapabilities,
  parseJob,
  parseProjects,
  parseReports,
  parseSession,
  verdictClass,
} from '../src/library.ts'

// ---- session detection ---------------------------------------------------------------

test('parseSession accepts only a well-formed library session', () => {
  assert.deepEqual(parseSession({ mode: 'library', token: 'abc' }),
    { mode: 'library', token: 'abc' })
  assert.equal(parseSession({ mode: 'library', token: '' }), null)
  assert.equal(parseSession({ mode: 'serve', token: 'x' }), null)
  assert.equal(parseSession({ error: 'not found' }), null)
  assert.equal(parseSession(null), null)
  assert.equal(parseSession('library'), null)
})

// ---- parsers degrade, never throw ------------------------------------------------------

test('parseProjects tolerates malformed rows and fills defaults', () => {
  const rows = parseProjects({
    projects: [
      { project_id: 'a1', name: 'App', kind: 'git', location: 'gh/app',
        source_available: true, reports_count: 2,
        latest_report: { report_id: 'r1', created_at: 'x', verdict: 'pass',
          findings: 3, duration_ms: 1200 },
        last_job: { job_id: 'j1', kind: 'scan', state: 'completed',
          online: false, semgrep: false, created_at: '', finished_at: '',
          error: '', report_id: 'r1' } },
      { project_id: 'b2', kind: 'weird' },       // unknown kind -> local
      { no_id: true },                            // dropped
      'junk', null,                               // dropped
    ],
  })
  assert.equal(rows.length, 2)
  assert.equal(rows[0].latest_report.findings, 3)
  assert.equal(rows[1].kind, 'local')
  assert.equal(rows[1].name, '(unnamed)')
  assert.equal(rows[1].latest_report, null)
  assert.deepEqual(parseProjects({}), [])
  assert.deepEqual(parseProjects(null), [])
})

test('parseReports and parseJob are defensive', () => {
  assert.deepEqual(parseReports({ reports: [{ report_id: '' }, null] }), [])
  const rows = parseReports({ reports: [
    { report_id: 'r9', created_at: 'c', verdict: 'block', findings: 7,
      duration_ms: 100 }] })
  assert.equal(rows[0].verdict, 'block')
  assert.equal(parseJob({}), null)
  assert.equal(parseJob({ job: { job_id: '' } }), null)
  assert.equal(parseJob({ job: { job_id: 'j', state: 'running' } }).state,
    'running')
})

test('parseCapabilities defaults are safe', () => {
  const c = parseCapabilities({})
  assert.equal(c.gitAvailable, false)
  assert.equal(c.registryDefault, 'offline')
  assert.equal(c.storeAvailable, true)
  const d = parseCapabilities({ git_available: true, semgrep_available: true,
    store_available: false, store_error: 'bad' })
  assert.equal(d.gitAvailable, true)
  assert.equal(d.storeAvailable, false)
  assert.equal(d.storeError, 'bad')
})

// ---- job states -------------------------------------------------------------------------

test('all six job states have labels; interrupted explains itself', () => {
  for (const s of ['pending', 'running', 'completed', 'failed', 'canceled',
    'interrupted']) {
    assert.ok(jobStateLabel(s).length > 0, s)
  }
  assert.match(jobStateLabel('interrupted'), /restart/i)
  assert.equal(isActiveJobState('running'), true)
  assert.equal(isActiveJobState('pending'), true)
  assert.equal(isActiveJobState('completed'), false)
  assert.equal(isActiveJobState('interrupted'), false)
})

// ---- client-side validation mirrors ------------------------------------------------------

test('gitUrlProblem mirrors the server policy', () => {
  assert.equal(gitUrlProblem('https://github.com/a/b.git'), null)
  assert.match(gitUrlProblem('http://github.com/a/b'), /https/)
  assert.match(gitUrlProblem('git@github.com:a/b.git'), /https|Credentials/)
  assert.match(gitUrlProblem('https://u:p@github.com/a/b'), /Credentials/)
  assert.match(gitUrlProblem('https://github.com/a/b?x=1'), /Query/)
  assert.match(gitUrlProblem('https://github.com/a/b#f'), /Query/)
  assert.match(gitUrlProblem('https://github.com'), /host and a repository/)
  assert.match(gitUrlProblem(''), /Enter/)
  assert.match(gitUrlProblem('https://github.com/a b'), /invalid characters/)
})

test('localPathProblem rejects UNC, relative, and traversal', () => {
  assert.equal(localPathProblem('C:\\work\\proj'), null)
  assert.equal(localPathProblem('/home/dev/proj'), null)
  assert.match(localPathProblem('\\\\server\\share'), /UNC/)
  assert.match(localPathProblem('//server/share'), /UNC/)
  assert.match(localPathProblem('relative/path'), /absolute/)
  assert.match(localPathProblem('C:\\work\\..\\secrets'), /traversal/)
  assert.match(localPathProblem(''), /Enter/)
})

// ---- formatting ---------------------------------------------------------------------------

test('formatDuration covers ms, seconds, and minutes', () => {
  assert.equal(formatDuration(0), '—')
  assert.equal(formatDuration(250), '250 ms')
  assert.equal(formatDuration(2500), '2.5 s')
  assert.equal(formatDuration(65000), '1m 5s')
})

test('formatWhen tolerates junk and empty', () => {
  assert.equal(formatWhen(''), '—')
  assert.equal(formatWhen('not-a-date'), 'not-a-date')
  assert.match(formatWhen('2026-07-24T08:00:00Z'), /^2026-07-24 /)
})

test('verdictClass maps the three verdicts and unknown', () => {
  assert.equal(verdictClass('pass'), 'verdict-pass')
  assert.equal(verdictClass('review'), 'verdict-review')
  assert.equal(verdictClass('block'), 'verdict-block')
  assert.equal(verdictClass(''), 'verdict-unknown')
})

// ---- library filters (they survive open/close because state lives in App) -----------------

test('filterProjects applies query and state together', () => {
  const rows = parseProjects({ projects: [
    { project_id: 'a1', name: 'Shop API', location: 'gh/shop', kind: 'git',
      reports_count: 1,
      last_job: { job_id: 'j1', state: 'completed' } },
    { project_id: 'b2', name: 'Billing', location: '…/work/billing',
      kind: 'local', reports_count: 0, last_job: null },
    { project_id: 'c3', name: 'Shop Front', location: 'gh/front',
      kind: 'git', reports_count: 2,
      last_job: { job_id: 'j2', state: 'failed' } },
  ] })
  assert.equal(filterProjects(rows, '', 'all').length, 3)
  assert.equal(filterProjects(rows, 'shop', 'all').length, 2)
  assert.equal(filterProjects(rows, 'shop', 'failed').length, 1)
  assert.equal(filterProjects(rows, '', 'never').length, 1)
  assert.equal(filterProjects(rows, '', 'never')[0].name, 'Billing')
  assert.equal(filterProjects(rows, 'billing', 'completed').length, 0)
  // query matches location too
  assert.equal(filterProjects(rows, 'gh/front', 'all').length, 1)
})

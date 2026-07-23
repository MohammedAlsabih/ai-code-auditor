// Deterministic node tests for the pure AI-audit model (W3-E2) —
// run directly: node --test web/tests/aiAudit.test.mjs. No network, no React.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AUDIT_ABSENCE_NOTE,
  AUDIT_ADVISORY_BADGE,
  AUDIT_PROFILES,
  parseAuditCandidates,
  parseAuditPreview,
  parseAuditStatus,
} from '../src/aiAudit.ts'

const preview = () => ({
  units: 3,
  request_count: 3,
  files: 7,
  input_bytes: 30000,
  estimated_input_tokens: 10000,
  max_output_tokens: 4608,
  redaction_total: 1,
  redactions: { token_kv: 1 },
  cached: 0,
  fresh: 3,
  concurrency: 1,
  request_timeout_seconds: 120,
  cost_status: 'unknown',
  retention: 'unknown',
  queries: ['AI001', 'AI002'],
  projects: ['svc'],
  consent_token: '',
})

test('parseAuditPreview accepts a legal preview', () => {
  const p = parseAuditPreview(preview())
  assert.ok(p)
  assert.equal(p.units, 3)
  assert.equal(p.concurrency, 1)
  assert.equal(p.cost_status, 'unknown')
})

test('parseAuditPreview rejects malformed payloads', () => {
  assert.equal(parseAuditPreview(null), null)
  assert.equal(parseAuditPreview({ ...preview(), units: 'three' }), null)
  assert.equal(parseAuditPreview({ ...preview(), retention: 7 }), null)
})

test('parseAuditStatus keeps unit progress by project/query', () => {
  const st = parseAuditStatus({
    audit_id: 'a1',
    state: 'running',
    units: [
      { audit_unit_id: 'u'.repeat(64), project: 'svc', query_id: 'AI001',
        state: 'completed', outcome: 'issues_found', error: '', issues: 2 },
      { audit_unit_id: 'v'.repeat(64), project: 'svc', query_id: 'AI002',
        state: 'running', outcome: '', error: '', issues: 0 },
    ],
    counts: { completed: 1, running: 1 },
    outcomes: { issues_found: 1 },
    remaining: 1,
  })
  assert.ok(st)
  assert.equal(st.units.length, 2)
  assert.equal(st.units[0].query_id, 'AI001')
  assert.equal(st.remaining, 1)
  assert.equal(parseAuditStatus({ audit_id: 'a', state: 'x', units: 'no' }), null)
})

test('parseAuditCandidates drops junk and keeps reviews', () => {
  const rows = parseAuditCandidates({
    candidates: [
      {
        candidate_id: 'c'.repeat(64), project: 'svc', query_id: 'AI001',
        file: 'svc/api/x.py', line: 4, title: 'Missing tenant check',
        category: 'authorization', confidence: 'medium', summary: 's',
        evidence: [{ context_id: 'src:1', file: 'svc/api/x.py',
          line_start: 3, line_end: 6, statement: 'flows into execute' }],
        missing_context: [], suggested_action: 'inspect',
        related_static_findings: [],
        review: { decision: 'uncertain', note: 'look later', updated_at: 't' },
      },
      { junk: true },
      { candidate_id: 'd'.repeat(64) },   // missing file/title
    ],
  })
  assert.equal(rows.length, 1)
  assert.equal(rows[0].review.decision, 'uncertain')
  assert.equal(rows[0].evidence[0].line_start, 3)
})

test('profiles and advisory wording are fixed', () => {
  assert.deepEqual([...AUDIT_PROFILES], ['security', 'correctness', 'ai_code_risks', 'all'])
  assert.match(AUDIT_ADVISORY_BADGE, /advisory only/)
  assert.match(AUDIT_ABSENCE_NOTE, /NOT evidence/)
})

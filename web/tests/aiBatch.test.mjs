// Deterministic node tests for the pure batch model (W3-D) —
// run directly: node --test web/tests/aiBatch.test.mjs. No network, no React.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AI_FILTERS,
  defaultLimitsFor,
  matchesAIFilter,
  parseAISummary,
  parseBatchPreview,
  parseBatchStatus,
} from '../src/aiBatch.ts'
import { effectiveSelection, emptySelection, selectAllFiltered, toggleRow } from '../src/selection.ts'

const preview = () => ({
  findings: 3,
  review_ids: ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)],
  input_bytes: 9000,
  estimated_input_tokens: 3000,
  max_output_tokens: 3072,
  request_count: 3,
  redaction_total: 2,
  redactions: { token_kv: 2 },
  cached: 1,
  fresh: 2,
  stale: 0,
  cost_status: 'unknown',
  consent_token: '',
  provider: 'ollama',
  model: 'm',
})

test('parseBatchPreview accepts a legal preview and derives default limits', () => {
  const p = parseBatchPreview(preview())
  assert.ok(p)
  assert.equal(p.findings, 3)
  const limits = defaultLimitsFor(p)
  assert.deepEqual(limits, {
    max_requests: 3,
    max_output_tokens: 3072,
    max_input_bytes: 9000,
  })
})

test('parseBatchPreview rejects malformed payloads', () => {
  assert.equal(parseBatchPreview(null), null)
  assert.equal(parseBatchPreview({ ...preview(), findings: 'three' }), null)
  assert.equal(parseBatchPreview({ ...preview(), review_ids: 'nope' }), null)
  assert.equal(parseBatchPreview({ ...preview(), cost_status: 7 }), null)
})

test('parseBatchStatus enforces the legal states', () => {
  const st = parseBatchStatus({
    batch_id: 'b1',
    state: 'running',
    reason: '',
    items: [{ review_id: 'a'.repeat(64), state: 'pending', assessment: '', error: '' }],
    counts: { pending: 1 },
    assessments: {},
    remaining: 1,
  })
  assert.ok(st)
  assert.equal(st.state, 'running')
  assert.equal(parseBatchStatus({ batch_id: 'b', state: 'exploded', items: [] }), null)
})

test('AI filter semantics: all / specific / none', () => {
  assert.deepEqual([...AI_FILTERS], ['all', 'confirmed', 'false_positive', 'uncertain', 'none'])
  assert.ok(matchesAIFilter(undefined, 'all'))
  assert.ok(matchesAIFilter(undefined, 'none'))
  assert.ok(!matchesAIFilter('confirmed', 'none'))
  assert.ok(matchesAIFilter('confirmed', 'confirmed'))
  assert.ok(!matchesAIFilter('uncertain', 'confirmed'))
})

test('parseAISummary keeps only well-formed rows', () => {
  const map = parseAISummary({
    results: {
      r1: { assessment: 'uncertain', provider: 'ollama', created_at: 't' },
      r2: { assessment: 7 },
      r3: 'junk',
    },
  })
  assert.deepEqual(map, { r1: 'uncertain' })
  assert.deepEqual(parseAISummary(null), {})
})

test('page selection vs all-filtered/excluded resolve through the same model', () => {
  const visible = ['r1', 'r2', 'r3', 'r4']
  // page picks
  let sel = emptySelection()
  sel = toggleRow(sel, 'r2')
  sel = toggleRow(sel, 'r4')
  assert.deepEqual(effectiveSelection(sel, visible), ['r2', 'r4'])
  // all-filtered minus excluded
  let all = selectAllFiltered()
  all = toggleRow(all, 'r3') // exclude r3
  assert.deepEqual(effectiveSelection(all, visible), ['r1', 'r2', 'r4'])
  // hidden rows can never enter the payload
  assert.deepEqual(effectiveSelection(all, ['r1']), ['r1'])
})

test('frozen ids: a snapshot does not change when selection changes later', () => {
  const visible = ['r1', 'r2', 'r3']
  let sel = selectAllFiltered()
  const frozen = [...effectiveSelection(sel, visible)] // what the preview keeps
  sel = toggleRow(sel, 'r1') // user changes filters/selection afterwards
  assert.deepEqual(frozen, ['r1', 'r2', 'r3'])
  assert.deepEqual(effectiveSelection(sel, visible), ['r2', 'r3'])
})

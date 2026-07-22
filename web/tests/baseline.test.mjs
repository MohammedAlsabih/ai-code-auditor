// Deterministic node tests for the pure baseline model (W2-B2.8B2-C) —
// run directly: node --test web/tests/baseline.test.mjs.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  BASELINE_FILTERS,
  baselineSummary,
  matchesBaselineFilter,
  normalizeBaselineState,
} from '../src/baseline.ts'

test('normalizeBaselineState accepts only the two contract values', () => {
  assert.equal(normalizeBaselineState('new'), 'new')
  assert.equal(normalizeBaselineState('unchanged'), 'unchanged')
  // fabricated/malformed states are dropped, never guessed into a bucket
  for (const bad of ['existing', 'NEW', '', null, undefined, 1, {}, ['new']]) {
    assert.equal(normalizeBaselineState(bad), '')
  }
})

test('baselineSummary requires a real enabled block', () => {
  assert.equal(baselineSummary(undefined), null)
  assert.equal(baselineSummary({}), null) // report without baseline
  assert.equal(baselineSummary({ baseline: {} }), null) // enabled missing
  assert.equal(baselineSummary({ baseline: { enabled: 'yes' } }), null) // not true
  assert.equal(baselineSummary({ baseline: [1] }), null)
  const ok = baselineSummary({
    baseline: { enabled: true, gate_scope: 'new', new: 2, unchanged: 5, resolved: 1 },
  })
  assert.deepEqual(ok, {
    enabled: true, gate_scope: 'new', new: 2, unchanged: 5, resolved: 1,
  })
})

test('baselineSummary sanitizes malformed counters to 0', () => {
  const s = baselineSummary({
    baseline: { enabled: true, new: -3, unchanged: 'many', resolved: 1.5 },
  })
  assert.deepEqual(s, {
    enabled: true, gate_scope: 'all', new: 0, unchanged: 0, resolved: 0,
  })
})

test('matchesBaselineFilter buckets rows strictly', () => {
  assert.deepEqual(BASELINE_FILTERS, ['all', 'new', 'existing'])
  assert.ok(matchesBaselineFilter('new', 'all'))
  assert.ok(matchesBaselineFilter('unchanged', 'all'))
  assert.ok(matchesBaselineFilter('', 'all'))
  assert.ok(matchesBaselineFilter('new', 'new'))
  assert.ok(!matchesBaselineFilter('unchanged', 'new'))
  assert.ok(!matchesBaselineFilter('', 'new'))
  assert.ok(matchesBaselineFilter('unchanged', 'existing'))
  assert.ok(!matchesBaselineFilter('new', 'existing'))
  // a row with no state never lands in a named bucket
  assert.ok(!matchesBaselineFilter('', 'existing'))
})

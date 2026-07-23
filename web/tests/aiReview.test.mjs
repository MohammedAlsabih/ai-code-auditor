// Deterministic node tests for the pure AI-review model (W3-B) —
// run directly: node --test web/tests/aiReview.test.mjs. No network, no React.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AI_ADVISORY_NOTICE,
  assessmentTone,
  parseAIReviewResult,
  pickStoredResult,
} from '../src/aiReview.ts'

const valid = () => ({
  review_id: 'a'.repeat(64),
  provider: 'ollama',
  model: 'm',
  prompt_version: 'w3b-v1',
  latency_ms: 812,
  context_digest: 'b'.repeat(64),
  created_at: '2026-07-23T12:00:00Z',
  assessment: 'uncertain',
  confidence: 'low',
  summary: 'cannot settle without metadata',
  evidence: [{ context_id: 'finding', statement: 'the import is undeclared' }],
  missing_context: ['nupkg provision metadata'],
  suggested_action: 'inspect',
  stale: false,
})

test('parseAIReviewResult accepts a legal result', () => {
  const r = parseAIReviewResult(valid())
  assert.ok(r)
  assert.equal(r.assessment, 'uncertain')
  assert.equal(r.evidence.length, 1)
  assert.equal(r.stale, false)
})

test('parseAIReviewResult rejects illegal enum values', () => {
  assert.equal(parseAIReviewResult({ ...valid(), assessment: 'maybe' }), null)
  assert.equal(parseAIReviewResult({ ...valid(), confidence: 'huge' }), null)
  assert.equal(parseAIReviewResult({ ...valid(), suggested_action: 'yolo' }), null)
})

test('parseAIReviewResult rejects malformed evidence and lists', () => {
  assert.equal(parseAIReviewResult({ ...valid(), evidence: [] }), null)
  assert.equal(
    parseAIReviewResult({ ...valid(), evidence: Array(6).fill({ context_id: 'finding', statement: 's' }) }),
    null,
  )
  assert.equal(parseAIReviewResult({ ...valid(), evidence: [{ context_id: 7, statement: 's' }] }), null)
  assert.equal(
    parseAIReviewResult({ ...valid(), missing_context: Array(6).fill('x') }),
    null,
  )
  assert.equal(parseAIReviewResult({ ...valid(), latency_ms: 'fast' }), null)
})

test('pickStoredResult prefers the freshest non-stale result', () => {
  const stale = { ...valid(), stale: true, created_at: '2026-07-23T13:00:00Z', summary: 'newer but stale' }
  const fresh = { ...valid(), created_at: '2026-07-23T12:30:00Z', summary: 'fresh' }
  const picked = pickStoredResult({ results: [stale, fresh] })
  assert.ok(picked)
  assert.equal(picked.summary, 'fresh')
  // only stale results -> the stale one comes back, still flagged
  const onlyStale = pickStoredResult({ results: [stale] })
  assert.ok(onlyStale)
  assert.equal(onlyStale.stale, true)
})

test('pickStoredResult drops malformed rows and empty payloads', () => {
  assert.equal(pickStoredResult({ results: [{ junk: 1 }] }), null)
  assert.equal(pickStoredResult({}), null)
  assert.equal(pickStoredResult(null), null)
})

test('assessmentTone maps the three assessments', () => {
  assert.equal(assessmentTone('confirmed'), 'bad')
  assert.equal(assessmentTone('false_positive'), 'good')
  assert.equal(assessmentTone('uncertain'), 'warn')
})

test('the advisory notice says AI never changes the human review', () => {
  assert.match(AI_ADVISORY_NOTICE, /advisory/i)
  assert.match(AI_ADVISORY_NOTICE, /never changes/i)
})

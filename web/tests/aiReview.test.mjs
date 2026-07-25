// Deterministic node tests for the pure AI-review model (W3-B2, v2) —
// run directly: node --test web/tests/aiReview.test.mjs. No network, no React.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AI_ADVISORY_NOTICE,
  AI_LEGACY_NOTICE,
  defectTone,
  parseAIReviewResult,
  pickStoredResult,
} from '../src/aiReview.ts'

// a legal v2 (w3c-v3) four-axis result
const valid = () => ({
  review_id: 'a'.repeat(64),
  provider: 'ollama',
  model: 'm',
  prompt_version: 'w3c-v3',
  latency_ms: 812,
  context_digest: 'b'.repeat(64),
  created_at: '2026-07-26T12:00:00Z',
  contract_version: 2,
  match_assessment: 'matched',
  defect_assessment: 'confirmed',
  impact: 'high',
  actionability: 'actionable',
  summary: 'a committed literal credential',
  evidence: [{ context_id: 'finding', statement: 'the connection string carries a literal' }],
  missing_context: [],
  suggested_action: 'fix_code',
  stale: false,
})

// a legacy w3c-v2 (v1) history row
const legacy = () => ({
  review_id: 'c'.repeat(64),
  provider: 'ollama',
  model: 'm',
  prompt_version: 'w3c-v2',
  latency_ms: 5,
  context_digest: 'd'.repeat(64),
  created_at: '2026-07-25T12:00:00Z',
  assessment: 'confirmed',
  confidence: 'high',
  summary: 's',
  evidence: [{ context_id: 'finding', statement: 'e' }],
  missing_context: [],
  suggested_action: 'fix_code',
  stale: false,
  legacy: true,
})

test('parseAIReviewResult accepts a legal v2 four-axis result', () => {
  const r = parseAIReviewResult(valid())
  assert.ok(r)
  assert.equal(r.legacy, false)
  assert.equal(r.match_assessment, 'matched')
  assert.equal(r.defect_assessment, 'confirmed')
  assert.equal(r.impact, 'high')
  assert.equal(r.actionability, 'actionable')
  assert.equal(r.assessment, undefined)      // no conflated single verdict
})

test('parseAIReviewResult reads a legacy v1 row as Legacy history', () => {
  const r = parseAIReviewResult(legacy())
  assert.ok(r)
  assert.equal(r.legacy, true)
  assert.equal(r.stale, true)                 // legacy is always stale vs v3
  assert.equal(r.assessment, 'confirmed')
  assert.equal(r.defect_assessment, undefined)
})

test('parseAIReviewResult rejects illegal axis values', () => {
  assert.equal(parseAIReviewResult({ ...valid(), match_assessment: 'maybe' }), null)
  assert.equal(parseAIReviewResult({ ...valid(), defect_assessment: 'false_positive' }), null)
  assert.equal(parseAIReviewResult({ ...valid(), impact: 'huge' }), null)
  assert.equal(parseAIReviewResult({ ...valid(), actionability: 'sometimes' }), null)
  assert.equal(parseAIReviewResult({ ...valid(), suggested_action: 'yolo' }), null)
})

test('parseAIReviewResult rejects a v2 row missing an axis', () => {
  const noImpact = { ...valid() }
  delete noImpact.impact
  assert.equal(parseAIReviewResult(noImpact), null)
})

test('parseAIReviewResult rejects malformed evidence and lists', () => {
  assert.equal(parseAIReviewResult({ ...valid(), evidence: [] }), null)
  assert.equal(
    parseAIReviewResult({ ...valid(), evidence: Array(6).fill({ context_id: 'finding', statement: 's' }) }),
    null,
  )
  assert.equal(parseAIReviewResult({ ...valid(), evidence: [{ context_id: 7, statement: 's' }] }), null)
  assert.equal(parseAIReviewResult({ ...valid(), missing_context: Array(6).fill('x') }), null)
  assert.equal(parseAIReviewResult({ ...valid(), latency_ms: 'fast' }), null)
})

test('pickStoredResult prefers the freshest non-stale, non-legacy result', () => {
  const stale = { ...valid(), stale: true, created_at: '2026-07-26T13:00:00Z', summary: 'newer but stale' }
  const fresh = { ...valid(), created_at: '2026-07-26T12:30:00Z', summary: 'fresh' }
  const picked = pickStoredResult({ results: [stale, fresh] })
  assert.ok(picked)
  assert.equal(picked.summary, 'fresh')
  // a legacy row is never preferred over nothing-fresh — it comes back flagged
  const onlyLegacy = pickStoredResult({ results: [legacy()] })
  assert.ok(onlyLegacy)
  assert.equal(onlyLegacy.legacy, true)
})

test('pickStoredResult drops malformed rows and empty payloads', () => {
  assert.equal(pickStoredResult({ results: [{ junk: 1 }] }), null)
  assert.equal(pickStoredResult({}), null)
  assert.equal(pickStoredResult(null), null)
})

test('defectTone maps the three defect assessments (no lone confirmed badge)', () => {
  assert.equal(defectTone('confirmed'), 'bad')
  assert.equal(defectTone('acceptable'), 'good')
  assert.equal(defectTone('uncertain'), 'warn')
})

test('advisory + legacy notices', () => {
  assert.match(AI_ADVISORY_NOTICE, /advisory/i)
  assert.match(AI_ADVISORY_NOTICE, /never changes/i)
  assert.match(AI_LEGACY_NOTICE, /Legacy/i)
  assert.match(AI_LEGACY_NOTICE, /No Apply/i)
})

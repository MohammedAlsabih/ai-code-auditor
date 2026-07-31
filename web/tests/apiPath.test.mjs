// The request-composition rule, extracted from apiFetch so it can be tested
// without a browser. Run: node --test web/tests/apiPath.test.mjs
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { resolveApiPath } from '../src/apiPath.ts'

const LIB = '/api/library/reports/0123456789abcdef'

test('single-report serve mode uses the path unchanged', () => {
  assert.equal(resolveApiPath('', '/api/report'), '/api/report')
  assert.equal(resolveApiPath('', '/api/coverage'), '/api/coverage')
  assert.equal(resolveApiPath('', '/api/ai/reviews'), '/api/ai/reviews')
})

test('library endpoints are server-global and never take the base', () => {
  assert.equal(resolveApiPath(LIB, '/api/library/projects'),
    '/api/library/projects')
  assert.equal(resolveApiPath(LIB, '/api/library/reports/abc'),
    '/api/library/reports/abc')
})

test('a report endpoint under a library base keeps ONE /api segment', () => {
  // the defect this pins: `${base}${path}` produced
  // /api/library/reports/<rid>/api/report, which the dispatcher forwards as
  // /api/api/report — a 404 on every report the library tried to open.
  assert.equal(resolveApiPath(LIB, '/api/report'), `${LIB}/report`)
  assert.equal(resolveApiPath(LIB, '/api/coverage'), `${LIB}/coverage`)
  assert.equal(resolveApiPath(LIB, '/api/ai/reviews'), `${LIB}/ai/reviews`)
  assert.equal(resolveApiPath(LIB, '/api/source?path=a.py'),
    `${LIB}/source?path=a.py`)
  for (const path of ['/api/report', '/api/ai/audit/x', '/api/reviews/r1']) {
    assert.equal(resolveApiPath(LIB, path).includes('/api/', 1), false)
  }
})

test('a path that is not under /api is appended as-is', () => {
  assert.equal(resolveApiPath(LIB, '/health'), `${LIB}/health`)
})

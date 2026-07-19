// Deterministic node tests for level normalization — the SAME vectors as the
// Python side (tests/test_web_levels.py). Run: node web/tests/levels.test.mjs
import assert from 'node:assert/strict'

import { levelColor, normalizeLevel } from '../src/levels.ts'

let passed = 0
function test(name, fn) {
  fn()
  passed += 1
  console.log(`  ok - ${name}`)
}

test('absent level falls back to legacy severity', () => {
  assert.equal(normalizeLevel(undefined, 'red'), 'error')
  assert.equal(normalizeLevel(null, 'red'), 'error')
  assert.equal(normalizeLevel(undefined, 'yellow'), 'warning')
  assert.equal(normalizeLevel(undefined, 'blue'), 'note')
})

test('valid level wins over conflicting severity', () => {
  assert.equal(normalizeLevel('error', 'blue'), 'error')
  assert.equal(normalizeLevel('note', 'red'), 'note')
})

test('present-but-invalid level never falls back to severity', () => {
  assert.equal(normalizeLevel('none', 'red'), '')   // SARIF "none" unused by us
  assert.equal(normalizeLevel('bogus', 'red'), '')
  assert.equal(normalizeLevel('', 'red'), '')
  assert.equal(normalizeLevel({}, 'red'), '')
  assert.equal(normalizeLevel([], 'red'), '')
  assert.equal(normalizeLevel(5, 'red'), '')
})

test('unknown severity with absent level is unclassified', () => {
  assert.equal(normalizeLevel(undefined, 'purple'), '')
})

test('levelColor is display-only derivation', () => {
  assert.equal(levelColor('error'), 'red')
  assert.equal(levelColor('warning'), 'yellow')
  assert.equal(levelColor('note'), 'blue')
  assert.equal(levelColor(''), '')
})

console.log(`${passed} level tests passed`)

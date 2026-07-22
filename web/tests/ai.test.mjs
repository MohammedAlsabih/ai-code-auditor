// Deterministic node tests for the pure AI-providers model (W3-A) —
// run directly: node --test web/tests/ai.test.mjs. No network, no React.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AI_STATUSES,
  PROBE_NOTICE,
  parseModelIds,
  parseProviders,
  statusTooltip,
} from '../src/ai.ts'

test('parseProviders keeps only well-formed rows', () => {
  const rows = parseProviders({
    providers: [
      { provider: 'openai', display: 'OpenAI', configured: true,
        key_present: true, locality: 'remote' },
      { provider: 'ollama', display: 'Ollama', configured: 'yes',
        key_present: 0, locality: 'local' },
      { provider: '', display: 'Broken', locality: 'remote' },
      { provider: 'x', display: 'X', locality: 'mars' },
      'not-an-object',
    ],
  })
  assert.equal(rows.length, 2)
  assert.deepEqual(rows[0], { provider: 'openai', display: 'OpenAI',
    configured: true, key_present: true, locality: 'remote' })
  // non-boolean flags are normalized to false, never truthy-guessed
  assert.equal(rows[1].configured, false)
  assert.equal(rows[1].key_present, false)
})

test('parseProviders degrades to empty on malformed payloads', () => {
  for (const bad of [undefined, null, 42, 'x', {}, { providers: 'x' }]) {
    assert.deepEqual(parseProviders(bad), [])
  }
})

test('parseModelIds keeps non-empty strings only', () => {
  assert.deepEqual(parseModelIds({ models: ['a', '', 3, null, 'b'] }), ['a', 'b'])
  assert.deepEqual(parseModelIds({}), [])
  assert.deepEqual(parseModelIds(null), [])
})

test('statusTooltip covers every legal status and never echoes input', () => {
  for (const s of AI_STATUSES) {
    const tip = statusTooltip(s)
    assert.ok(tip.length > 5, s)
  }
  // unknown/hostile statuses get the generic line, not an echo
  const hostile = statusTooltip('sk-SECRET C:\\Users\\x')
  assert.equal(hostile, 'The request failed.')
  assert.ok(!hostile.includes('sk-SECRET'))
})

test('the probe notice matches the spec text', () => {
  assert.equal(PROBE_NOTICE,
    'Connection tests send a fixed probe only. Reports and source code are not sent.')
})

test('no Groq anywhere in the AI model', async () => {
  const fs = await import('node:fs/promises')
  const url = new URL('../src/ai.ts', import.meta.url)
  const src = await fs.readFile(url, 'utf-8')
  assert.ok(!src.toLowerCase().includes('groq'))
})

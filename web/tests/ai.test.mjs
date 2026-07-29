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
  // W3-A2 added kind/capabilities/reason/version. A payload that omits them —
  // an older server — must degrade to a plain HTTP provider claiming NOTHING,
  // never to one that appears to support everything.
  assert.deepEqual(rows[0], { provider: 'openai', display: 'OpenAI',
    configured: true, key_present: true, locality: 'remote',
    kind: 'http', capabilities: [], reason: '', version: null,
    installed: null, supported: false,
    experimental_capabilities: [], experimental_enabled: false })
  // non-boolean flags are normalized to false, never truthy-guessed
  assert.equal(rows[1].configured, false)
  assert.equal(rows[1].key_present, false)
})

test('parseProviders carries CLI provider facts without guessing them', () => {
  const rows = parseProviders({
    providers: [
      { provider: 'claude_cli', display: 'Claude Code CLI', configured: true,
        key_present: false, locality: 'remote', kind: 'cli',
        capabilities: ['test', 'review', 'fixed_audit', 7], reason: '',
        version: '2.1.116' },
      { provider: 'codex_cli', display: 'Codex CLI', configured: false,
        key_present: false, locality: 'remote', kind: 'cli',
        capabilities: [], reason: 'the command was not found on this machine',
        version: null },
      // a CLI claiming to be local must still be read as the server sent it;
      // locality is the server's call, not the browser's
      { provider: 'weird', display: 'W', locality: 'remote', kind: 'nonsense',
        capabilities: 'not-a-list', reason: 42, version: 9 },
    ],
  })
  assert.equal(rows[0].kind, 'cli')
  assert.deepEqual(rows[0].capabilities, ['test', 'review', 'fixed_audit'])
  assert.equal(rows[0].version, '2.1.116')
  assert.equal(rows[1].configured, false)
  assert.ok(rows[1].reason.length > 0)
  // an unknown kind falls back to http, and junk fields are dropped
  assert.equal(rows[2].kind, 'http')
  assert.deepEqual(rows[2].capabilities, [])
  assert.equal(rows[2].reason, '')
  assert.equal(rows[2].version, null)
})

test('installed is not supported', () => {
  const [row] = parseProviders({
    providers: [
      { provider: 'codex_cli', display: 'Codex CLI', configured: false,
        key_present: false, locality: 'remote', kind: 'cli',
        capabilities: [], reason: 'no verified contract',
        version: '1.0.0', installed: true, supported: false },
    ],
  })
  // the program runs, and the UI must still not offer it
  assert.equal(row.installed, true)
  assert.equal(row.supported, false)
  assert.equal(row.configured, false)
  assert.deepEqual(row.capabilities, [])
})

test('an experimental capability is carried but not counted as executable', () => {
  const [row] = parseProviders({
    providers: [
      { provider: 'claude_cli', display: 'Claude Code CLI', configured: true,
        key_present: false, locality: 'remote', kind: 'cli',
        capabilities: ['test'],
        experimental_capabilities: ['review', 'fixed_audit', 9],
        experimental_enabled: 'yes',   // not a boolean -> false
        reason: '', version: null, installed: true, supported: true },
    ],
  })
  // what may run now, and what merely exists, are different lists
  assert.deepEqual(row.capabilities, ['test'])
  assert.deepEqual(row.experimental_capabilities, ['review', 'fixed_audit'])
  // a non-boolean opt-in is never read as consent
  assert.equal(row.experimental_enabled, false)
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

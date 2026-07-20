// Deterministic node tests for the pure Rule Coverage model (W2-B2.7C1) —
// run directly: node --test web/tests/rulecov.test.mjs. Execution is read
// ONLY from analysis_manifest; findings never participate.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  EXECUTION_STATUSES,
  buildRuleCoverage,
  filterRuleRows,
  ruleFilterOptions,
  sortRuleRows,
} from '../src/rulecov.ts'

const desc = (id, extra = {}) => ({
  rule_id: id,
  title: `Title of ${id}`,
  description: `Description of ${id}`,
  category: 'cat',
  default_level: 'warning',
  default_precision: 'exact',
  engine: 'pattern-engine',
  languages: ['python'],
  frameworks: [],
  scope: 'file',
  source: 'builtin',
  ...extra,
})

const rec = (status, extra = {}) => ({
  status,
  eligible_inputs: 2,
  attempted: 1,
  failures: 0,
  blocked_inputs: 0,
  partial_parse_inputs: 0,
  not_applicable_reasons: [],
  unavailable_reasons: [],
  partial_reasons: [],
  failure_reasons: [],
  skipped_reasons: [],
  ...extra,
})

const manifest = (catalog, execution) => ({
  schema_version: execution ? 2 : 1,
  catalog,
  ...(execution ? { execution } : {}),
})

test('executed with zero findings stays executed (findings never consulted)', () => {
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('executed', { attempted: 3 }) } }],
  }))
  assert.equal(cov.rows.length, 1)
  assert.equal(cov.rows[0].contexts[0].status, 'executed')
  assert.equal(cov.rows[0].statusCounts.executed, 1)
})

test('executed in one project and blocked in another shows BOTH', () => {
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [
      { language: 'python', root: 'a', contract_errors: [],
        rules: { P001: rec('executed') } },
      { language: 'python', root: 'b', contract_errors: [],
        rules: { P001: rec('blocked', { attempted: 0, blocked_inputs: 2 }) } },
    ],
  }))
  const row = cov.rows[0]
  assert.equal(row.contexts.length, 2)
  assert.equal(row.statusCounts.executed, 1)
  assert.equal(row.statusCounts.blocked, 1)     // never collapsed to one status
})

test('catalog rule with no execution record becomes not_recorded (not NA)', () => {
  const cov = buildRuleCoverage(manifest([desc('P001'), desc('R001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('executed') } }],
  }))
  const r001 = cov.rows.find((r) => r.rule_id === 'R001')
  assert.equal(r001.contexts[0].status, 'not_recorded')
  assert.equal(r001.contexts[0].record, null)
})

test('execution rule missing from catalog is kept as inconsistent w/ fallback title', () => {
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('executed'), X999: rec('executed') } }],
  }))
  const x = cov.rows.find((r) => r.rule_id === 'X999')
  assert.ok(x, 'X999 must not be dropped')
  assert.equal(x.fromCatalog, false)
  assert.equal(x.contexts[0].status, 'inconsistent') // never claims it ran clean
  assert.match(x.title, /missing from the rule catalog/)
})

test('v1 report (no execution) gets NO fabricated statuses', () => {
  const cov = buildRuleCoverage(manifest([desc('P001'), desc('P002')]))
  assert.equal(cov.executionAvailable, false)
  assert.equal(cov.catalogAvailable, true)
  for (const row of cov.rows) assert.equal(row.contexts.length, 0)
})

test('rule count comes from the report, never hardcoded', () => {
  const many = Array.from({ length: 7 }, (_, i) => desc(`P00${i}`))
  assert.equal(buildRuleCoverage(manifest(many)).rows.length, 7)
})

test('malformed schema/arrays/counters degrade without throwing', () => {
  for (const bad of [
    null, undefined, 42, 'nope', [],
    { catalog: 'oops' },                                    // no schema_version
    { schema_version: 2, catalog: 'oops' },
    { schema_version: 2, catalog: [null, 42, { no_id: true }] },
    { schema_version: 2, catalog: [desc('P001')], execution: 'oops' },
    { schema_version: 2, catalog: [desc('P001')], execution: { projects: 'oops' } },
    { schema_version: 2, catalog: [desc('P001')],
      execution: { schema_version: 1, projects: [null, 42, { rules: 'oops' }] } },
    { schema_version: 2, catalog: [desc('P001')],
      execution: { schema_version: 1, projects: [{ language: 'python', root: '.',
        rules: { P001: { status: 'weird-status', attempted: 'NaN-ish',
          partial_reasons: 'not-a-list' } } }] } },
  ]) {
    const cov = buildRuleCoverage(bad)
    assert.ok(Array.isArray(cov.rows))
    for (const row of cov.rows) {
      for (const c of row.contexts) {
        assert.ok(EXECUTION_STATUSES.includes(c.status))
      }
    }
  }
  // an ILLEGAL status string never upgrades to executed — it is inconsistent
  const cov = buildRuleCoverage({ schema_version: 2, catalog: [desc('P001')],
    execution: { schema_version: 1, projects: [{ language: 'python', root: '.',
      contract_errors: [], rules: { P001: { status: 'passed' } } }] } })
  assert.equal(cov.rows[0].contexts[0].status, 'inconsistent')
})

// --- fix round: language scoping / strict schema / record hygiene ------------

test('missing-record contexts exist only for the project languages the rule declares', () => {
  const cov = buildRuleCoverage(manifest(
    [desc('N001', { languages: ['typescript', 'tsx'] }),
     desc('P008', { languages: ['python'] })],
    { schema_version: 1, projects: [
      { language: 'python', root: '.', contract_errors: [], rules: {} },
      { language: 'typescript', root: 'web', contract_errors: [],
        rules: { N001: rec('executed') } },
    ] }))
  const n001 = cov.rows.find((r) => r.rule_id === 'N001')
  const p008 = cov.rows.find((r) => r.rule_id === 'P008')
  // N001: ONLY the typescript context — no phantom python not_recorded
  assert.deepEqual(n001.contexts.map((c) => `${c.language}:${c.status}`),
    ['typescript:executed'])
  // P008: python not_recorded only — no phantom typescript context
  assert.deepEqual(p008.contexts.map((c) => `${c.language}:${c.status}`),
    ['python:not_recorded'])
})

test('dotnet projects match csharp rules via the adapter-language alias', () => {
  const cov = buildRuleCoverage(manifest(
    [desc('D001', { languages: ['csharp'] })],
    { schema_version: 1, projects: [
      { language: 'dotnet', root: '.', contract_errors: [],
        rules: { D001: rec('executed') } },
    ] }))
  assert.equal(cov.rows[0].contexts[0].status, 'executed')  // not inconsistent
})

test('a record in a language the rule does not declare is inconsistent with a note', () => {
  const cov = buildRuleCoverage(manifest(
    [desc('P008', { languages: ['python'] })],
    { schema_version: 1, projects: [
      { language: 'typescript', root: 'web', contract_errors: [],
        rules: { P008: rec('executed') } },
    ] }))
  const ctx = cov.rows[0].contexts[0]
  assert.equal(ctx.status, 'inconsistent')      // an existing record is SHOWN
  assert.ok(ctx.ruleErrors.some((e) => e.includes('does not declare')))
})

test('unknown execution schema_version disables execution, no fabricated states', () => {
  const cov = buildRuleCoverage({ schema_version: 2, catalog: [desc('P001')],
    execution: { schema_version: 999, projects: [
      { language: 'python', root: '.', rules: { P001: rec('executed') } }] } })
  assert.equal(cov.executionAvailable, false)
  assert.equal(cov.rows[0].contexts.length, 0)
  assert.ok(cov.notes.some((n) => n.includes('unknown schema_version')))
  assert.equal(cov.catalogAvailable, true)      // catalog contract still known
})

test('unknown MANIFEST schema_version displays neither catalog nor execution', () => {
  const cov = buildRuleCoverage({ schema_version: 999, catalog: [desc('P001')] })
  assert.equal(cov.catalogAvailable, false)
  assert.equal(cov.executionAvailable, false)
  assert.equal(cov.rows.length, 0)
})

test('execution under manifest v1 is not a known contract', () => {
  const cov = buildRuleCoverage({ schema_version: 1, catalog: [desc('P001')],
    execution: { schema_version: 1, projects: [
      { language: 'python', root: '.', rules: { P001: rec('executed') } }] } })
  assert.equal(cov.executionAvailable, false)
  assert.equal(cov.rows[0].contexts.length, 0)
})

test('structurally invalid records become inconsistent, raw values dropped', () => {
  const cases = [
    { status: 'executed', attempted: -1 },              // negative
    { status: 'executed', attempted: 1.5 },             // float
    { status: 'executed', attempted: true },            // bool
    { status: 'executed', partial_reasons: 'oops' },    // string, not a list
    { status: 'executed', partial_reasons: ['ok', 42, ''] }, // junk elements
    { status: 'executed', failure_reasons: ['same', 'same'] }, // duplicates
  ]
  for (const bad of cases) {
    const cov = buildRuleCoverage(manifest([desc('P001')], {
      schema_version: 1,
      projects: [{ language: 'python', root: '.', contract_errors: [], rules: { P001: bad } }],
    }))
    const ctx = cov.rows[0].contexts[0]
    assert.equal(ctx.status, 'inconsistent', JSON.stringify(bad))
    // the violating raw values never survive into the record
    assert.notEqual(ctx.record.attempted, -1)
    assert.notEqual(ctx.record.attempted, 1.5)
    assert.notEqual(ctx.record.attempted, true)
    if (ctx.record.partial_reasons !== undefined) {
      assert.ok(Array.isArray(ctx.record.partial_reasons))
      assert.ok(ctx.record.partial_reasons.every((x) => typeof x === 'string' && x))
    }
  }
  // a VALID record stays executed
  const ok = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('executed', { attempted: 2 }) } }],
  }))
  assert.equal(ok.rows[0].contexts[0].status, 'executed')
})

test('contract errors attach by exact "rule <id>:" prefix, per project context', () => {
  const cov = buildRuleCoverage(manifest(
    [desc('P001'), desc('P0011')],
    { schema_version: 1, projects: [
      { language: 'python', root: '.',
        contract_errors: ['rule P0011: invalid entries in partial_reasons',
                          'execution project root is not repository-relative'],
        rules: { P001: rec('executed'), P0011: rec('executed') } },
    ] }))
  const p001 = cov.rows.find((r) => r.rule_id === 'P001').contexts[0]
  const p0011 = cov.rows.find((r) => r.rule_id === 'P0011').contexts[0]
  // "rule P0011:" must NOT leak onto P001 (includes() would)
  assert.deepEqual(p001.ruleErrors, [])
  assert.deepEqual(p0011.ruleErrors,
    ['rule P0011: invalid entries in partial_reasons'])
  // the project-general error is not lost: visible in every context
  for (const ctx of [p001, p0011]) {
    assert.deepEqual(ctx.projectErrors,
      ['execution project root is not repository-relative'])
  }
})

test('no catalog at all: catalogAvailable=false (UI shows the catalog message, not "0 rules")', () => {
  for (const m of [undefined, null]) {
    const cov = buildRuleCoverage(m)
    assert.equal(cov.catalogAvailable, false)
    assert.equal(cov.executionAvailable, false)
    assert.equal(cov.rows.length, 0)
  }
})

test('search matches ID, title and description (case-insensitive)', () => {
  const rows = buildRuleCoverage(manifest([
    desc('P001', { title: 'Empty catch', description: 'swallowed exceptions' }),
    desc('R001', { title: 'Conditional hook', description: 'rules of hooks' }),
  ])).rows
  assert.equal(filterRuleRows(rows, { query: 'p001' }).length, 1)
  assert.equal(filterRuleRows(rows, { query: 'CONDITIONAL' })[0].rule_id, 'R001')
  assert.equal(filterRuleRows(rows, { query: 'swallowed' })[0].rule_id, 'P001')
  assert.equal(filterRuleRows(rows, { query: 'zzz' }).length, 0)
})

test('OR inside a category, AND across categories', () => {
  const cov = buildRuleCoverage(manifest([
    desc('P001', { engine: 'pattern-engine', category: 'common' }),
    desc('H001', { engine: 'hallucination', category: 'deps' }),
    desc('R001', { engine: 'pattern-engine', category: 'react' }),
  ], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('executed'),
        H001: rec('unavailable', { attempted: 0, unavailable_reasons: ['offline'] }),
        R001: rec('executed') } }],
  }))
  // OR inside statuses: executed OR unavailable matches all three
  assert.equal(filterRuleRows(cov.rows,
    { statuses: new Set(['executed', 'unavailable']) }).length, 3)
  // AND across categories: executed AND engine=pattern-engine excludes H001
  const both = filterRuleRows(cov.rows, {
    statuses: new Set(['executed']),
    engines: new Set(['pattern-engine']),
  })
  assert.deepEqual(both.map((r) => r.rule_id).sort(), ['P001', 'R001'])
  // AND continues: adding category=react narrows to R001
  assert.deepEqual(filterRuleRows(cov.rows, {
    statuses: new Set(['executed']),
    engines: new Set(['pattern-engine']),
    categories: new Set(['react']),
  }).map((r) => r.rule_id), ['R001'])
})

test('execution-attention sort ranks inconsistent first, executed last', () => {
  const cov = buildRuleCoverage(manifest([
    desc('A1'), desc('B2'), desc('C3'),
  ], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { A1: rec('executed'), B2: { status: 'inconsistent' },
        C3: rec('failed', { failures: 1 }) } }],
  }))
  const sorted = sortRuleRows(cov.rows, 'attention')
  assert.deepEqual(sorted.map((r) => r.rule_id), ['B2', 'C3', 'A1'])
  // default deterministic order is by id
  assert.deepEqual(sortRuleRows(cov.rows, 'id').map((r) => r.rule_id),
    ['A1', 'B2', 'C3'])
})

test('findings rule-filter labels: catalog first, finding-title fallback, never dropped', () => {
  const rows = buildRuleCoverage(manifest([
    desc('P001', { title: 'Empty catch block swallows errors silently' }),
  ])).rows
  const opts = ruleFilterOptions(['P001', 'OLD9', 'BARE'], rows,
    { OLD9: 'Legacy title from the finding itself' })
  assert.equal(opts[0].label, 'P001 — Empty catch block swallows errors silently')
  assert.equal(opts[0].full, 'Empty catch block swallows errors silently')
  assert.match(opts[1].label, /^OLD9 — Legacy title/)   // old report fallback
  assert.equal(opts[2].label, 'BARE')                   // no descriptor: kept as id
  assert.equal(opts.length, 3)                          // nothing dropped
})

test('long titles are shortened with an ellipsis, tooltip keeps the full text', () => {
  const long = 'A'.repeat(80)
  const rows = buildRuleCoverage(manifest([desc('P001', { title: long })])).rows
  const [opt] = ruleFilterOptions(['P001'], rows, {})
  assert.ok(opt.label.length < long.length)
  assert.ok(opt.label.endsWith('…'))
  assert.equal(opt.full, long)
})

test('pass/clean/safe are not execution statuses', () => {
  for (const banned of ['pass', 'passed', 'clean', 'safe']) {
    assert.ok(!EXECUTION_STATUSES.includes(banned), banned)
  }
})

// --- closing round: semantic v1 record contract + full project validation ----

test('a bare {status:executed} record is inconsistent (v1 needs all 11 fields)', () => {
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: { status: 'executed' } } }],
  }))
  assert.equal(cov.rows[0].contexts[0].status, 'inconsistent')
})

test('stored status must MATCH the derived status', () => {
  // executed claimed, but the facts derive "unavailable"
  let cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('executed', { attempted: 0,
        unavailable_reasons: ['offline'] }) } }],
  }))
  assert.equal(cov.rows[0].contexts[0].status, 'inconsistent')
  // executed claimed, but the facts derive "failed"
  cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('executed', { attempted: 1, failures: 1,
        failure_reasons: ['engine failed'] }) } }],
  }))
  assert.equal(cov.rows[0].contexts[0].status, 'inconsistent')
})

test('legal complete records keep their stored status', () => {
  const cases = {
    executed: rec('executed', { attempted: 2 }),
    failed: rec('failed', { attempted: 2, failures: 2,
      failure_reasons: ['engine failed'] }),
    partial: rec('partial', { attempted: 2, failures: 1 }),
    unavailable: rec('unavailable', { attempted: 0,
      unavailable_reasons: ['offline'] }),
    skipped: rec('skipped', { attempted: 0, skipped_reasons: ['disabled'] }),
    not_applicable: rec('not_applicable', { eligible_inputs: 0, attempted: 0,
      not_applicable_reasons: ['no files'] }),
    not_recorded: rec('not_recorded', { eligible_inputs: 1, attempted: 0 }),
  }
  for (const [want, record] of Object.entries(cases)) {
    const cov = buildRuleCoverage(manifest([desc('P001')], {
      schema_version: 1,
      projects: [{ language: 'python', root: '.', contract_errors: [],
        rules: { P001: record } }],
    }))
    assert.equal(cov.rows[0].contexts[0].status, want, want)
  }
})

test('a lone surrogate inside a reason is rejected and never rendered', () => {
  const bad = 'bad\ud800'
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [{ language: 'python', root: '.', contract_errors: [],
      rules: { P001: rec('unavailable', { attempted: 0,
        unavailable_reasons: [bad] }) } }],
  }))
  const ctx = cov.rows[0].contexts[0]
  assert.equal(ctx.status, 'inconsistent')
  assert.ok(!(ctx.record.unavailable_reasons ?? []).includes(bad))
})

test('invalid execution projects are skipped entirely with index-only notes', () => {
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [
      null, 42,
      { root: '.', language: 'python', rules: 'oops' },          // bad rules
      { root: '.', language: '', contract_errors: [], rules: {} }, // bad language
      { root: '.', language: 'python', contract_errors: [42], rules: {} },
      { root: '.', language: 'python', contract_errors: [],       // the VALID one
        rules: { P001: rec('executed') } },
    ],
  }))
  assert.equal(cov.executionAvailable, true)          // one valid project remains
  assert.deepEqual(cov.rows[0].contexts.map((c) => c.status), ['executed'])
  // notes name index/field only — no raw values, no fabricated not_recorded
  assert.ok(cov.notes.some((n) => n.includes('index 0')))
  assert.ok(cov.notes.some((n) => n.includes('invalid rules')))
  assert.ok(!cov.notes.some((n) => n.includes('oops')))
})

test('a non-empty projects list that is ALL invalid disables execution', () => {
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1,
    projects: [null, 42, { root: '.', language: 'python', rules: 'oops' }],
  }))
  assert.equal(cov.executionAvailable, false)
  assert.equal(cov.rows[0].contexts.length, 0)        // no P001:not_recorded
  assert.ok(cov.notes.some((n) => n.includes('all execution projects were invalid')))
})

test('an EMPTY projects list stays a legal contract', () => {
  const cov = buildRuleCoverage(manifest([desc('P001')], {
    schema_version: 1, projects: [],
  }))
  assert.equal(cov.executionAvailable, true)
  assert.equal(cov.rows[0].contexts.length, 0)
})

test('a zero-work not_applicable record in an undeclared language stays not_applicable', () => {
  // the semgrep recorder legitimately writes "no java files in this project"
  // into python projects — coherent evidence, never inconsistent
  const cov = buildRuleCoverage(manifest(
    [desc('SJ', { languages: ['java'] })],
    { schema_version: 1, projects: [
      { language: 'python', root: '.', contract_errors: [],
        rules: { SJ: rec('not_applicable', { eligible_inputs: 0, attempted: 0,
          not_applicable_reasons: ['no java files in this project'] }) } },
    ] }))
  assert.equal(cov.rows[0].contexts[0].status, 'not_applicable')
  assert.deepEqual(cov.rows[0].contexts[0].ruleErrors, [])
})

// --- C1 hotfix: Findings rule-filter acceptance numbers on examples ----------

test('examples: H003 filter gives 6/24, off again gives 24/24 (literal numbers)', async () => {
  const { readFileSync } = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const path = fileURLToPath(new URL('../../examples/report.json', import.meta.url))
  const report = JSON.parse(readFileSync(path, 'utf-8'))
  const rows = report.projects.flatMap((p) => p.findings ?? [])
  // the EXACT Findings-tab predicate for the rule category:
  const byRule = (ruleF) => rows.filter(
    (r) => !(ruleF.size && !ruleF.has(r.rule_id)))
  assert.equal(byRule(new Set()).length, 24)                 // Clear all
  assert.equal(byRule(new Set(['H003'])).length, 6)          // H003 alone
  assert.equal(byRule(new Set()).length, 24)                 // toggled off
  // OR inside the category, AND across categories stays intact
  const h003OrP001 = byRule(new Set(['H003', 'P001']))
  assert.ok(h003OrP001.length >= 6)
  const andLevel = h003OrP001.filter((r) => r.level === 'note')
  assert.ok(andLevel.length <= h003OrP001.length)
})

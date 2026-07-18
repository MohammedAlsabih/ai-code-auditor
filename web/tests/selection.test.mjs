// Deterministic node tests for the pure selection model (no JS framework —
// run directly: node web/tests/selection.test.mjs). These are the mandatory
// acceptance cases from the W2-B2.5 selection-integrity fix round.
import assert from 'node:assert/strict'

import {
  dedupeIds,
  effectiveSelection,
  emptySelection,
  isSelected,
  selectAllFiltered,
  togglePage,
  toggleRow,
} from '../src/selection.ts'

let passed = 0
function test(name, fn) {
  fn()
  passed += 1
  console.log(`  ok - ${name}`)
}

test('hidden selected row never reaches the payload', () => {
  // review=unreviewed filter; A picked; A turns confirmed and drops out of
  // the filtered set -> payload/counter must both exclude it
  let sel = emptySelection()
  sel = toggleRow(sel, 'A')
  const visibleAfterStatusChange = ['B', 'C'] // A no longer matches the filter
  const eff = effectiveSelection(sel, visibleAfterStatusChange)
  assert.deepEqual(eff, [])
  assert.equal(eff.includes('A'), false)
})

test('select-all then unchecking a page keeps the other pages', () => {
  let sel = selectAllFiltered()
  sel = togglePage(sel, ['A', 'B'], false) // page 1 unchecked
  const eff = effectiveSelection(sel, ['A', 'B', 'C', 'D'])
  assert.deepEqual(eff, ['C', 'D']) // rest of the filtered set survives
})

test('select-all then unchecking one row keeps everything else', () => {
  let sel = selectAllFiltered()
  sel = toggleRow(sel, 'A')
  const eff = effectiveSelection(sel, ['A', 'B', 'C'])
  assert.deepEqual(eff, ['B', 'C'])
  // re-checking the row brings it back
  sel = toggleRow(sel, 'A')
  assert.deepEqual(effectiveSelection(sel, ['A', 'B', 'C']), ['A', 'B', 'C'])
})

test('duplicate review_ids collapse to unique ids', () => {
  assert.deepEqual(dedupeIds(['X', 'X', 'Y']), ['X', 'Y'])
  const all = selectAllFiltered()
  assert.deepEqual(effectiveSelection(all, ['X', 'X', 'Y']), ['X', 'Y'])
  let sel = emptySelection()
  sel = toggleRow(sel, 'X')
  assert.deepEqual(effectiveSelection(sel, ['X', 'X', 'Y']), ['X'])
})

test('effective selection is always an intersection with visible ids', () => {
  let sel = emptySelection()
  sel = togglePage(sel, ['A', 'B', 'C'], true)
  assert.deepEqual(effectiveSelection(sel, ['B']), ['B']) // narrowed filter
  assert.deepEqual(effectiveSelection(sel, []), [])       // zero matches
  const all = selectAllFiltered()
  assert.deepEqual(effectiveSelection(all, []), [])
})

test('isSelected mirrors the model in both modes', () => {
  let sel = selectAllFiltered()
  assert.equal(isSelected(sel, 'A'), true)
  sel = toggleRow(sel, 'A')
  assert.equal(isSelected(sel, 'A'), false)
  let p = emptySelection()
  assert.equal(isSelected(p, 'A'), false)
  p = toggleRow(p, 'A')
  assert.equal(isSelected(p, 'A'), true)
})

console.log(`${passed} selection tests passed`)

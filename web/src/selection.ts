// Pure selection model for bulk review (W2-B2.5).
//
// Model: {mode:'picked', picked:Set} for explicit row/page picks, or
// {mode:'all', excluded:Set} after "Select all N filtered" — unchecking rows
// or pages while in 'all' only grows `excluded`, so the rest of the filtered
// set stays selected (no silent materialize-to-empty loss).
//
// The ONE source of truth consumed by the payload, the counter and the bulk
// bar is effectiveSelection(): the intersection of the model with the
// DEDUPLICATED currently-visible (filtered) ids. A row hidden by a filter or
// by its own status change can therefore never reach a batch payload, and a
// malformed report with duplicate review_ids can never produce duplicates.

export type Selection =
  | { mode: 'picked'; picked: Set<string> }
  | { mode: 'all'; excluded: Set<string> }

export function emptySelection(): Selection {
  return { mode: 'picked', picked: new Set() }
}

export function selectAllFiltered(): Selection {
  return { mode: 'all', excluded: new Set() }
}

/** Deduplicated visible ids — always applied before anything else. */
export function dedupeIds(ids: readonly string[]): string[] {
  return [...new Set(ids)]
}

/** The unified effective selection: model ∩ visible, deduped, order-stable. */
export function effectiveSelection(sel: Selection, visibleIds: readonly string[]): string[] {
  const vis = dedupeIds(visibleIds)
  if (sel.mode === 'all') return vis.filter((id) => !sel.excluded.has(id))
  return vis.filter((id) => sel.picked.has(id))
}

export function isSelected(sel: Selection, id: string): boolean {
  return sel.mode === 'all' ? !sel.excluded.has(id) : sel.picked.has(id)
}

/** Toggle one row. In 'all' mode this only edits `excluded` — never collapses
 * the mode, so every other filtered row stays selected. */
export function toggleRow(sel: Selection, id: string): Selection {
  if (sel.mode === 'all') {
    const excluded = new Set(sel.excluded)
    if (excluded.has(id)) excluded.delete(id)
    else excluded.add(id)
    return { mode: 'all', excluded }
  }
  const picked = new Set(sel.picked)
  if (picked.has(id)) picked.delete(id)
  else picked.add(id)
  return { mode: 'picked', picked }
}

/** Check/uncheck a whole page. Same 'all'-preserving rule as toggleRow. */
export function togglePage(sel: Selection, pageIds: readonly string[], on: boolean): Selection {
  if (sel.mode === 'all') {
    const excluded = new Set(sel.excluded)
    for (const id of pageIds) {
      if (on) excluded.delete(id)
      else excluded.add(id)
    }
    return { mode: 'all', excluded }
  }
  const picked = new Set(sel.picked)
  for (const id of pageIds) {
    if (on) picked.add(id)
    else picked.delete(id)
  }
  return { mode: 'picked', picked }
}

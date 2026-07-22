// Pure baseline model (W2-B2.8B2-C) — Node-testable, no React.
//
// A report scanned with --baseline marks every finding with
// baseline_state: 'new' | 'unchanged'. The UI shows a New/Existing badge and
// an All/New/Existing filter — but ONLY for reports whose summary carries a
// real baseline block: reports without a baseline get NO fabricated states
// and no active filter, and a malformed/unknown state value is treated as
// "no state" rather than guessed.

export type BaselineFilter = 'all' | 'new' | 'existing'

export const BASELINE_FILTERS: BaselineFilter[] = ['all', 'new', 'existing']

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

/** Strict state normalization: only the two contract values survive. */
export function normalizeBaselineState(v: unknown): 'new' | 'unchanged' | '' {
  return v === 'new' || v === 'unchanged' ? v : ''
}

export interface BaselineSummary {
  enabled: boolean
  gate_scope: string
  new: number
  unchanged: number
  resolved: number
}

/** The summary.baseline block, or null when the report has no (valid)
 * baseline — the strict gate for showing any baseline UI at all. */
export function baselineSummary(summary: unknown): BaselineSummary | null {
  if (!isObj(summary)) return null
  const b = summary.baseline
  if (!isObj(b) || b.enabled !== true) return null
  const num = (x: unknown): number =>
    typeof x === 'number' && Number.isInteger(x) && x >= 0 ? x : 0
  return {
    enabled: true,
    gate_scope: typeof b.gate_scope === 'string' ? b.gate_scope : 'all',
    new: num(b.new),
    unchanged: num(b.unchanged),
    resolved: num(b.resolved),
  }
}

/** Row predicate for the All/New/Existing filter. `state` is the row's
 * (already normalized) baseline state; '' rows only appear in reports
 * without a baseline, where the filter is not rendered — but if a mixed
 * report ever occurs, unstated rows match only 'all' (never fabricated
 * into a bucket). */
export function matchesBaselineFilter(
  state: string,
  filter: BaselineFilter,
): boolean {
  if (filter === 'all') return true
  if (filter === 'new') return state === 'new'
  return state === 'unchanged'
}

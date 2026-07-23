// Pure batch AI-review model (W3-D) — Node-testable, no React, no network.
//
// The review_ids are FROZEN at preview time: the panel snapshots the
// effective selection (page picks, or all-filtered minus excluded) and later
// filter changes never alter a running batch's payload.

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

export interface AIBatchPreview {
  findings: number
  review_ids: string[]
  input_bytes: number
  estimated_input_tokens: number
  max_output_tokens: number
  request_count: number
  redaction_total: number
  cached: number
  fresh: number
  stale: number
  cost_status: string
  estimated_cost_usd?: number
  consent_token: string
  provider: string
  model: string
}

export function parseBatchPreview(raw: unknown): AIBatchPreview | null {
  if (!isObj(raw)) return null
  if (!Array.isArray(raw.review_ids)) return null
  const ids = raw.review_ids.filter((r): r is string => typeof r === 'string')
  for (const k of ['findings', 'input_bytes', 'estimated_input_tokens',
    'max_output_tokens', 'request_count', 'redaction_total',
    'cached', 'fresh', 'stale'] as const) {
    if (typeof raw[k] !== 'number') return null
  }
  if (typeof raw.cost_status !== 'string') return null
  return {
    findings: raw.findings as number,
    review_ids: ids,
    input_bytes: raw.input_bytes as number,
    estimated_input_tokens: raw.estimated_input_tokens as number,
    max_output_tokens: raw.max_output_tokens as number,
    request_count: raw.request_count as number,
    redaction_total: raw.redaction_total as number,
    cached: raw.cached as number,
    fresh: raw.fresh as number,
    stale: raw.stale as number,
    cost_status: raw.cost_status,
    estimated_cost_usd:
      typeof raw.estimated_cost_usd === 'number' ? raw.estimated_cost_usd : undefined,
    consent_token: typeof raw.consent_token === 'string' ? raw.consent_token : '',
    provider: typeof raw.provider === 'string' ? raw.provider : '',
    model: typeof raw.model === 'string' ? raw.model : '',
  }
}

export const BATCH_STATES = [
  'pending', 'running', 'completed', 'failed', 'canceled', 'interrupted',
] as const

export interface AIBatchItem {
  review_id: string
  state: string
  assessment: string
  error: string
}

export interface AIBatchStatus {
  batch_id: string
  state: (typeof BATCH_STATES)[number]
  reason: string
  items: AIBatchItem[]
  counts: Record<string, number>
  assessments: Record<string, number>
  remaining: number
}

export function parseBatchStatus(raw: unknown): AIBatchStatus | null {
  if (!isObj(raw)) return null
  if (typeof raw.batch_id !== 'string') return null
  if (typeof raw.state !== 'string' ||
    !(BATCH_STATES as readonly string[]).includes(raw.state)) return null
  if (!Array.isArray(raw.items)) return null
  const items: AIBatchItem[] = []
  for (const it of raw.items) {
    if (!isObj(it) || typeof it.review_id !== 'string') return null
    items.push({
      review_id: it.review_id,
      state: typeof it.state === 'string' ? it.state : 'pending',
      assessment: typeof it.assessment === 'string' ? it.assessment : '',
      error: typeof it.error === 'string' ? it.error : '',
    })
  }
  const counts = isObj(raw.counts)
    ? Object.fromEntries(
      Object.entries(raw.counts).filter(([, v]) => typeof v === 'number'),
    ) as Record<string, number>
    : {}
  const assessments = isObj(raw.assessments)
    ? Object.fromEntries(
      Object.entries(raw.assessments).filter(([, v]) => typeof v === 'number'),
    ) as Record<string, number>
    : {}
  return {
    batch_id: raw.batch_id,
    state: raw.state as AIBatchStatus['state'],
    reason: typeof raw.reason === 'string' ? raw.reason : '',
    items,
    counts,
    assessments,
    remaining: typeof raw.remaining === 'number' ? raw.remaining : 0,
  }
}

// ---- AI assessment filter -----------------------------------------------------

export const AI_FILTERS = ['all', 'confirmed', 'false_positive', 'uncertain', 'none'] as const
export type AIFilter = (typeof AI_FILTERS)[number]

/** Does a finding pass the AI-assessment filter? `assessment` is undefined
 * when the finding has no stored AI result. */
export function matchesAIFilter(assessment: string | undefined, filter: AIFilter): boolean {
  if (filter === 'all') return true
  if (filter === 'none') return assessment === undefined
  return assessment === filter
}

/** rid -> assessment map from GET /api/ai/reviews — strict, drops junk. */
export function parseAISummary(raw: unknown): Record<string, string> {
  if (!isObj(raw) || !isObj(raw.results)) return {}
  const out: Record<string, string> = {}
  for (const [rid, row] of Object.entries(raw.results)) {
    if (!isObj(row) || typeof row.assessment !== 'string') continue
    out[rid] = row.assessment
  }
  return out
}

/** Default mandatory limits derived from a preview — the user can raise or
 * lower them in the panel before starting. */
export function defaultLimitsFor(preview: AIBatchPreview): {
  max_requests: number
  max_output_tokens: number
  max_input_bytes: number
} {
  return {
    max_requests: preview.request_count,
    max_output_tokens: preview.max_output_tokens,
    max_input_bytes: preview.input_bytes,
  }
}

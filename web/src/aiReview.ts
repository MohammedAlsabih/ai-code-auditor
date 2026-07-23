// Pure AI-review model (W3-B) — Node-testable, no React, no network.
//
// The browser can only name {review_id, provider, model}. There is NO prompt
// box anywhere: the prompt is fixed on the server. Results are ADVISORY —
// they never change the human review status.

export const AI_ASSESSMENTS = ['confirmed', 'false_positive', 'uncertain'] as const
export const AI_CONFIDENCES = ['low', 'medium', 'high'] as const
export const AI_ACTIONS = ['inspect', 'fix_code', 'adjust_rule', 'dismiss'] as const

export interface AIEvidence {
  context_id: string
  statement: string
}

export interface AIReviewResult {
  review_id: string
  provider: string
  model: string
  prompt_version: string
  latency_ms: number
  context_digest: string
  created_at: string
  assessment: (typeof AI_ASSESSMENTS)[number]
  confidence: (typeof AI_CONFIDENCES)[number]
  summary: string
  evidence: AIEvidence[]
  missing_context: string[]
  suggested_action: (typeof AI_ACTIONS)[number]
  stale: boolean
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

const inList = <T extends readonly string[]>(list: T, v: unknown): v is T[number] =>
  typeof v === 'string' && (list as readonly string[]).includes(v)

/** Strict guard over one server result. Malformed → null, never guessed. */
export function parseAIReviewResult(raw: unknown): AIReviewResult | null {
  if (!isObj(raw)) return null
  if (!inList(AI_ASSESSMENTS, raw.assessment)) return null
  if (!inList(AI_CONFIDENCES, raw.confidence)) return null
  if (!inList(AI_ACTIONS, raw.suggested_action)) return null
  for (const k of ['review_id', 'provider', 'model', 'prompt_version', 'context_digest', 'created_at', 'summary'] as const) {
    if (typeof raw[k] !== 'string') return null
  }
  if (typeof raw.latency_ms !== 'number') return null
  if (!Array.isArray(raw.evidence) || raw.evidence.length < 1 || raw.evidence.length > 5) return null
  const evidence: AIEvidence[] = []
  for (const e of raw.evidence) {
    if (!isObj(e) || typeof e.context_id !== 'string' || typeof e.statement !== 'string') return null
    evidence.push({ context_id: e.context_id, statement: e.statement })
  }
  if (!Array.isArray(raw.missing_context) || raw.missing_context.length > 5) return null
  const missing: string[] = []
  for (const m of raw.missing_context) {
    if (typeof m !== 'string') return null
    missing.push(m)
  }
  return {
    review_id: raw.review_id as string,
    provider: raw.provider as string,
    model: raw.model as string,
    prompt_version: raw.prompt_version as string,
    latency_ms: raw.latency_ms,
    context_digest: raw.context_digest as string,
    created_at: raw.created_at as string,
    assessment: raw.assessment,
    confidence: raw.confidence,
    summary: raw.summary as string,
    evidence,
    missing_context: missing,
    suggested_action: raw.suggested_action,
    stale: raw.stale === true,
  }
}

/** GET /api/ai/reviews/{rid} → the freshest usable result (or the freshest
 * stale one, flagged) — malformed rows are dropped. */
export function pickStoredResult(payload: unknown): AIReviewResult | null {
  if (!isObj(payload) || !Array.isArray(payload.results)) return null
  const parsed = payload.results
    .map(parseAIReviewResult)
    .filter((r): r is AIReviewResult => r !== null)
  if (parsed.length === 0) return null
  const fresh = parsed.find((r) => !r.stale)
  return fresh ?? parsed[0]
}

export const AI_ADVISORY_NOTICE =
  'AI assessment — advisory only, separate from Human Review. It never changes the review status.'

export function assessmentTone(a: AIReviewResult['assessment']): 'bad' | 'good' | 'warn' {
  if (a === 'confirmed') return 'bad'
  if (a === 'false_positive') return 'good'
  return 'warn'
}

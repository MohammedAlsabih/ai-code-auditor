// Pure AI-review model (W3-B / W3-B2) — Node-testable, no React, no network.
//
// The browser can only name {review_id, provider, model}. There is NO prompt
// box anywhere: the prompt is fixed on the server. Results are ADVISORY —
// they never change the human review status.
//
// W3-B2: the result contract is v2 (w3c-v3). A single `assessment` no longer
// conflates four independent questions; they are separated into match /
// defect / impact / actionability. A legacy w3c-v2 (v1) result is still
// readable as history, flagged `legacy`, and never offers an Apply path.

export const AI_MATCH = ['matched', 'not_matched', 'uncertain'] as const
export const AI_DEFECT = ['confirmed', 'acceptable', 'uncertain'] as const
export const AI_IMPACT = ['none', 'low', 'medium', 'high', 'critical', 'uncertain'] as const
export const AI_ACTIONABILITY = ['actionable', 'context_dependent', 'not_actionable', 'uncertain'] as const
export const AI_ACTIONS = ['inspect', 'fix_code', 'adjust_rule', 'dismiss'] as const
// legacy w3c-v2 single assessment, kept ONLY to render history
export const AI_LEGACY_ASSESSMENTS = ['confirmed', 'false_positive', 'uncertain'] as const
export const REVIEW_CONTRACT_VERSION = 2

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
  summary: string
  evidence: AIEvidence[]
  missing_context: string[]
  suggested_action: (typeof AI_ACTIONS)[number]
  stale: boolean
  legacy: boolean
  // v2 four axes — present when !legacy
  match_assessment?: (typeof AI_MATCH)[number]
  defect_assessment?: (typeof AI_DEFECT)[number]
  impact?: (typeof AI_IMPACT)[number]
  actionability?: (typeof AI_ACTIONABILITY)[number]
  // legacy v1 single assessment — present when legacy
  assessment?: (typeof AI_LEGACY_ASSESSMENTS)[number]
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

const inList = <T extends readonly string[]>(list: T, v: unknown): v is T[number] =>
  typeof v === 'string' && (list as readonly string[]).includes(v)

function parseEnvelope(raw: Record<string, unknown>): Omit<AIReviewResult, 'legacy'
  | 'match_assessment' | 'defect_assessment' | 'impact' | 'actionability' | 'assessment'> | null {
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
    summary: raw.summary as string,
    evidence,
    missing_context: missing,
    suggested_action: raw.suggested_action,
    stale: raw.stale === true,
  }
}

/** Strict guard over one server result — v2 four-axis OR legacy v1. Malformed
 * → null, never guessed. */
export function parseAIReviewResult(raw: unknown): AIReviewResult | null {
  if (!isObj(raw)) return null
  const base = parseEnvelope(raw)
  if (base === null) return null
  if (raw.contract_version === REVIEW_CONTRACT_VERSION) {
    if (!inList(AI_MATCH, raw.match_assessment) || !inList(AI_DEFECT, raw.defect_assessment)
      || !inList(AI_IMPACT, raw.impact) || !inList(AI_ACTIONABILITY, raw.actionability)) return null
    return {
      ...base, legacy: false,
      match_assessment: raw.match_assessment,
      defect_assessment: raw.defect_assessment,
      impact: raw.impact,
      actionability: raw.actionability,
    }
  }
  // legacy w3c-v2 row (history) — a single assessment, always shown as Legacy
  if (!inList(AI_LEGACY_ASSESSMENTS, raw.assessment)) return null
  return { ...base, legacy: true, stale: true, assessment: raw.assessment }
}

/** GET /api/ai/reviews/{rid} → the freshest usable result (or the freshest
 * stale one, flagged) — malformed rows are dropped. */
export function pickStoredResult(payload: unknown): AIReviewResult | null {
  if (!isObj(payload) || !Array.isArray(payload.results)) return null
  const parsed = payload.results
    .map(parseAIReviewResult)
    .filter((r): r is AIReviewResult => r !== null)
  if (parsed.length === 0) return null
  const fresh = parsed.find((r) => !r.stale && !r.legacy)
  return fresh ?? parsed[0]
}

export const AI_ADVISORY_NOTICE =
  'AI assessment — advisory only, separate from Human Review. It never changes the review status.'

export const AI_LEGACY_NOTICE =
  'Legacy review (w3c-v2). Kept as history only — re-run for the current four-axis decision. No Apply.'

// tone for the DEFECT axis — the closest analogue to the old single verdict,
// but shown as one of four fields, never as a lone `confirmed` badge.
export function defectTone(d: AIReviewResult['defect_assessment']): 'bad' | 'good' | 'warn' {
  if (d === 'confirmed') return 'bad'
  if (d === 'acceptable') return 'good'
  return 'warn'
}

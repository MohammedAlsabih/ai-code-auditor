// Pure AI-audit model (W3-E2) — Node-testable, no React, no network.
//
// The user never writes a prompt: profile + projects + provider/model +
// limits only. Every candidate is ADVISORY; absence of candidates is never
// evidence the project is safe.

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

export const AUDIT_PROFILES = ['security', 'correctness', 'ai_code_risks', 'all'] as const
export type AuditProfile = (typeof AUDIT_PROFILES)[number]

export const CANDIDATE_DECISIONS = ['confirmed', 'false_positive', 'uncertain'] as const

export interface AIAuditPreview {
  units: number
  request_count: number
  files: number
  input_bytes: number
  estimated_input_tokens: number
  max_output_tokens: number
  redaction_total: number
  cached: number
  fresh: number
  concurrency: number
  request_timeout_seconds: number
  cost_status: string
  estimated_cost_usd?: number
  retention: string
  queries: string[]
  projects: string[]
  consent_token: string
}

export function parseAuditPreview(raw: unknown): AIAuditPreview | null {
  if (!isObj(raw)) return null
  for (const k of ['units', 'request_count', 'files', 'input_bytes',
    'estimated_input_tokens', 'max_output_tokens', 'redaction_total',
    'cached', 'fresh', 'concurrency', 'request_timeout_seconds'] as const) {
    if (typeof raw[k] !== 'number') return null
  }
  if (typeof raw.cost_status !== 'string' || typeof raw.retention !== 'string') return null
  const strArr = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
  return {
    units: raw.units as number,
    request_count: raw.request_count as number,
    files: raw.files as number,
    input_bytes: raw.input_bytes as number,
    estimated_input_tokens: raw.estimated_input_tokens as number,
    max_output_tokens: raw.max_output_tokens as number,
    redaction_total: raw.redaction_total as number,
    cached: raw.cached as number,
    fresh: raw.fresh as number,
    concurrency: raw.concurrency as number,
    request_timeout_seconds: raw.request_timeout_seconds as number,
    cost_status: raw.cost_status,
    estimated_cost_usd:
      typeof raw.estimated_cost_usd === 'number' ? raw.estimated_cost_usd : undefined,
    retention: raw.retention,
    queries: strArr(raw.queries),
    projects: strArr(raw.projects),
    consent_token: typeof raw.consent_token === 'string' ? raw.consent_token : '',
  }
}

export interface AIAuditUnit {
  audit_unit_id: string
  project: string
  query_id: string
  state: string
  outcome: string
  error: string
  issues: number
}

export interface AIAuditStatus {
  audit_id: string
  state: string
  units: AIAuditUnit[]
  counts: Record<string, number>
  outcomes: Record<string, number>
  remaining: number
}

export function parseAuditStatus(raw: unknown): AIAuditStatus | null {
  if (!isObj(raw) || typeof raw.audit_id !== 'string' || typeof raw.state !== 'string')
    return null
  if (!Array.isArray(raw.units)) return null
  const units: AIAuditUnit[] = []
  for (const u of raw.units) {
    if (!isObj(u) || typeof u.audit_unit_id !== 'string') return null
    units.push({
      audit_unit_id: u.audit_unit_id,
      project: typeof u.project === 'string' ? u.project : '',
      query_id: typeof u.query_id === 'string' ? u.query_id : '',
      state: typeof u.state === 'string' ? u.state : 'pending',
      outcome: typeof u.outcome === 'string' ? u.outcome : '',
      error: typeof u.error === 'string' ? u.error : '',
      issues: typeof u.issues === 'number' ? u.issues : 0,
    })
  }
  const nums = (v: unknown): Record<string, number> =>
    isObj(v)
      ? (Object.fromEntries(
        Object.entries(v).filter(([, n]) => typeof n === 'number'),
      ) as Record<string, number>)
      : {}
  return {
    audit_id: raw.audit_id,
    state: raw.state,
    units,
    counts: nums(raw.counts),
    outcomes: nums(raw.outcomes),
    remaining: typeof raw.remaining === 'number' ? raw.remaining : 0,
  }
}

export interface AIAuditEvidence {
  context_id: string
  file: string
  line_start: number
  line_end: number
  statement: string
}

export interface AIAuditCandidate {
  candidate_id: string
  project: string
  query_id: string
  file: string
  line: number
  title: string
  category: string
  confidence: string
  summary: string
  evidence: AIAuditEvidence[]
  missing_context: string[]
  suggested_action: string
  related_static_findings: string[]
  review: { decision: string; note: string; updated_at: string } | null
}

export function parseAuditCandidates(raw: unknown): AIAuditCandidate[] {
  if (!isObj(raw) || !Array.isArray(raw.candidates)) return []
  const out: AIAuditCandidate[] = []
  for (const c of raw.candidates) {
    if (!isObj(c) || typeof c.candidate_id !== 'string') continue
    if (typeof c.file !== 'string' || typeof c.title !== 'string') continue
    const evidence: AIAuditEvidence[] = []
    if (Array.isArray(c.evidence)) {
      for (const e of c.evidence) {
        if (!isObj(e) || typeof e.statement !== 'string') continue
        evidence.push({
          context_id: typeof e.context_id === 'string' ? e.context_id : '',
          file: typeof e.file === 'string' ? e.file : '',
          line_start: typeof e.line_start === 'number' ? e.line_start : 0,
          line_end: typeof e.line_end === 'number' ? e.line_end : 0,
          statement: e.statement,
        })
      }
    }
    const review = isObj(c.review) && typeof c.review.decision === 'string'
      ? {
        decision: c.review.decision,
        note: typeof c.review.note === 'string' ? c.review.note : '',
        updated_at: typeof c.review.updated_at === 'string' ? c.review.updated_at : '',
      }
      : null
    out.push({
      candidate_id: c.candidate_id,
      project: typeof c.project === 'string' ? c.project : '',
      query_id: typeof c.query_id === 'string' ? c.query_id : '',
      file: c.file,
      line: typeof c.line === 'number' ? c.line : 0,
      title: c.title,
      category: typeof c.category === 'string' ? c.category : '',
      confidence: typeof c.confidence === 'string' ? c.confidence : '',
      summary: typeof c.summary === 'string' ? c.summary : '',
      evidence,
      missing_context: Array.isArray(c.missing_context)
        ? c.missing_context.filter((m): m is string => typeof m === 'string')
        : [],
      suggested_action: typeof c.suggested_action === 'string' ? c.suggested_action : '',
      related_static_findings: Array.isArray(c.related_static_findings)
        ? c.related_static_findings.filter((r): r is string => typeof r === 'string')
        : [],
      review,
    })
  }
  return out
}

export const AUDIT_ADVISORY_BADGE = 'AI-generated candidate — advisory only'
export const AUDIT_ABSENCE_NOTE =
  'Absence of AI candidates is NOT evidence the project is safe.'

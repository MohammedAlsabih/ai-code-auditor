import type { Coverage, Finding, Report, Review, ReviewsResponse, SourceWindow } from './types'

// ---- W4-A2: explicit report context + library control token -------------------------
// In classic serve mode the base is '' and the token is unset — every request
// is byte-identical to before. In Library mode the App sets the base to
// /api/library/reports/<rid> before mounting the explorer (each report gets
// its own backend context) and attaches the control token to every mutating
// request (the server refuses them without it).
let reportBase = ''
let controlToken = ''

export function setReportBase(base: string): void {
  reportBase = base
}

export function setControlToken(token: string): void {
  controlToken = token
}

export const CONTROL_HEADER = 'X-Auditor-Control'

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const method = (init?.method ?? 'GET').toUpperCase()
  const merged: RequestInit = { ...init }
  if (controlToken && method !== 'GET' && method !== 'HEAD') {
    merged.headers = { ...(init?.headers as Record<string, string>),
      [CONTROL_HEADER]: controlToken }
  }
  // library endpoints are server-global; report endpoints get the base
  const target = path.startsWith('/api/library/') ? path : `${reportBase}${path}`
  return fetch(target, merged)
}

export async function fetchCoverage(): Promise<Coverage> {
  const res = await apiFetch('/api/coverage')
  if (!res.ok) throw new Error(`coverage request failed (HTTP ${res.status})`)
  return res.json()
}

export async function fetchReport(): Promise<Report> {
  const res = await apiFetch('/api/report')
  if (!res.ok) throw new Error(`report request failed (HTTP ${res.status})`)
  return res.json()
}

// level normalization lives in the pure module ./levels (Node-testable);
// re-exported here for existing importers.
export { CANONICAL_LEVELS, levelColor, normalizeLevel } from './levels'
import { normalizeBaselineState } from './baseline'
import { normalizeLevel } from './levels'

// Thrown by fetchSource so the panel can distinguish "server has no --repo"
// (unavailable) from a real error.
export class SourceUnavailable extends Error {}

// Finding.file is PROJECT-relative; /api/source wants a REPO-relative path.
// Mirrors the backend's repo_relative() exactly.
export function sourcePathFor(f: Finding): string {
  const root = (f.project ?? '').replace(/^\/+|\/+$/g, '')
  return root === '' || root === '.' ? f.file : `${root}/${f.file}`
}

export async function fetchSource(
  path: string,
  line: number,
  signal?: AbortSignal,
): Promise<SourceWindow> {
  const q = `path=${encodeURIComponent(path)}&line=${line}`
  const res = await apiFetch(`/api/source?${q}`, { signal })
  const body = await res.json().catch(() => ({}))
  if (res.status === 409) throw new SourceUnavailable(body.error ?? 'source unavailable')
  if (!res.ok) throw new Error(body.error ?? `source request failed (HTTP ${res.status})`)
  return body as SourceWindow
}

// Mirror of the backend aggregate_findings: flatten every project's findings
// and tag each with its owning project + resolved language.
export function aggregate(report: Report): Finding[] {
  const rows: Finding[] = []
  for (const p of report.projects ?? []) {
    for (const f of p.findings ?? []) {
      rows.push({
        rule_id: f.rule_id ?? '',
        severity: f.severity ?? '',
        level: normalizeLevel(f.level, f.severity ?? ''),
        precision: f.precision ?? '',
        language: f.language || p.language || '',
        project: p.root ?? '',
        file: f.file ?? '',
        line: f.line ?? 0,
        title: f.title ?? '',
        detail: f.detail ?? '',
        snippet: f.snippet ?? '',
        engine: f.engine,
        review_id: (f as { review_id?: string }).review_id,
        gate_action: typeof f.gate_action === 'string' ? f.gate_action : '',
        baseline_state: normalizeBaselineState(f.baseline_state),
      })
    }
  }
  return rows
}

export async function fetchReviews(): Promise<ReviewsResponse> {
  const res = await apiFetch('/api/reviews')
  if (!res.ok) throw new Error(`reviews request failed (HTTP ${res.status})`)
  return res.json()
}

export async function putReview(
  rid: string,
  status: string,
  note: string,
): Promise<Review> {
  const res = await apiFetch(`/api/reviews/${encodeURIComponent(rid)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, note }),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(body.error ?? `save failed (HTTP ${res.status})`)
  return body as Review
}

export interface BatchResult {
  applied: number
  status: string
  updated_at: string
}

export class ErrorConfirmationRequired extends Error {
  errorCount: number
  constructor(message: string, errorCount: number) {
    super(message)
    this.errorCount = errorCount
  }
}

export async function putReviewBatch(
  reviewIds: string[],
  status: string,
  noteMode: string,
  note: string,
  confirmError: boolean,
): Promise<BatchResult> {
  const res = await apiFetch('/api/review-batch', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      review_ids: reviewIds,
      status,
      note_mode: noteMode,
      note,
      confirm_error: confirmError, // canonical name; server also accepts legacy confirm_red
    }),
  })
  const body = await res.json().catch(() => ({}))
  const count = body.error_count ?? body.red_count
  if (res.status === 409 && typeof count === 'number')
    throw new ErrorConfirmationRequired(body.error ?? 'error-level confirmation required', count)
  if (!res.ok) throw new Error(body.error ?? `batch failed (HTTP ${res.status})`)
  return body as BatchResult
}

// Path-filter helpers (W2-B2.5). Matching is component-bounded: "api" matches
// "api/x.cs" but NOT "api-old/x.cs". User input is normalized (\ -> /) and
// absolute/drive/traversal inputs are rejected as invalid.
export function normalizePathFilter(input: string): string | null {
  const p = input.trim().replace(/\\/g, '/')
  if (!p) return null
  if (p.startsWith('/') || /^[A-Za-z]:/.test(p)) return null
  const parts = p.split('/').filter((s) => s !== '')
  if (parts.length === 0 || parts.some((s) => s === '.' || s === '..')) return null
  return parts.join('/')
}

export function pathFilterMatches(repoRelative: string, filter: string): boolean {
  return repoRelative === filter || repoRelative.startsWith(filter + '/')
}

// ---- AI provider layer (W3-A) ----------------------------------------------
// providers = LOCAL server metadata (no outbound call); models/test are the
// ONLY calls that reach a provider, and only on an explicit click.

export async function fetchAIProviders(): Promise<unknown> {
  const res = await apiFetch('/api/ai/providers')
  if (!res.ok) throw new Error(`providers request failed (HTTP ${res.status})`)
  return res.json()
}

export async function postAIModels(provider: string): Promise<unknown> {
  const res = await apiFetch('/api/ai/models', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider }),
  })
  const body = await res.json().catch(() => ({}))
  if (res.status === 409) throw new Error('another AI request is already running')
  if (!res.ok) throw new Error(
    (body as { error?: string }).error ?? `models request failed (HTTP ${res.status})`)
  return body
}

export interface AITestResult {
  status: string
  message: string
  latency_ms?: number
}

export async function postAITest(provider: string, model: string): Promise<AITestResult> {
  const res = await apiFetch('/api/ai/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, model }),
  })
  const body = await res.json().catch(() => ({}))
  if (res.status === 409) throw new Error('another AI request is already running')
  if (!res.ok) throw new Error(
    (body as { error?: string }).error ?? `test request failed (HTTP ${res.status})`)
  return body as AITestResult
}

// ---- AI single-finding review (W3-B) ---------------------------------------
// The browser sends {review_id, provider, model} — never a prompt, key, or
// URL. 403 = privacy gate (local providers only until W3-C).

export class AIPrivacyGate extends Error {}

export interface AIConsentPreview {
  provider: string
  model: string
  locality: string
  findings: number
  files: number
  input_bytes: number
  estimated_input_tokens: number
  redaction_total: number
  redactions: Record<string, number>
  retention: string
  cost: string
  consent_token: string
}

export async function postAIConsentPreview(
  reviewIds: string[],
  provider: string,
  model: string,
): Promise<AIConsentPreview> {
  const res = await apiFetch('/api/ai/consent-preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ review_ids: reviewIds, provider, model }),
  })
  const body = await res.json().catch(() => ({}))
  if (res.status === 403) {
    throw new AIPrivacyGate(
      (body as { error?: string }).error ?? 'remote AI reviews are disabled by server policy',
    )
  }
  if (!res.ok) {
    throw new Error(
      (body as { error?: string }).error ?? `consent preview failed (HTTP ${res.status})`,
    )
  }
  return body as AIConsentPreview
}

export async function postAIReview(
  reviewId: string,
  provider: string,
  model: string,
  consentToken = '',
): Promise<unknown> {
  const res = await apiFetch('/api/ai/reviews', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      review_id: reviewId,
      provider,
      model,
      consent_token: consentToken,
    }),
  })
  const body = await res.json().catch(() => ({}))
  if (res.status === 403) {
    throw new AIPrivacyGate(
      (body as { error?: string }).error ??
        'blocked: local providers only until the privacy gate ships',
    )
  }
  if (res.status === 409) throw new Error('an AI review for this finding is already running')
  if (!res.ok) {
    const b = body as { error?: string; message?: string; status?: string }
    throw new Error(b.error ?? b.message ?? `AI review failed (HTTP ${res.status})`)
  }
  return body
}

export async function fetchAIReview(reviewId: string): Promise<unknown> {
  const res = await apiFetch(`/api/ai/reviews/${encodeURIComponent(reviewId)}`)
  if (!res.ok) throw new Error(`AI review lookup failed (HTTP ${res.status})`)
  return res.json()
}

// ---- W3-D: batch AI review ---------------------------------------------------

async function aiJson(res: Response): Promise<unknown> {
  const body = await res.json().catch(() => ({}))
  if (res.status === 403) {
    const b = body as { error?: string }
    throw new AIPrivacyGate(b.error ?? 'blocked by the privacy gate')
  }
  if (!res.ok) {
    const b = body as { error?: string }
    throw new Error(b.error ?? `request failed (HTTP ${res.status})`)
  }
  return body
}

export async function postAIBatchPreview(
  reviewIds: string[],
  provider: string,
  model: string,
): Promise<unknown> {
  return aiJson(
    await apiFetch('/api/ai/batches/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ review_ids: reviewIds, provider, model }),
    }),
  )
}

export interface AIBatchLimits {
  max_requests: number
  max_output_tokens: number
  max_input_bytes?: number
}

export async function postAIBatch(
  reviewIds: string[],
  provider: string,
  model: string,
  limits: AIBatchLimits,
  consentToken = '',
): Promise<unknown> {
  return aiJson(
    await apiFetch('/api/ai/batches', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        review_ids: reviewIds,
        provider,
        model,
        limits,
        consent_token: consentToken,
      }),
    }),
  )
}

export async function fetchAIBatch(batchId: string): Promise<unknown> {
  return aiJson(await apiFetch(`/api/ai/batches/${encodeURIComponent(batchId)}`))
}

export async function cancelAIBatch(batchId: string): Promise<void> {
  await aiJson(
    await apiFetch(`/api/ai/batches/${encodeURIComponent(batchId)}/cancel`, { method: 'POST' }),
  )
}

export async function fetchAIReviewsSummary(): Promise<unknown> {
  const res = await apiFetch('/api/ai/reviews')
  if (!res.ok) throw new Error(`AI summary failed (HTTP ${res.status})`)
  return res.json()
}

// ---- W3-E: independent AI audit ---------------------------------------------

export async function postAIAuditPreview(
  profile: string,
  provider: string,
  model: string,
  projects: string[],
  mode: 'fixed' | 'agent' = 'fixed',
): Promise<unknown> {
  return aiJson(
    await apiFetch('/api/ai/audits/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile, provider, model, projects, mode }),
    }),
  )
}

export async function postAIAudit(
  profile: string,
  provider: string,
  model: string,
  projects: string[],
  limits: AIBatchLimits,
  consentToken = '',
  mode: 'fixed' | 'agent' = 'fixed',
): Promise<unknown> {
  return aiJson(
    await apiFetch('/api/ai/audits', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        profile,
        provider,
        model,
        projects,
        limits,
        consent_token: consentToken,
        mode,
      }),
    }),
  )
}

export async function fetchAIAudit(auditId: string): Promise<unknown> {
  return aiJson(await apiFetch(`/api/ai/audits/${encodeURIComponent(auditId)}`))
}

export async function cancelAIAudit(auditId: string): Promise<void> {
  await aiJson(
    await apiFetch(`/api/ai/audits/${encodeURIComponent(auditId)}/cancel`, { method: 'POST' }),
  )
}

export async function fetchAIAuditResults(): Promise<unknown> {
  return aiJson(await apiFetch('/api/ai/audit-results'))
}

export async function putAICandidateReview(
  candidateId: string,
  decision: string,
  note: string,
): Promise<unknown> {
  return aiJson(
    await apiFetch(`/api/ai/audit-candidates/${encodeURIComponent(candidateId)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, note }),
    }),
  )
}

export async function deleteReview(rid: string): Promise<void> {
  const res = await apiFetch(`/api/reviews/${encodeURIComponent(rid)}`, { method: 'DELETE' })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? `clear failed (HTTP ${res.status})`)
  }
}

// ---- W4-A2: Library mode API -------------------------------------------------------
// All mutating calls carry the control token via apiFetch automatically.

async function libJson(res: Response): Promise<unknown> {
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(
      (body as { error?: string }).error ?? `request failed (HTTP ${res.status})`)
  }
  return body
}

export async function fetchLibrarySession(): Promise<unknown | null> {
  try {
    const res = await fetch('/api/library/session')
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function fetchLibraryCapabilities(): Promise<unknown> {
  return libJson(await apiFetch('/api/library/capabilities'))
}

export async function fetchLibraryProjects(): Promise<unknown> {
  return libJson(await apiFetch('/api/library/projects'))
}

export async function addLibraryProject(
  body: { kind: string; name?: string; path?: string; url?: string },
): Promise<unknown> {
  return libJson(await apiFetch('/api/library/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }))
}

export async function removeLibraryProject(pid: string): Promise<unknown> {
  return libJson(await apiFetch(
    `/api/library/projects/${encodeURIComponent(pid)}?confirm=true`,
    { method: 'DELETE' }))
}

export async function deleteLibrarySource(pid: string): Promise<unknown> {
  return libJson(await apiFetch(
    `/api/library/projects/${encodeURIComponent(pid)}/delete-source`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    }))
}

export async function startLibraryScan(
  pid: string, online: boolean, semgrep: boolean,
): Promise<unknown> {
  return libJson(await apiFetch(
    `/api/library/projects/${encodeURIComponent(pid)}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ online, semgrep }),
    }))
}

export async function fetchLibraryScan(jid: string): Promise<unknown> {
  return libJson(await apiFetch(
    `/api/library/scans/${encodeURIComponent(jid)}`))
}

export async function cancelLibraryScan(jid: string): Promise<unknown> {
  return libJson(await apiFetch(
    `/api/library/scans/${encodeURIComponent(jid)}/cancel`,
    { method: 'POST' }))
}

export async function fetchLibraryReports(pid: string): Promise<unknown> {
  return libJson(await apiFetch(
    `/api/library/projects/${encodeURIComponent(pid)}/reports`))
}

export async function deleteLibraryReport(rid: string): Promise<unknown> {
  return libJson(await apiFetch(
    `/api/library/reports/${encodeURIComponent(rid)}?confirm=true`,
    { method: 'DELETE' }))
}

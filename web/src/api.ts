import type { Coverage, Finding, Report, Review, ReviewsResponse, SourceWindow } from './types'

export async function fetchCoverage(): Promise<Coverage> {
  const res = await fetch('/api/coverage')
  if (!res.ok) throw new Error(`coverage request failed (HTTP ${res.status})`)
  return res.json()
}

export async function fetchReport(): Promise<Report> {
  const res = await fetch('/api/report')
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
  const res = await fetch(`/api/source?${q}`, { signal })
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
  const res = await fetch('/api/reviews')
  if (!res.ok) throw new Error(`reviews request failed (HTTP ${res.status})`)
  return res.json()
}

export async function putReview(
  rid: string,
  status: string,
  note: string,
): Promise<Review> {
  const res = await fetch(`/api/reviews/${encodeURIComponent(rid)}`, {
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
  const res = await fetch('/api/review-batch', {
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
  const res = await fetch('/api/ai/providers')
  if (!res.ok) throw new Error(`providers request failed (HTTP ${res.status})`)
  return res.json()
}

export async function postAIModels(provider: string): Promise<unknown> {
  const res = await fetch('/api/ai/models', {
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
  const res = await fetch('/api/ai/test', {
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

export async function deleteReview(rid: string): Promise<void> {
  const res = await fetch(`/api/reviews/${encodeURIComponent(rid)}`, { method: 'DELETE' })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? `clear failed (HTTP ${res.status})`)
  }
}

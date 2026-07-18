import type { Finding, Report, SourceWindow } from './types'

export async function fetchReport(): Promise<Report> {
  const res = await fetch('/api/report')
  if (!res.ok) throw new Error(`report request failed (HTTP ${res.status})`)
  return res.json()
}

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
        precision: f.precision ?? '',
        language: f.language || p.language || '',
        project: p.root ?? '',
        file: f.file ?? '',
        line: f.line ?? 0,
        title: f.title ?? '',
        detail: f.detail ?? '',
        snippet: f.snippet ?? '',
        engine: f.engine,
      })
    }
  }
  return rows
}

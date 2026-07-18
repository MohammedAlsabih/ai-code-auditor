import type { Finding, Report } from './types'

export async function fetchReport(): Promise<Report> {
  const res = await fetch('/api/report')
  if (!res.ok) throw new Error(`report request failed (HTTP ${res.status})`)
  return res.json()
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

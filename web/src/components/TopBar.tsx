import { Activity, Gauge, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'

import type { Summary } from '../types'

function verdictIcon(v?: string) {
  if (v === 'pass') return <ShieldCheck size={16} />
  if (v === 'block') return <ShieldAlert size={16} />
  return <ShieldQuestion size={16} />
}

export function TopBar({
  summary,
  target,
  total,
  shown,
  activeSeverities,
  onToggleSeverity,
}: {
  summary: Summary
  target?: string
  total: number
  shown: number
  activeSeverities: Set<string>
  onToggleSeverity: (s: string) => void
}) {
  const c = summary.counts ?? {}
  const verdict = summary.verdict ?? 'review'

  const chip = (sev: 'red' | 'yellow' | 'blue', n: number) => (
    <button
      className={`count count-${sev} ${activeSeverities.has(sev) ? 'active' : ''}`}
      onClick={() => onToggleSeverity(sev)}
      title={`${sev} findings — click to toggle filter (multi-select)`}
    >
      <span className="dot" /> {n}
    </button>
  )

  return (
    <header className="topbar">
      <div className="brand">
        AI Code Auditor <span className="sub">Report Explorer</span>
      </div>
      <div className={`verdict verdict-${verdict}`}>
        {verdictIcon(verdict)} <span>{verdict.toUpperCase()}</span>
      </div>
      <div className="metric">
        <Activity size={15} /> code_health <b>{summary.overall_score ?? '—'}</b>
      </div>
      <div className="metric">
        <Gauge size={15} /> confidence <b>{summary.analysis_confidence ?? '—'}</b>
      </div>
      <div className="counts">
        {chip('red', c.red ?? 0)}
        {chip('yellow', c.yellow ?? 0)}
        {chip('blue', c.blue ?? 0)}
      </div>
      <div className="showing">
        {shown}/{total} findings{target ? ` · ${target}` : ''}
      </div>
    </header>
  )
}

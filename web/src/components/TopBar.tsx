import { Activity, Database, Gauge, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'

import type { Summary } from '../types'

function verdictIcon(v?: string) {
  if (v === 'pass') return <ShieldCheck size={16} />
  if (v === 'block') return <ShieldAlert size={16} />
  return <ShieldQuestion size={16} />
}

const CHIP_COLOR: Record<string, string> = { error: 'red', warning: 'yellow', note: 'blue' }

export function TopBar({
  summary,
  target,
  total,
  shown,
  activeLevels,
  onToggleLevel,
}: {
  summary: Summary
  target?: string
  total: number
  shown: number
  activeLevels: Set<string>
  onToggleLevel: (s: string) => void
}) {
  const legacy = summary.counts ?? {}
  const lc = summary.level_counts ?? {
    error: legacy.red,
    warning: legacy.yellow,
    note: legacy.blue,
  }
  const verdict = summary.verdict ?? 'review'
  const gc = summary.gate_counts

  const chip = (level: 'error' | 'warning' | 'note', n: number) => (
    <button
      className={`count count-${CHIP_COLOR[level]} ${activeLevels.has(level) ? 'active' : ''}`}
      onClick={() => onToggleLevel(level)}
      title={`${level} findings — click to toggle filter (multi-select)`}
    >
      <span className="dot" /> {level} {n}
    </button>
  )

  return (
    <header className="topbar">
      <div className="brand">
        AI Code Auditor <span className="sub">Report Explorer</span>
      </div>
      <div
        className={`verdict verdict-${verdict}`}
        title={'Verdict derives from per-finding gate_action: exact errors '
          + 'block; HEURISTIC errors require review but do NOT block by '
          + 'default; notes are informational.'
          + (gc ? ` Gate: block ${gc.block ?? 0} · review ${gc.review ?? 0} `
            + `· informational ${gc.informational ?? 0}` : '')}
      >
        {verdictIcon(verdict)} <span>{verdict.toUpperCase()}</span>
      </div>
      <div className="metric">
        <Activity size={15} /> code_health <b>{summary.overall_score ?? '—'}</b>
      </div>
      <div
        className="metric"
        title="How COMPLETE the file/manifest/rule analysis was — registry
verification is the separate metric next to this one"
      >
        <Gauge size={15} /> Analysis confidence{' '}
        <b>{summary.analysis_confidence ?? '—'}</b>
      </div>
      {summary.registry_status && (
        <div
          className="metric"
          title="Registry verification (separate axis): whether dependency
lookups ran and how many failed — 'unavailable' means an intended --offline
run and does not reduce analysis confidence"
        >
          <Database size={15} /> Registry <b>{summary.registry_status}</b>
          {typeof summary.registry_confidence === 'number' && (
            <b> {summary.registry_confidence}</b>
          )}
        </div>
      )}
      <div className="counts">
        {chip('error', lc.error ?? 0)}
        {chip('warning', lc.warning ?? 0)}
        {chip('note', lc.note ?? 0)}
      </div>
      <div className="showing">
        {shown}/{total} findings{target ? ` · ${target}` : ''}
      </div>
    </header>
  )
}

import { BadgeCheck, CircleAlert, Info, Sparkle, TriangleAlert } from 'lucide-react'

import type { Finding, Review } from '../types'

function sevIcon(s: string) {
  if (s === 'red') return <CircleAlert size={15} />
  if (s === 'yellow') return <TriangleAlert size={15} />
  return <Info size={15} />
}

function precIcon(p: string) {
  return p === 'exact' ? <BadgeCheck size={13} /> : <Sparkle size={13} />
}

const REVIEW_BADGE: Record<string, [string, string]> = {
  confirmed: ['C', 'Confirmed'],
  false_positive: ['FP', 'False positive'],
  accepted_risk: ['AR', 'Accepted risk'],
}

export function FindingsTable({
  rows,
  reviews,
  selected,
  onSelect,
}: {
  rows: Finding[]
  reviews: Record<string, Review>
  selected: Finding | null
  onSelect: (f: Finding) => void
}) {
  return (
    <div className="table-wrap">
      <table className="findings">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>Precision</th>
            <th>Language</th>
            <th>Project</th>
            <th>File:Line</th>
            <th>Title</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f, i) => {
            const review = f.review_id ? reviews[f.review_id] : undefined
            const badge = review ? REVIEW_BADGE[review.status] : undefined
            return (
              <tr
                key={i}
                className={`sev-${f.severity} ${selected === f ? 'selected' : ''}`}
                onClick={() => onSelect(f)}
              >
                <td className="c-sev">
                  <span className={`sev sev-${f.severity}`}>
                    {sevIcon(f.severity)} {f.severity}
                  </span>
                </td>
                <td className="mono">{f.rule_id}</td>
                <td>
                  <span className={`prec prec-${f.precision}`}>
                    {precIcon(f.precision)} {f.precision}
                  </span>
                </td>
                <td>{f.language}</td>
                <td className="mono ellip" title={f.project}>
                  {f.project || '(root)'}
                </td>
                <td className="mono ellip" title={`${f.file}:${f.line}`}>
                  {f.file}:{f.line}
                </td>
                <td className="ellip" title={f.title}>
                  {f.title}
                </td>
                <td>
                  {badge && (
                    <span className={`rev-badge rev-${review!.status}`} title={badge[1]}>
                      {badge[0]}
                    </span>
                  )}
                </td>
              </tr>
            )
          })}
          {rows.length === 0 && (
            <tr>
              <td colSpan={8} className="empty">
                No findings match the current filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

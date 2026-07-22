import { BadgeCheck, CircleAlert, Info, Sparkle, TriangleAlert } from 'lucide-react'

import { levelColor } from '../api'
import type { Finding, Review } from '../types'

function levelIcon(level: string) {
  if (level === 'error') return <CircleAlert size={15} />
  if (level === 'warning') return <TriangleAlert size={15} />
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
  showBaseline,
  reviews,
  selected,
  onSelect,
  isRowSelected,
  onTogglePick,
  onTogglePage,
}: {
  rows: Finding[]
  // true only for reports scanned with --baseline: no fabricated badges
  showBaseline: boolean
  reviews: Record<string, Review>
  selected: Finding | null
  onSelect: (f: Finding) => void
  isRowSelected: (rid: string) => boolean
  onTogglePick: (rid: string) => void
  onTogglePage: (ids: string[], on: boolean) => void
}) {
  const pageIds = rows.filter((r) => r.review_id).map((r) => r.review_id as string)
  const pageAllPicked = pageIds.length > 0 && pageIds.every((id) => isRowSelected(id))

  return (
    <div className="table-wrap">
      <table className="findings">
        <thead>
          <tr>
            <th className="c-check">
              <input
                type="checkbox"
                checked={pageAllPicked}
                onChange={(e) => onTogglePage(pageIds, e.target.checked)}
                title="Select current page"
              />
            </th>
            <th>Level</th>
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
            const checked = Boolean(f.review_id && isRowSelected(f.review_id))
            const color = levelColor(f.level)
            return (
              <tr
                key={f.review_id ?? `${f.file}:${f.line}:${i}`}
                className={`sev-${color} ${selected === f ? 'selected' : ''}`}
                onClick={() => onSelect(f)}
              >
                <td className="c-check" onClick={(e) => e.stopPropagation()}>
                  {f.review_id ? (
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => onTogglePick(f.review_id as string)}
                      title="Select finding"
                    />
                  ) : (
                    <span className="cov-muted" title="No stable identity — not selectable">
                      —
                    </span>
                  )}
                </td>
                <td className="c-sev">
                  <span className={`sev sev-${color}`}>
                    {levelIcon(f.level)} {f.level || f.severity || 'unclassified'}
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
                  {showBaseline && f.baseline_state && (
                    <span
                      className={`bl-badge bl-${f.baseline_state}`}
                      title={f.baseline_state === 'new'
                        ? 'Not in the baseline report'
                        : 'Already present in the baseline report'}
                    >
                      {f.baseline_state === 'new' ? 'NEW' : 'EXISTING'}
                    </span>
                  )}
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
              <td colSpan={9} className="empty">
                No findings match the current filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

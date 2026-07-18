import { BadgeCheck, CircleAlert, Info, Sparkle, TriangleAlert } from 'lucide-react'

import type { Finding } from '../types'

function sevIcon(s: string) {
  if (s === 'red') return <CircleAlert size={15} />
  if (s === 'yellow') return <TriangleAlert size={15} />
  return <Info size={15} />
}

function precIcon(p: string) {
  return p === 'exact' ? <BadgeCheck size={13} /> : <Sparkle size={13} />
}

export function FindingsTable({
  rows,
  selected,
  onSelect,
}: {
  rows: Finding[]
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
          </tr>
        </thead>
        <tbody>
          {rows.map((f, i) => (
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
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={7} className="empty">
                No findings match the current filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

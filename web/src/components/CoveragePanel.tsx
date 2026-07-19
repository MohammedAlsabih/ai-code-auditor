import { useEffect, useState } from 'react'
import {
  CheckCircle2,
  CircleHelp,
  CircleMinus,
  CircleOff,
  Info,
  Loader2,
  XCircle,
} from 'lucide-react'

import { fetchCoverage } from '../api'
import type { Coverage, CoverageStage } from '../types'

// status is always icon + TEXT — color is never the only signal.
const STATUS_META: Record<CoverageStage['status'], [JSX.Element, string]> = {
  complete: [<CheckCircle2 size={14} key="c" />, 'Complete'],
  partial: [<CircleMinus size={14} key="p" />, 'Partial'],
  failed: [<XCircle size={14} key="f" />, 'Failed'],
  unavailable: [<CircleOff size={14} key="u" />, 'Unavailable'],
  not_recorded: [<CircleHelp size={14} key="n" />, 'Not recorded'],
}

function StatusChip({ status }: { status: CoverageStage['status'] }) {
  const [icon, label] = STATUS_META[status] ?? STATUS_META.not_recorded
  return (
    <span className={`cov-status cov-${status}`}>
      {icon} {label}
    </span>
  )
}

function Section({
  title,
  children,
  open = true,
}: {
  title: string
  children: React.ReactNode
  open?: boolean
}) {
  return (
    <details className="cov-section" open={open}>
      <summary>{title}</summary>
      <div className="cov-section-body">{children}</div>
    </details>
  )
}

export function CoveragePanel() {
  const [cov, setCov] = useState<Coverage | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchCoverage()
      .then(setCov)
      .catch((e) => setError(String(e?.message ?? e)))
  }, [])

  if (error) return <div className="fatal">Could not load coverage: {error}</div>
  if (!cov)
    return (
      <div className="loading">
        <Loader2 className="spin" size={16} /> Loading coverage…
      </div>
    )

  const d = cov.diagnostics
  const diagRows: Array<[string, string[] | string]> = [
    ['Manifest errors', d.manifest_errors],
    ['Manifests incomplete', d.manifest_incomplete],
    ['Include gaps', d.include_gaps],
    ['Skipped files', d.skipped_files],
    ['Parse errors', d.parse_error_files],
    ['Rule errors', d.rule_errors],
    [
      'Rule attempts',
      d.rule_attempted === null
        ? 'Not recorded'
        : `${d.rule_attempted} attempted, ${d.rule_failures ?? 0} failed`,
    ],
    [
      'Registry lookups',
      d.registry_attempted === null
        ? 'Not recorded'
        : `${d.registry_attempted} attempted, ${d.registry_failures ?? 0} failed`,
    ],
    ['Notes', d.notes],
  ]

  return (
    <div className="coverage">
      <Section title="Analysis stages">
        <table className="cov-table">
          <thead>
            <tr>
              <th>Stage</th>
              <th>Status</th>
              <th>Evidence</th>
              <th>Issues</th>
            </tr>
          </thead>
          <tbody>
            {cov.stages.map((s) => (
              <tr key={s.key}>
                <td>{s.label}</td>
                <td>
                  <StatusChip status={s.status} />
                </td>
                <td>{s.evidence}</td>
                <td>
                  {s.issues.length === 0 ? (
                    <span className="cov-muted">—</span>
                  ) : (
                    <ul className="cov-list">
                      {s.issues.map((i, n) => (
                        <li key={n}>{i}</li>
                      ))}
                    </ul>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Projects & languages">
        <table className="cov-table">
          <thead>
            <tr>
              <th>Root</th>
              <th>Language</th>
              <th>Frameworks</th>
              <th>Files</th>
              <th>Score</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {cov.projects.map((p) => (
              <tr key={p.root}>
                <td className="mono">{p.root || '(root)'}</td>
                <td>{p.language}</td>
                <td>{p.frameworks.length ? p.frameworks.join(', ') : '—'}</td>
                <td>{p.file_count ?? 'Not recorded'}</td>
                <td>{p.score ?? 'Not recorded'}</td>
                <td>{p.findings_count ?? 'Not recorded'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Engines & provenance">
        <table className="cov-table">
          <tbody>
            <tr>
              <th>Tool</th>
              <td>
                {cov.provenance.tool ?? 'Not recorded'} {cov.provenance.version ?? ''}
              </td>
            </tr>
            <tr>
              <th>Generated at</th>
              <td>{cov.provenance.generated_at ?? 'Not recorded'}</td>
            </tr>
            <tr>
              <th>Target</th>
              <td className="mono">{cov.provenance.target ?? 'Not recorded'}</td>
            </tr>
            {Object.entries(cov.provenance.engines).map(([k, v]) => (
              <tr key={k}>
                <th>engine: {k}</th>
                <td>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="cov-muted">
          Engines describe what the tool ships — they are provenance, not proof that a
          stage ran. Stage completion above is judged from recorded evidence only.
        </p>
      </Section>

      <Section title="Diagnostics">
        <table className="cov-table">
          <tbody>
            {diagRows.map(([label, value]) => (
              <tr key={label}>
                <th>{label}</th>
                <td>
                  {typeof value === 'string' ? (
                    value
                  ) : value.length === 0 ? (
                    <span className="cov-muted">none recorded</span>
                  ) : (
                    <ul className="cov-list">
                      {value.map((v, n) => (
                        <li key={n}>{v}</li>
                      ))}
                    </ul>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Limitations (as recorded by the report)">
        {cov.limitations.length === 0 ? (
          <p className="cov-muted">No limitations recorded.</p>
        ) : (
          <ul className="cov-list">
            {cov.limitations.map((l, n) => (
              <li key={n}>{l}</li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Observed finding rules">
        <div className="cov-callout">
          <Info size={14} /> {cov.observed_rules_disclaimer}
        </div>
        <table className="cov-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Count</th>
              <th>Languages</th>
              <th>Precision</th>
              <th>Levels</th>
            </tr>
          </thead>
          <tbody>
            {cov.observed_rules.map((r) => (
              <tr key={r.rule_id}>
                <td className="mono">{r.rule_id}</td>
                <td>{r.count}</td>
                <td>{r.languages.join(', ')}</td>
                <td>{r.precisions.join(', ')}</td>
                <td>{r.levels.join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  )
}

import type React from 'react'
import { useEffect, useMemo, useState } from 'react'
import {
  Ban,
  ChevronDown,
  CircleDashed,
  CircleHelp,
  CircleMinus,
  CirclePlay,
  CircleX,
  CloudOff,
  SkipForward,
  TriangleAlert,
  X,
} from 'lucide-react'

import {
  ATTENTION_ORDER,
  type ExecutionStatus,
  type RuleCoverage,
  type RuleRow,
  type RuleSortKey,
  filterRuleRows,
  sortRuleRows,
} from '../rulecov'

// icon + text for every legal status — never color alone, and the executed
// mark is NEUTRAL (the rule ran; it says nothing about code safety)
const STATUS_META: Record<ExecutionStatus, { label: string; Icon: typeof Ban }> = {
  executed: { label: 'Executed', Icon: CirclePlay },
  partial: { label: 'Partial', Icon: CircleDashed },
  failed: { label: 'Failed', Icon: CircleX },
  blocked: { label: 'Blocked', Icon: Ban },
  unavailable: { label: 'Unavailable', Icon: CloudOff },
  skipped: { label: 'Skipped', Icon: SkipForward },
  not_applicable: { label: 'Not applicable', Icon: CircleMinus },
  not_recorded: { label: 'Not recorded', Icon: CircleHelp },
  inconsistent: { label: 'Inconsistent', Icon: TriangleAlert },
}

const STATUS_BY_ATTENTION = (Object.keys(ATTENTION_ORDER) as ExecutionStatus[])
  .sort((a, b) => ATTENTION_ORDER[a] - ATTENTION_ORDER[b])

function StatusChip({ status, count }: { status: ExecutionStatus; count?: number }) {
  const meta = STATUS_META[status]
  return (
    <span className={`rc-status rc-${status}`}>
      <meta.Icon size={12} aria-hidden />
      {meta.label}
      {count !== undefined ? ` ${count}` : ''}
    </span>
  )
}

function StatusSummary({ row }: { row: RuleRow }) {
  const entries = STATUS_BY_ATTENTION
    .filter((s) => (row.statusCounts[s] ?? 0) > 0)
  if (!entries.length) return <span className="rc-none">—</span>
  return (
    <span className="rc-chips">
      {entries.map((s) => (
        <StatusChip key={s} status={s} count={row.statusCounts[s]} />
      ))}
    </span>
  )
}

function MultiFilter({ name, options, active, onToggle }: {
  name: string
  options: string[]
  active: Set<string>
  onToggle: (v: string) => void
}) {
  const [open, setOpen] = useState(false)
  if (!options.length) return null
  return (
    <span className="tb-group tb-rules">
      <button className="btn" onClick={() => setOpen(!open)}>
        {name}{active.size ? ` (${active.size})` : ''} <ChevronDown size={13} />
      </button>
      {open && (
        <div className="tb-rules-pop">
          {options.map((o) => (
            <label key={o}>
              <input type="checkbox" checked={active.has(o)} onChange={() => onToggle(o)} />{' '}
              <span className="mono">{o.replace(/_/g, ' ')}</span>
            </label>
          ))}
        </div>
      )}
    </span>
  )
}

function CountersList({ row, ctxIndex }: { row: RuleRow; ctxIndex: number }) {
  const rec = row.contexts[ctxIndex].record
  if (!rec) return null
  const counters: Array<[string, number | undefined]> = [
    ['eligible', rec.eligible_inputs],
    ['attempted', rec.attempted],
    ['failures', rec.failures],
    ['blocked', rec.blocked_inputs],
    ['partial parse', rec.partial_parse_inputs],
  ]
  // only fields the report actually recorded — an absent counter is absent,
  // never rendered as a fabricated zero
  const present = counters.filter(([, v]) => typeof v === 'number')
  const reasons: Array<[string, string[] | undefined]> = [
    ['Not applicable', rec.not_applicable_reasons],
    ['Unavailable', rec.unavailable_reasons],
    ['Partial', rec.partial_reasons],
    ['Failure', rec.failure_reasons],
    ['Skipped', rec.skipped_reasons],
  ]
  return (
    <>
      {present.length > 0 && (
        <div className="rc-counters mono">
          {present.map(([k, v]) => `${k} ${v}`).join(' · ')}
        </div>
      )}
      {reasons.map(([label, list]) =>
        list && list.length > 0 ? (
          <div key={label} className="rc-reasons">
            <span className="rc-reason-label">{label}:</span> {list.join(' · ')}
          </div>
        ) : null,
      )}
    </>
  )
}

export function RulesPanel({ coverage }: { coverage: RuleCoverage }) {
  const [query, setQuery] = useState('')
  const [statusF, setStatusF] = useState<Set<string>>(new Set())
  const [languageF, setLanguageF] = useState<Set<string>>(new Set())
  const [engineF, setEngineF] = useState<Set<string>>(new Set())
  const [categoryF, setCategoryF] = useState<Set<string>>(new Set())
  const [levelF, setLevelF] = useState<Set<string>>(new Set())
  const [precisionF, setPrecisionF] = useState<Set<string>>(new Set())
  const [sortKey, setSortKey] = useState<RuleSortKey>('id')
  const [selected, setSelected] = useState<RuleRow | null>(null)

  // FUNCTIONAL updates: rapid clicks never operate on a stale closure set
  const toggle = (setter: React.Dispatch<React.SetStateAction<Set<string>>>) =>
    (v: string) => {
      setter((prev) => {
        const next = new Set(prev)
        if (next.has(v)) next.delete(v)
        else next.add(v)
        return next
      })
    }

  const opts = useMemo(() => {
    const uniq = (vals: string[]) => Array.from(new Set(vals.filter(Boolean))).sort()
    return {
      statuses: coverage.executionAvailable
        ? STATUS_BY_ATTENTION.filter((s) =>
            coverage.rows.some((r) => (r.statusCounts[s] ?? 0) > 0))
        : [],
      languages: uniq(coverage.rows.flatMap((r) => r.languages)),
      engines: uniq(coverage.rows.map((r) => r.engine)),
      categories: uniq(coverage.rows.map((r) => r.category)),
      levels: uniq(coverage.rows.map((r) => r.default_level)),
      precisions: uniq(coverage.rows.map((r) => r.default_precision)),
    }
  }, [coverage])

  const shown = useMemo(() => {
    const filtered = filterRuleRows(coverage.rows, {
      query,
      statuses: statusF,
      languages: languageF,
      engines: engineF,
      categories: categoryF,
      levels: levelF,
      precisions: precisionF,
    })
    return sortRuleRows(filtered, sortKey)
  }, [coverage, query, statusF, languageF, engineF, categoryF, levelF,
      precisionF, sortKey])

  // the detail panel must never keep showing a rule the filters hid
  useEffect(() => {
    if (selected && !shown.some((r) => r.rule_id === selected.rule_id)) {
      setSelected(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shown])

  const anyFilter = Boolean(query.trim()) || statusF.size > 0 ||
    languageF.size > 0 || engineF.size > 0 || categoryF.size > 0 ||
    levelF.size > 0 || precisionF.size > 0
  const clearFilters = () => {
    setQuery('')
    setStatusF(new Set())
    setLanguageF(new Set())
    setEngineF(new Set())
    setCategoryF(new Set())
    setLevelF(new Set())
    setPrecisionF(new Set())
  }

  return (
    <div className="rc-wrap">
      <div className="rc-head">
        {coverage.catalogAvailable ? (
          <h2>
            {coverage.rows.length} rule{coverage.rows.length === 1 ? '' : 's'} in
            this report
          </h2>
        ) : (
          <div className="rc-banner">
            <TriangleAlert size={14} aria-hidden /> Rule catalog was not
            recorded in this report.
          </div>
        )}
        {!coverage.executionAvailable && (
          <div className="rc-banner">
            <TriangleAlert size={14} aria-hidden /> Execution evidence was not
            recorded in this report. Rescan with the current auditor version to
            see per-rule execution coverage.
          </div>
        )}
        {coverage.notes.map((n) => (
          <div key={n} className="rc-banner rc-note">
            <TriangleAlert size={14} aria-hidden /> {n}
          </div>
        ))}
      </div>

      <div className="toolbar rc-toolbar">
        <input
          className="rc-search"
          placeholder="Search rule ID, title, description…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <MultiFilter name="Status" options={opts.statuses} active={statusF}
          onToggle={toggle(setStatusF)} />
        <MultiFilter name="Language" options={opts.languages} active={languageF}
          onToggle={toggle(setLanguageF)} />
        <MultiFilter name="Engine" options={opts.engines} active={engineF}
          onToggle={toggle(setEngineF)} />
        <MultiFilter name="Category" options={opts.categories} active={categoryF}
          onToggle={toggle(setCategoryF)} />
        <MultiFilter name="Level" options={opts.levels} active={levelF}
          onToggle={toggle(setLevelF)} />
        <MultiFilter name="Precision" options={opts.precisions} active={precisionF}
          onToggle={toggle(setPrecisionF)} />
        <span className="tb-group">
          <label className="tb-label">
            Sort{' '}
            <select value={sortKey}
              onChange={(e) => setSortKey(e.target.value as RuleSortKey)}>
              <option value="id">Rule ID</option>
              <option value="title">Title</option>
              <option value="engine">Engine</option>
              <option value="attention">Execution attention</option>
            </select>
          </label>
        </span>
        {anyFilter && (
          <button className="btn" onClick={clearFilters}>Clear filters</button>
        )}
        <span className="tb-count">
          {shown.length} / {coverage.rows.length} rules
        </span>
      </div>

      <div className="rc-body">
        <div className="tablewrap rc-tablewrap">
          <table className="rc-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Execution</th>
                <th>Engine</th>
                <th>Category</th>
                <th>Languages</th>
                <th>Scope</th>
                <th>Level</th>
                <th>Precision</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr
                  key={r.rule_id}
                  className={selected?.rule_id === r.rule_id ? 'sel' : ''}
                  onClick={() => setSelected(r)}
                >
                  <td>
                    <span className="mono">{r.rule_id}</span>
                    <span className="rc-title" title={r.title}> — {r.title}</span>
                  </td>
                  <td><StatusSummary row={r} /></td>
                  <td className="mono">{r.engine || '—'}</td>
                  <td>{r.category || '—'}</td>
                  <td className="mono rc-langs">
                    {r.languages.join(', ') || '—'}
                    {r.frameworks.length > 0 && (
                      <span className="rc-fw"> [{r.frameworks.join(', ')}]</span>
                    )}
                  </td>
                  <td>{r.scope || '—'}</td>
                  <td>{r.default_level || '—'}</td>
                  <td>{r.default_precision || '—'}</td>
                </tr>
              ))}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={8} className="rc-none">No rules match the filters.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {selected && (
          <section className="detail rc-detail">
            <div className="detail-head">
              <span className="mono">{selected.rule_id}</span>
              <button className="close" onClick={() => setSelected(null)}
                aria-label="Close">
                <X size={15} />
              </button>
            </div>
            <h2 className="detail-title">{selected.title}</h2>
            {selected.description && selected.description !== selected.title && (
              <p className="rc-desc">{selected.description}</p>
            )}
            <dl className="detail-meta">
              <dt>Engine</dt><dd className="mono">{selected.engine || '—'}</dd>
              <dt>Category</dt><dd>{selected.category || '—'}</dd>
              <dt>Scope</dt><dd>{selected.scope || '—'}</dd>
              <dt>Source</dt><dd>{selected.source || '—'}</dd>
              <dt>Languages</dt>
              <dd className="mono">{selected.languages.join(', ') || '—'}</dd>
              {selected.frameworks.length > 0 && (
                <>
                  <dt>Frameworks</dt>
                  <dd className="mono">{selected.frameworks.join(', ')}</dd>
                </>
              )}
              <dt>Default level</dt><dd>{selected.default_level || '—'}</dd>
              <dt>Default precision</dt><dd>{selected.default_precision || '—'}</dd>
            </dl>

            <div className="detail-label">Execution by project</div>
            {!coverage.executionAvailable && (
              <div className="rc-banner">
                Execution evidence was not recorded in this report. Rescan with
                the current auditor version to see per-rule execution coverage.
              </div>
            )}
            {selected.contexts.map((c, i) => (
              <div key={`${c.root}:${c.language}`} className="rc-ctx">
                <div className="rc-ctx-head">
                  <span className="mono">{c.root}</span> · {c.language}{' '}
                  <StatusChip status={c.status} />
                </div>
                <CountersList row={selected} ctxIndex={i} />
                {c.ruleErrors.map((e) => (
                  <div key={e} className="rc-reasons">
                    <span className="rc-reason-label">Contract:</span> {e}
                  </div>
                ))}
                {c.projectErrors.map((e) => (
                  <div key={e} className="rc-reasons">
                    <span className="rc-reason-label">Project:</span> {e}
                  </div>
                ))}
              </div>
            ))}
          </section>
        )}
      </div>
    </div>
  )
}

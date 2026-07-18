import { useState } from 'react'
import { ChevronDown, ChevronLeft, ChevronRight, Search, X } from 'lucide-react'

export const SORT_KEYS: Array<[string, string]> = [
  ['severity', 'Severity'],
  ['rule', 'Rule'],
  ['precision', 'Precision'],
  ['language', 'Language'],
  ['project', 'Project'],
  ['path', 'Path'],
  ['line', 'Line'],
  ['title', 'Title'],
  ['review', 'Review status'],
]

export function Toolbar({
  query,
  onQuery,
  pathInput,
  onPathInput,
  pathFilters,
  onAddPath,
  onRemovePath,
  pathInvalid,
  pathSuggestions,
  ruleOptions,
  ruleFilter,
  onToggleRule,
  precisionFilter,
  onTogglePrecision,
  sortKey,
  sortDir,
  onSortKey,
  onSortDir,
  anyFilterActive,
  onClearAllFilters,
}: {
  query: string
  onQuery: (q: string) => void
  pathInput: string
  onPathInput: (v: string) => void
  pathFilters: string[]
  onAddPath: () => void
  onRemovePath: (p: string) => void
  pathInvalid: boolean
  pathSuggestions: string[]
  ruleOptions: string[]
  ruleFilter: Set<string>
  onToggleRule: (r: string) => void
  precisionFilter: Set<string>
  onTogglePrecision: (p: string) => void
  sortKey: string
  sortDir: 'asc' | 'desc'
  onSortKey: (k: string) => void
  onSortDir: () => void
  anyFilterActive: boolean
  onClearAllFilters: () => void
}) {
  const [rulesOpen, setRulesOpen] = useState(false)
  return (
    <div className="toolbar">
      <div className="tb-row">
        <div className="tb-search">
          <Search size={14} />
          <input
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            placeholder="Search rule, title, detail, snippet, project, file…"
          />
          {query && (
            <button className="tb-x" onClick={() => onQuery('')} title="Clear search">
              <X size={13} />
            </button>
          )}
        </div>
        <div className="tb-path">
          <input
            list="path-suggestions"
            value={pathInput}
            onChange={(e) => onPathInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && onAddPath()}
            placeholder="Filter by folder or file (repo-relative)…"
            className={pathInvalid ? 'invalid' : ''}
          />
          <datalist id="path-suggestions">
            {pathSuggestions.map((p) => (
              <option key={p} value={p} />
            ))}
          </datalist>
          <button className="btn" onClick={onAddPath} disabled={!pathInput.trim()}>
            Add path
          </button>
        </div>
        <div className="tb-sort">
          <label>Sort</label>
          <select value={sortKey} onChange={(e) => onSortKey(e.target.value)}>
            {SORT_KEYS.map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
          <button className="btn" onClick={onSortDir} title="Toggle direction">
            {sortDir === 'asc' ? '↑ asc' : '↓ desc'}
          </button>
        </div>
        <button
          className="btn"
          onClick={onClearAllFilters}
          disabled={!anyFilterActive}
          title="Reset search, all filters and path chips (sort and page size stay)"
        >
          Clear all filters
        </button>
      </div>
      <div className="tb-row tb-row2">
        {pathInvalid && (
          <span className="tb-invalid">
            Invalid path filter (absolute, drive, or “..” inputs are rejected)
          </span>
        )}
        {pathFilters.map((p) => (
          <span key={p} className="chip">
            <span className="mono">{p}</span>
            <button onClick={() => onRemovePath(p)} title={`Remove ${p}`}>
              <X size={12} />
            </button>
          </span>
        ))}
        <span className="tb-group">
          {(['exact', 'heuristic'] as const).map((p) => (
            <button
              key={p}
              className={`btn btn-toggle ${precisionFilter.has(p) ? 'on' : ''}`}
              onClick={() => onTogglePrecision(p)}
            >
              {p}
            </button>
          ))}
        </span>
        <span className="tb-group tb-rules">
          <button className="btn" onClick={() => setRulesOpen(!rulesOpen)}>
            Rules{ruleFilter.size ? ` (${ruleFilter.size})` : ''} <ChevronDown size={13} />
          </button>
          {rulesOpen && (
            <div className="tb-rules-pop">
              {ruleOptions.map((r) => (
                <label key={r}>
                  <input
                    type="checkbox"
                    checked={ruleFilter.has(r)}
                    onChange={() => onToggleRule(r)}
                  />{' '}
                  <span className="mono">{r}</span>
                </label>
              ))}
            </div>
          )}
        </span>
      </div>
    </div>
  )
}

export function PaginationBar({
  page,
  pageCount,
  pageSize,
  onPage,
  onPageSize,
  from,
  to,
  matched,
  total,
}: {
  page: number
  pageCount: number
  pageSize: number
  onPage: (p: number) => void
  onPageSize: (s: number) => void
  from: number
  to: number
  matched: number
  total: number
}) {
  return (
    <div className="pagebar">
      <span>
        Showing {matched === 0 ? 0 : from}–{to} of {matched} matched
        <span className="cov-muted"> · {total} total in report</span>
      </span>
      <span className="pagebar-controls">
        <select value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))}>
          {[25, 50, 100].map((s) => (
            <option key={s} value={s}>
              {s} / page
            </option>
          ))}
        </select>
        <button className="btn" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <ChevronLeft size={14} /> Prev
        </button>
        <span>
          Page {pageCount === 0 ? 0 : page} of {pageCount}
        </span>
        <button className="btn" disabled={page >= pageCount} onClick={() => onPage(page + 1)}>
          Next <ChevronRight size={14} />
        </button>
      </span>
    </div>
  )
}

export function BulkBar({
  count,
  allFiltered,
  filteredCount,
  onSelectAllFiltered,
  onClear,
  status,
  onStatus,
  noteMode,
  onNoteMode,
  note,
  onNote,
  onApply,
  busy,
  message,
  error,
}: {
  count: number
  allFiltered: boolean
  filteredCount: number
  onSelectAllFiltered: () => void
  onClear: () => void
  status: string
  onStatus: (s: string) => void
  noteMode: string
  onNoteMode: (m: string) => void
  note: string
  onNote: (n: string) => void
  onApply: () => void
  busy: boolean
  message: string
  error: string
}) {
  return (
    <div className="bulkbar">
      <b>
        {allFiltered ? `All ${count} filtered selected` : `${count} selected`}
      </b>
      {!allFiltered && filteredCount > count && (
        <button className="btn" onClick={onSelectAllFiltered}>
          Select all {filteredCount} filtered results across all pages
        </button>
      )}
      <select value={status} onChange={(e) => onStatus(e.target.value)}>
        <option value="">— set status —</option>
        <option value="confirmed">Confirmed</option>
        <option value="false_positive">False positive</option>
        <option value="accepted_risk">Accepted risk</option>
        <option value="unreviewed">Unreviewed (clear)</option>
      </select>
      <select value={noteMode} onChange={(e) => onNoteMode(e.target.value)}>
        <option value="keep">Keep notes</option>
        <option value="append">Append note</option>
        <option value="replace">Replace note</option>
      </select>
      {noteMode !== 'keep' && (
        <input
          className="bulk-note"
          value={note}
          maxLength={2000}
          onChange={(e) => onNote(e.target.value)}
          placeholder="Note…"
        />
      )}
      <button className="btn btn-primary" onClick={onApply} disabled={!status || busy}>
        {busy ? 'Applying…' : 'Apply'}
      </button>
      <button className="btn" onClick={onClear} disabled={busy}>
        Clear selection
      </button>
      {message && <span className="review-msg ok">{message}</span>}
      {error && <span className="review-msg err">{error}</span>}
    </div>
  )
}

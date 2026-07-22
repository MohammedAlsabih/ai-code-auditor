import { useEffect, useMemo, useState } from 'react'
import { Loader2, TriangleAlert } from 'lucide-react'

import {
  ErrorConfirmationRequired,
  aggregate,
  fetchReport,
  fetchReviews,
  normalizePathFilter,
  pathFilterMatches,
  putReviewBatch,
  sourcePathFor,
} from './api'
import { AIProvidersPanel } from './components/AIProvidersPanel'
import { CoveragePanel } from './components/CoveragePanel'
import { DetailPanel } from './components/DetailPanel'
import { BulkBar, PaginationBar, Toolbar } from './components/FindingsControls'
import { FindingsTable } from './components/FindingsTable'
import { RulesPanel } from './components/RulesPanel'
import { Sidebar } from './components/Sidebar'
import { TopBar } from './components/TopBar'
import { type BaselineFilter, baselineSummary, matchesBaselineFilter } from './baseline'
import { buildRuleCoverage, ruleFilterOptions } from './rulecov'
import {
  type Selection,
  dedupeIds,
  effectiveSelection,
  emptySelection,
  isSelected as selIsSelected,
  selectAllFiltered,
  togglePage as selTogglePage,
  toggleRow as selToggleRow,
} from './selection'
import type { Finding, Report, Review } from './types'

const LEVEL_ORDER: Record<string, number> = { error: 0, warning: 1, note: 2 }
const REVIEW_ORDER: Record<string, number> = {
  confirmed: 0,
  false_positive: 1,
  accepted_risk: 2,
}

function toggleSet(set: Set<string>, value: string): Set<string> {
  const next = new Set(set)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  return next
}

export default function App() {
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Finding | null>(null)
  const [reviews, setReviews] = useState<Record<string, Review>>({})
  const [reviewsOk, setReviewsOk] = useState(true)
  const [reviewsError, setReviewsError] = useState('')
  const [tab, setTab] = useState<'findings' | 'rules' | 'coverage' | 'ai'>('findings')

  // multi-value filters: OR inside a category, AND across categories
  const [query, setQuery] = useState('')
  const [projectF, setProjectF] = useState<Set<string>>(new Set())
  const [languageF, setLanguageF] = useState<Set<string>>(new Set())
  const [levelF, setLevelF] = useState<Set<string>>(new Set())
  const [precisionF, setPrecisionF] = useState<Set<string>>(new Set())
  const [ruleF, setRuleF] = useState<Set<string>>(new Set())
  const [reviewF, setReviewF] = useState<Set<string>>(new Set())
  // All/New/Existing — rendered ONLY for reports with a real baseline block
  const [baselineF, setBaselineF] = useState<BaselineFilter>('all')
  const [pathFilters, setPathFilters] = useState<string[]>([])
  const [pathInput, setPathInput] = useState('')
  const [pathInvalid, setPathInvalid] = useState(false)

  // bumped by Clear-all: resets Toolbar-local state (rule search/popover)
  const [filterResetToken, setFilterResetToken] = useState(0)
  const [sortKey, setSortKey] = useState('level')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  // selection model (pure helpers in selection.mjs): 'picked' set, or 'all'
  // with an excluded set — unchecking rows/pages inside select-all only grows
  // `excluded`, and the effective selection is always the intersection with
  // the deduplicated currently-visible ids (hidden rows can never be sent)
  const [sel, setSel] = useState<Selection>(emptySelection())
  const [bulkStatus, setBulkStatus] = useState('')
  const [bulkNoteMode, setBulkNoteMode] = useState('keep')
  const [bulkNote, setBulkNote] = useState('')
  const [bulkBusy, setBulkBusy] = useState(false)
  const [bulkMsg, setBulkMsg] = useState('')
  const [bulkErr, setBulkErr] = useState('')

  useEffect(() => {
    fetchReport().then(setReport).catch((e) => setError(String(e?.message ?? e)))
    fetchReviews()
      .then((r) => {
        setReviews(r.reviews)
        setReviewsOk(r.available)
        setReviewsError(r.error ?? '')
      })
      .catch((e) => {
        setReviewsOk(false)
        setReviewsError(String(e?.message ?? e))
      })
  }, [])

  const allRows = useMemo(() => (report ? aggregate(report) : []), [report])
  // strict gate: baseline UI exists ONLY when the report carries a real block
  const baseline = useMemo(
    () => (report ? baselineSummary(report.summary) : null),
    [report],
  )
  const projects = useMemo(
    () => Array.from(new Set(allRows.map((r) => r.project))).sort(),
    [allRows],
  )
  const languages = useMemo(
    () => Array.from(new Set(allRows.map((r) => r.language).filter(Boolean))).sort(),
    [allRows],
  )
  // Rules-tab model: catalog x execution from the REPORT only (rulecov.ts)
  const ruleCoverage = useMemo(
    () => buildRuleCoverage(report?.analysis_manifest),
    [report],
  )
  const ruleOptions = useMemo(() => {
    const ids = Array.from(new Set(allRows.map((r) => r.rule_id).filter(Boolean))).sort()
    // fallback for OLD reports without a catalog: the first finding title
    const titles: Record<string, string> = {}
    for (const r of allRows) {
      if (r.rule_id && r.title && !(r.rule_id in titles)) titles[r.rule_id] = r.title
    }
    return ruleFilterOptions(ids, ruleCoverage.rows, titles)
  }, [allRows, ruleCoverage])
  const pathSuggestions = useMemo(() => {
    // derived from existing findings ONLY — never walks the repository
    const set = new Set<string>()
    for (const r of allRows) {
      const rel = sourcePathFor(r)
      const parts = rel.split('/')
      for (let i = 1; i <= parts.length; i++) set.add(parts.slice(0, i).join('/'))
    }
    return Array.from(set).sort()
  }, [allRows])

  // ---- pipeline: filter -> sort -> paginate --------------------------------
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return allRows.filter((r) => {
      if (q) {
        const hay = [r.rule_id, r.title, r.detail, r.snippet, r.project, r.file, r.language]
          .join('\n')
          .toLowerCase()
        if (!hay.includes(q)) return false
      }
      if (projectF.size && !projectF.has(r.project)) return false
      if (languageF.size && !languageF.has(r.language)) return false
      if (levelF.size && !levelF.has(r.level)) return false
      if (precisionF.size && !precisionF.has(r.precision)) return false
      if (ruleF.size && !ruleF.has(r.rule_id)) return false
      if (reviewF.size) {
        const rv = r.review_id ? reviews[r.review_id] : undefined
        const state = rv ? rv.status : 'unreviewed'
        if (!reviewF.has(state)) return false
      }
      if (baseline && !matchesBaselineFilter(r.baseline_state, baselineF)) {
        return false
      }
      if (pathFilters.length) {
        const rel = sourcePathFor(r)
        if (!pathFilters.some((p) => pathFilterMatches(rel, p))) return false
      }
      return true
    })
  }, [allRows, query, projectF, languageF, levelF, precisionF, ruleF, reviewF,
      baseline, baselineF, pathFilters, reviews])

  const sorted = useMemo(() => {
    const dir = sortDir === 'asc' ? 1 : -1
    const key = (r: Finding): Array<string | number> => {
      switch (sortKey) {
        case 'level':
          return [LEVEL_ORDER[r.level] ?? 9]
        case 'rule':
          return [r.rule_id]
        case 'precision':
          return [r.precision]
        case 'language':
          return [r.language]
        case 'project':
          return [r.project]
        case 'path':
          return [sourcePathFor(r)]
        case 'line':
          return [r.line]
        case 'title':
          return [r.title]
        case 'review': {
          const rv = r.review_id ? reviews[r.review_id] : undefined
          return [rv ? REVIEW_ORDER[rv.status] ?? 8 : 9]
        }
        default:
          return [0]
      }
    }
    const rows = [...filtered]
    rows.sort((a, b) => {
      // primary key, then FIXED secondary keys so rows never jump randomly
      const ka = [...key(a), a.project, sourcePathFor(a), a.line, a.rule_id]
      const kb = [...key(b), b.project, sourcePathFor(b), b.line, b.rule_id]
      for (let i = 0; i < ka.length; i++) {
        const x = ka[i]
        const y = kb[i]
        if (x === y) continue
        const primary = i < ka.length - 4 ? dir : 1 // secondaries always ascending
        return (x < y ? -1 : 1) * primary
      }
      return 0
    })
    return rows
  }, [filtered, sortKey, sortDir, reviews])

  // zero matches => zero pages ("Page 0 of 0"), never a phantom "Page 1 of 1"
  const pageCount = sorted.length === 0 ? 0 : Math.ceil(sorted.length / pageSize)
  const safePage = pageCount === 0 ? 1 : Math.min(page, pageCount)
  const paged = useMemo(
    () => sorted.slice((safePage - 1) * pageSize, safePage * pageSize),
    [sorted, safePage, pageSize],
  )

  // any search/filter/page-size change returns to page 1 AND clears selection
  // baselineF included: switching All/New/Existing clears the (possibly
  // hidden) selection so bulk review can never touch rows outside the view
  const filterStamp = JSON.stringify([
    query, [...projectF], [...languageF], [...levelF], [...precisionF],
    [...ruleF], [...reviewF], baselineF, pathFilters, pageSize,
  ])
  useEffect(() => {
    setPage(1)
    setSel(emptySelection())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterStamp])

  // the DetailPanel must never keep showing a finding the filters hid
  useEffect(() => {
    if (selected && !filtered.includes(selected)) setSelected(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered])

  // DEDUPLICATED visible selectable ids — the single base for payload/counter
  const filteredSelectable = useMemo(
    () => dedupeIds(filtered.filter((r) => r.review_id).map((r) => r.review_id as string)),
    [filtered],
  )
  // unified effective selection: model ∩ visible — a row hidden by a filter
  // (or by its own status change) can never reach the batch payload
  const selectedIds = useMemo(
    () => effectiveSelection(sel, filteredSelectable),
    [sel, filteredSelectable],
  )
  const allMode = sel.mode === 'all'

  const clearAllFilters = () => {
    setFilterResetToken((n) => n + 1)   // rule search cleared + popover closed
    setQuery('')
    setProjectF(new Set())
    setLanguageF(new Set())
    setLevelF(new Set())
    setPrecisionF(new Set())
    setRuleF(new Set())
    setReviewF(new Set())
    setBaselineF('all')
    setPathFilters([])
    setPathInput('')
    setPathInvalid(false)
    // page reset + selection clear follow via the filterStamp effect
  }
  const anyFilterActive =
    Boolean(query.trim()) || projectF.size > 0 || languageF.size > 0 ||
    levelF.size > 0 || precisionF.size > 0 || ruleF.size > 0 ||
    reviewF.size > 0 || baselineF !== 'all' || pathFilters.length > 0

  const applyBulk = async (confirmRed: boolean) => {
    if (!bulkStatus || selectedIds.length === 0) return
    setBulkBusy(true)
    setBulkMsg('')
    setBulkErr('')
    try {
      const res = await putReviewBatch(selectedIds, bulkStatus, bulkNoteMode,
        bulkNote, confirmRed)
      const fresh = await fetchReviews()
      setReviews(fresh.reviews)
      setBulkMsg(`Applied "${res.status}" to ${res.applied} finding(s).`)
      setSel(emptySelection())
    } catch (e) {
      if (e instanceof ErrorConfirmationRequired) {
        const go = window.confirm(
          `${e.errorCount} ERROR-level finding(s) are in this selection. ` +
          `Marking error-level findings as ${bulkStatus.replace('_', ' ')} ` +
          'dismisses real-defect candidates. Proceed?',
        )
        if (go) {
          setBulkBusy(false)
          await applyBulk(true)
          return
        }
        setBulkErr('Cancelled — error-level findings kept.')
      } else {
        setBulkErr(String((e as Error)?.message ?? e))
      }
    } finally {
      setBulkBusy(false)
    }
  }

  const onReviewChange = (rid: string, review: Review | null) => {
    setReviews((prev) => {
      const next = { ...prev }
      if (review === null) delete next[rid]
      else next[rid] = review
      return next
    })
  }

  const addPath = () => {
    const norm = normalizePathFilter(pathInput)
    if (norm === null) {
      setPathInvalid(true)
      return
    }
    setPathInvalid(false)
    setPathInput('')
    setPathFilters((prev) => (prev.includes(norm) ? prev : [...prev, norm]))
  }

  if (error) {
    return (
      <div className="fatal">
        <TriangleAlert size={18} />
        <span>Could not load report: {error}</span>
      </div>
    )
  }
  if (!report) {
    return (
      <div className="loading">
        <Loader2 className="spin" size={18} /> Loading report…
      </div>
    )
  }

  return (
    <div className="app">
      <TopBar
        summary={report.summary}
        target={report.target}
        total={allRows.length}
        shown={sorted.length}
        activeLevels={levelF}
        onToggleLevel={(s) => setLevelF((prev) => toggleSet(prev, s))}
      />
      <nav className="tabs">
        <button
          className={`tab ${tab === 'findings' ? 'active' : ''}`}
          onClick={() => setTab('findings')}
        >
          Findings
        </button>
        <button
          className={`tab ${tab === 'rules' ? 'active' : ''}`}
          onClick={() => setTab('rules')}
        >
          Rules
        </button>
        <button
          className={`tab ${tab === 'coverage' ? 'active' : ''}`}
          onClick={() => setTab('coverage')}
        >
          Coverage
        </button>
        <button
          className={`tab ${tab === 'ai' ? 'active' : ''}`}
          onClick={() => setTab('ai')}
        >
          AI Providers
        </button>
      </nav>
      {tab === 'rules' ? (
        <div className="body">
          <main className="main">
            <RulesPanel coverage={ruleCoverage} />
          </main>
        </div>
      ) : tab === 'coverage' ? (
        <div className="body">
          <main className="main">
            <CoveragePanel />
          </main>
        </div>
      ) : tab === 'ai' ? (
        <div className="body">
          <main className="main">
            <AIProvidersPanel />
          </main>
        </div>
      ) : (
        <div className="body">
          <Sidebar
            projects={projects}
            languages={languages}
            projectF={projectF}
            languageF={languageF}
            reviewF={reviewF}
            onToggleProject={(p) => setProjectF((prev) => toggleSet(prev, p))}
            onToggleLanguage={(l) => setLanguageF((prev) => toggleSet(prev, l))}
            onToggleReview={(s) => setReviewF((prev) => toggleSet(prev, s))}
            onClearProjects={() => setProjectF(new Set())}
            onClearLanguages={() => setLanguageF(new Set())}
            onClearReviews={() => setReviewF(new Set())}
          />
          <main className="main main-col">
            <Toolbar
              query={query}
              onQuery={setQuery}
              pathInput={pathInput}
              onPathInput={(v) => {
                setPathInput(v)
                setPathInvalid(false)
              }}
              pathFilters={pathFilters}
              onAddPath={addPath}
              onRemovePath={(p) => setPathFilters(pathFilters.filter((x) => x !== p))}
              pathInvalid={pathInvalid}
              pathSuggestions={pathSuggestions}
              ruleOptions={ruleOptions}
              ruleFilter={ruleF}
              onToggleRule={(r) => setRuleF((prev) => toggleSet(prev, r))}
              precisionFilter={precisionF}
              onTogglePrecision={(p) => setPrecisionF((prev) => toggleSet(prev, p))}
              baselineInfo={baseline}
              baselineFilter={baselineF}
              onBaselineFilter={setBaselineF}
              sortKey={sortKey}
              sortDir={sortDir}
              onSortKey={setSortKey}
              onSortDir={() => setSortDir(sortDir === 'asc' ? 'desc' : 'asc')}
              anyFilterActive={anyFilterActive}
              onClearAllFilters={clearAllFilters}
              resetToken={filterResetToken}
            />
            {selectedIds.length > 0 && (
              <BulkBar
                count={selectedIds.length}
                allFiltered={allMode && selectedIds.length === filteredSelectable.length}
                filteredCount={filteredSelectable.length}
                onSelectAllFiltered={() => setSel(selectAllFiltered())}
                onClear={() => {
                  setSel(emptySelection())
                  setBulkMsg('')
                  setBulkErr('')
                }}
                status={bulkStatus}
                onStatus={setBulkStatus}
                noteMode={bulkNoteMode}
                onNoteMode={setBulkNoteMode}
                note={bulkNote}
                onNote={setBulkNote}
                onApply={() => applyBulk(false)}
                busy={bulkBusy}
                message={bulkMsg}
                error={bulkErr}
              />
            )}
            <FindingsTable
              rows={paged}
              showBaseline={baseline !== null}
              reviews={reviews}
              selected={selected}
              onSelect={setSelected}
              isRowSelected={(rid) => selIsSelected(sel, rid)}
              onTogglePick={(rid) => setSel(selToggleRow(sel, rid))}
              onTogglePage={(ids, on) => setSel(selTogglePage(sel, ids, on))}
            />
            <PaginationBar
              page={safePage}
              pageCount={pageCount}
              pageSize={pageSize}
              onPage={setPage}
              onPageSize={setPageSize}
              from={(safePage - 1) * pageSize + 1}
              to={Math.min(safePage * pageSize, sorted.length)}
              matched={sorted.length}
              total={allRows.length}
            />
          </main>
          {selected && (
            <DetailPanel
              finding={selected}
              review={selected.review_id ? reviews[selected.review_id] : undefined}
              reviewsOk={reviewsOk}
              reviewsError={reviewsError}
              onReviewChange={onReviewChange}
              onClose={() => setSelected(null)}
            />
          )}
        </div>
      )}
    </div>
  )
}

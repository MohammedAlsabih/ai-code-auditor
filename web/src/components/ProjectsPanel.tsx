import { useCallback, useEffect, useRef, useState } from 'react'
import {
  FolderOpen, FolderPlus, GitBranch, GitCompare, Loader2, Play, RefreshCw,
  Sparkles, Trash2, TriangleAlert, X,
} from 'lucide-react'

import {
  addLibraryProject,
  cancelLibraryScan,
  deleteLibraryReport,
  deleteLibrarySource,
  fetchLibraryCapabilities,
  fetchLibraryProjects,
  fetchLibraryReports,
  removeLibraryProject,
  startLibraryScan,
} from '../api'
import {
  type LibraryCapabilities,
  type LibraryProject,
  type LibraryReportRow,
  type ScanOptions,
  baselineChoices,
  changeCounts,
  defaultScanOptions,
  filterProjects,
  formatDuration,
  formatWhen,
  gateScopeLabel,
  gitUrlProblem,
  isActiveJobState,
  isNewOnlyGate,
  jobStateLabel,
  localPathProblem,
  newOnlyBlockedReason,
  parseCapabilities,
  parseProjects,
  parseReports,
  scanRequestBody,
  verdictClass,
} from '../library'

type Props = {
  query: string
  onQuery: (q: string) => void
  stateFilter: string
  onStateFilter: (s: string) => void
  onOpenReport: (reportId: string, projectName: string,
                 focus?: 'new') => void
}

const STATE_FILTERS = ['all', 'running', 'completed', 'failed', 'canceled',
  'interrupted', 'never'] as const

export function ProjectsPanel({
  query, onQuery, stateFilter, onStateFilter, onOpenReport,
}: Props) {
  const [rows, setRows] = useState<LibraryProject[] | null>(null)
  const [caps, setCaps] = useState<LibraryCapabilities | null>(null)
  const [loadError, setLoadError] = useState('')
  const [actionError, setActionError] = useState('')
  const [activeJob, setActiveJob] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [reports, setReports] = useState<Record<string, LibraryReportRow[]>>({})
  const [modalOpen, setModalOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  // per-row scan options (defaults: offline, no semgrep — explicit opt-ins)
  const [scanOnline, setScanOnline] = useState<Set<string>>(new Set())
  const [scanSemgrep, setScanSemgrep] = useState<Set<string>>(new Set())
  // W4-B: the project whose scan options are open, and its history (needed
  // for the baseline picker before the row itself has been expanded)
  const [scanFor, setScanFor] = useState<LibraryProject | null>(null)
  const timer = useRef<number | null>(null)

  const refresh = useCallback(async () => {
    try {
      const raw = await fetchLibraryProjects()
      setRows(parseProjects(raw))
      setActiveJob(String((raw as { active_job?: string }).active_job ?? ''))
      setLoadError('')
    } catch (e) {
      setLoadError(String((e as Error)?.message ?? e))
    }
  }, [])

  const refreshReports = useCallback(async (pid: string) => {
    try {
      const raw = await fetchLibraryReports(pid)
      setReports((prev) => ({ ...prev, [pid]: parseReports(raw) }))
    } catch {
      /* the row keeps its last list; the next poll retries */
    }
  }, [])

  useEffect(() => {
    refresh()
    fetchLibraryCapabilities()
      .then((raw) => setCaps(parseCapabilities(raw)))
      .catch(() => setCaps(parseCapabilities({})))
  }, [refresh])

  // poll while any job is active so progress/state stays live
  useEffect(() => {
    if (timer.current !== null) window.clearInterval(timer.current)
    const anyActive = activeJob !== '' ||
      (rows ?? []).some((r) => r.last_job && isActiveJobState(r.last_job.state))
    timer.current = window.setInterval(refresh, anyActive ? 1500 : 15000)
    return () => {
      if (timer.current !== null) window.clearInterval(timer.current)
    }
  }, [activeJob, rows, refresh])

  const act = async (fn: () => Promise<unknown>, afterPid?: string) => {
    setBusy(true)
    setActionError('')
    try {
      await fn()
      await refresh()
      if (afterPid) await refreshReports(afterPid)
    } catch (e) {
      setActionError(String((e as Error)?.message ?? e))
    } finally {
      setBusy(false)
    }
  }

  if (rows === null && !loadError) {
    return (
      <div className="loading">
        <Loader2 className="spin" size={18} /> Loading library…
      </div>
    )
  }

  const visible = filterProjects(rows ?? [], query, stateFilter)

  return (
    <div className="projects-panel">
      {caps && !caps.storeAvailable && (
        <div className="lib-banner lib-banner-error">
          <TriangleAlert size={14} />
          Library store unavailable: {caps.storeError}
        </div>
      )}
      {loadError && (
        <div className="lib-banner lib-banner-error">
          <TriangleAlert size={14} /> {loadError}
          <button className="btn" onClick={refresh}>Retry</button>
        </div>
      )}
      {actionError && (
        <div className="lib-banner lib-banner-error">
          <TriangleAlert size={14} /> {actionError}
          <button className="icon-btn" title="Dismiss"
            onClick={() => setActionError('')}><X size={13} /></button>
        </div>
      )}

      <div className="lib-toolbar">
        <input
          className="input lib-search"
          placeholder="Filter projects…"
          value={query}
          onChange={(e) => onQuery(e.target.value)}
        />
        <select
          className="review-select"
          value={stateFilter}
          onChange={(e) => onStateFilter(e.target.value)}
          title="Filter by last job state"
        >
          {STATE_FILTERS.map((s) => (
            <option key={s} value={s}>
              {s === 'all' ? 'Any state' : s === 'never' ? 'Never scanned' : s}
            </option>
          ))}
        </select>
        <span className="lib-count">
          {visible.length} / {(rows ?? []).length} project(s)
        </span>
        <button className="btn btn-primary" onClick={() => setModalOpen(true)}>
          <FolderPlus size={14} /> Add project
        </button>
      </div>

      {(rows ?? []).length === 0 ? (
        <div className="lib-empty">
          <p>No projects yet.</p>
          <p className="muted">
            Register a local folder (under an allowed root) or add a public
            GitHub/GitLab/Bitbucket repository over HTTPS, then run an
            offline scan.
          </p>
          <button className="btn btn-primary" onClick={() => setModalOpen(true)}>
            <FolderPlus size={14} /> Add your first project
          </button>
        </div>
      ) : (
        <table className="lib-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Last scan</th>
              <th>Status</th>
              <th className="num">Findings</th>
              <th className="num" title="Findings absent from the baseline">New</th>
              <th className="num" title="Baseline findings no longer present">Resolved</th>
              <th>Verdict</th>
              <th className="num">Time</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((p) => {
              const job = p.last_job
              const jobActive = job !== null && isActiveJobState(job.state)
              const latest = p.latest_report
              const isOpen = expanded === p.project_id
              return (
                <ProjectRow
                  key={p.project_id}
                  project={p}
                  busy={busy}
                  jobActive={jobActive}
                  latest={latest}
                  isOpen={isOpen}
                  reports={reports[p.project_id] ?? null}
                  onScan={() => {
                    setScanFor(p)
                    refreshReports(p.project_id)
                  }}
                  onCancel={() => job && act(() => cancelLibraryScan(job.job_id))}
                  onExpand={() => {
                    const next = isOpen ? null : p.project_id
                    setExpanded(next)
                    if (next) refreshReports(p.project_id)
                  }}
                  onOpenLatest={() => latest
                    && onOpenReport(latest.report_id, p.name)}
                  onOpenReport={(rid, focus) =>
                    onOpenReport(rid, p.name, focus)}
                  onDeleteReport={(rid) => {
                    if (window.confirm(
                      'Delete this report and its review/AI sidecars? '
                      + 'The project source is not touched.')) {
                      act(() => deleteLibraryReport(rid), p.project_id)
                    }
                  }}
                  onRemove={() => {
                    if (window.confirm(
                      `Remove "${p.name}" from the library? Its reports are `
                      + 'deleted; the source folder/clone is NOT deleted.')) {
                      act(() => removeLibraryProject(p.project_id))
                    }
                  }}
                  onDeleteSource={() => {
                    if (window.confirm(
                      'Delete the managed clone from the library folder? '
                      + 'This cannot be undone.')) {
                      act(() => deleteLibrarySource(p.project_id))
                    }
                  }}
                />
              )
            })}
          </tbody>
        </table>
      )}

      {scanFor && (
        <ScanOptionsModal
          project={scanFor}
          caps={caps}
          history={reports[scanFor.project_id] ?? null}
          online={scanOnline.has(scanFor.project_id)}
          semgrep={scanSemgrep.has(scanFor.project_id)}
          onClose={() => setScanFor(null)}
          onStart={async (opts) => {
            const pid = scanFor.project_id
            setScanOnline((prev) => {
              const next = new Set(prev)
              if (opts.online) next.add(pid); else next.delete(pid)
              return next
            })
            setScanSemgrep((prev) => {
              const next = new Set(prev)
              if (opts.semgrep) next.add(pid); else next.delete(pid)
              return next
            })
            setScanFor(null)
            await act(() => startLibraryScan(pid, scanRequestBody(opts)), pid)
          }}
        />
      )}

      {modalOpen && (
        <AddProjectModal
          caps={caps}
          onClose={() => setModalOpen(false)}
          onAdd={async (body) => {
            await addLibraryProject(body)
            setModalOpen(false)
            await refresh()
          }}
        />
      )}
    </div>
  )
}

type RowProps = {
  project: LibraryProject
  busy: boolean
  jobActive: boolean
  latest: LibraryReportRow | null
  isOpen: boolean
  reports: LibraryReportRow[] | null
  onScan: () => void
  onCancel: () => void
  onExpand: () => void
  onOpenLatest: () => void
  onOpenReport: (rid: string, focus?: 'new') => void
  onDeleteReport: (rid: string) => void
  onRemove: () => void
  onDeleteSource: () => void
}

function ProjectRow({
  project: p, busy, jobActive, latest, isOpen, reports,
  onScan, onCancel, onExpand, onOpenLatest, onOpenReport, onDeleteReport,
  onRemove, onDeleteSource,
}: RowProps) {
  const job = p.last_job
  const changes = changeCounts(latest)
  return (
    <>
      <tr className={isOpen ? 'lib-row open' : 'lib-row'}>
        <td className="lib-name">
          <button className="link" onClick={onExpand}
            title={isOpen ? 'Hide reports' : 'Show reports'}>
            {p.name}
          </button>
          <span className="mono muted lib-loc">{p.location}</span>
        </td>
        <td>
          <span className="lib-kind">
            {p.kind === 'git'
              ? <><GitBranch size={12} /> Git</>
              : <><FolderOpen size={12} /> Local</>}
          </span>
          {!p.source_available && (
            <span className="lib-badge lib-badge-warn"
              title="Source folder/clone is missing — scanning is disabled">
              no source
            </span>
          )}
        </td>
        <td>{latest ? formatWhen(latest.created_at) : '—'}</td>
        <td>
          {job === null ? (
            <span className="muted">never scanned</span>
          ) : (
            <span className={`lib-state lib-state-${job.state}`}
              title={job.error || jobStateLabel(job.state)}>
              {jobActive && <Loader2 className="spin" size={12} />}
              {jobStateLabel(job.state)}
            </span>
          )}
          {job !== null && job.state === 'failed' && job.error && (
            <span className="lib-err">{job.error}</span>
          )}
        </td>
        <td className="num">{latest ? latest.findings : '—'}</td>
        <td className="num">
          {changes === null ? (
            <span className="muted" title={latest
              ? 'This scan was not compared with a previous report'
              : 'Never scanned'}>—</span>
          ) : (
            <button className="link lib-new-link" disabled={changes.new === 0}
              onClick={() => latest && onOpenReport(latest.report_id, 'new')}
              title={changes.new === 0 ? 'No new findings'
                : 'Open the report filtered to the new findings'}>
              {changes.new}
            </button>
          )}
        </td>
        <td className="num">
          {changes === null ? <span className="muted">—</span> : changes.resolved}
        </td>
        <td>
          {latest && latest.verdict
            ? <>
                <span className={`lib-verdict ${verdictClass(latest.verdict)}`}>
                  {latest.verdict}
                </span>
                {isNewOnlyGate(latest) && (
                  <span className="lib-badge lib-badge-scope"
                    title="The verdict counted NEW findings only — existing
                          findings were not gated">
                    new only
                  </span>
                )}
              </>
            : '—'}
        </td>
        <td className="num">{latest ? formatDuration(latest.duration_ms) : '—'}</td>
        <td className="lib-actions">
          {jobActive ? (
            <button className="icon-btn" onClick={onCancel} disabled={busy}
              title="Cancel the running job">
              <X size={14} />
            </button>
          ) : (
            <button className="icon-btn" onClick={onScan}
              disabled={busy || !p.source_available}
              title={latest ? 'Rescan — choose what to compare against'
                : 'Scan now'}>
              {latest ? <RefreshCw size={14} /> : <Play size={14} />}
            </button>
          )}
          <button className="icon-btn" onClick={onOpenLatest}
            disabled={latest === null}
            title="Open the latest report">
            <FolderOpen size={14} />
          </button>
          <button className="icon-btn danger" onClick={onRemove}
            disabled={busy || jobActive}
            title="Remove from library (reports deleted; source kept)">
            <Trash2 size={14} />
          </button>
        </td>
      </tr>
      {isOpen && (
        <tr className="lib-reports-row">
          <td colSpan={10}>
            {reports === null ? (
              <span className="muted"><Loader2 className="spin" size={12} /> Loading reports…</span>
            ) : reports.length === 0 ? (
              <span className="muted">No reports yet — run a scan.</span>
            ) : (
              <table className="lib-subtable">
                <thead>
                  <tr>
                    <th>Created</th><th className="num">Findings</th>
                    <th className="num">New</th>
                    <th className="num">Existing</th>
                    <th className="num">Resolved</th>
                    <th>Verdict</th><th className="num">Time</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => {
                    const c = changeCounts(r)
                    return (
                    <tr key={r.report_id}>
                      <td>{formatWhen(r.created_at)}</td>
                      <td className="num">{r.findings}</td>
                      {c === null ? (
                        <td className="num muted" colSpan={3}
                          title="This scan was not compared with a previous report">
                          not compared
                        </td>
                      ) : (
                        <>
                          <td className="num">{c.new}</td>
                          <td className="num">{c.unchanged}</td>
                          <td className="num">{c.resolved}</td>
                        </>
                      )}
                      <td>
                        <span className={`lib-verdict ${verdictClass(r.verdict)}`}>
                          {r.verdict || '—'}
                        </span>
                        {isNewOnlyGate(r) && (
                          <span className="lib-badge lib-badge-scope"
                            title={`Gate scope: ${gateScopeLabel(r)}`}>
                            new only
                          </span>
                        )}
                      </td>
                      <td className="num">{formatDuration(r.duration_ms)}</td>
                      <td className="lib-actions">
                        {c !== null && c.new > 0 && (
                          <button className="icon-btn"
                            onClick={() => onOpenReport(r.report_id, 'new')}
                            title="Open this report filtered to its new findings">
                            <Sparkles size={14} />
                          </button>
                        )}
                        <button className="icon-btn"
                          onClick={() => onOpenReport(r.report_id)}
                          title="Open this report">
                          <FolderOpen size={14} />
                        </button>
                        <button className="icon-btn danger"
                          onClick={() => onDeleteReport(r.report_id)}
                          title="Delete this report and its sidecars">
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
            {p.kind === 'git' && p.source_available && (
              <button className="btn btn-danger-outline lib-del-src"
                onClick={onDeleteSource} disabled={busy || jobActive}>
                <Trash2 size={13} /> Delete managed clone
              </button>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

// W4-B: everything a scan decides, in one place. It opens for every scan,
// so the comparison is visible BEFORE the run rather than discovered in the
// results — and on a first scan it says plainly that there is nothing to
// compare with yet.
function ScanOptionsModal({
  project: p, caps, history, online, semgrep, onClose, onStart,
}: {
  project: LibraryProject
  caps: LibraryCapabilities | null
  history: LibraryReportRow[] | null
  online: boolean
  semgrep: boolean
  onClose: () => void
  onStart: (opts: ScanOptions) => Promise<void>
}) {
  const hasHistory = p.reports_count > 0
  const [opts, setOpts] = useState<ScanOptions>(
    { ...defaultScanOptions(hasHistory), online, semgrep })
  const [starting, setStarting] = useState(false)
  const set = (patch: Partial<ScanOptions>) =>
    setOpts((prev) => ({ ...prev, ...patch }))
  const newOnlyBlocked = newOnlyBlockedReason(opts, hasHistory)
  const choices = baselineChoices(history ?? [], opts.baselineReportId)

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal lib-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <strong>Scan “{p.name}”</strong>
          <button className="icon-btn" onClick={onClose} title="Close">
            <X size={14} />
          </button>
        </div>
        <div className="modal-body">
          <label className="lib-opt-row">
            <input type="checkbox" checked={opts.online}
              onChange={(e) => {
                if (!e.target.checked) { set({ online: false }); return }
                set({ online: window.confirm(
                  'Online registry checks send dependency NAMES to public '
                  + 'registries (PyPI/npm/Maven/NuGet). No code is sent. '
                  + 'Enable for this scan?') })
              }} />
            <span>
              <strong>Check registries online</strong>
              <span className="muted"> — off by default; sends dependency
                names only, never code</span>
            </span>
          </label>
          <label className={`lib-opt-row ${caps && !caps.semgrepAvailable
            ? 'muted' : ''}`}>
            <input type="checkbox" checked={opts.semgrep}
              disabled={caps !== null && !caps.semgrepAvailable}
              onChange={(e) => set({ semgrep: e.target.checked })} />
            <span>
              <strong>Run Semgrep too</strong>
              <span className="muted">
                {caps && !caps.semgrepAvailable
                  ? ' — not installed on this machine'
                  : ' — the pattern engine, in addition to the built-in rules'}
              </span>
            </span>
          </label>

          <hr className="lib-sep" />

          <label className="lib-opt-row">
            <input type="checkbox" checked={opts.comparePrevious}
              disabled={!hasHistory}
              onChange={(e) => set({
                comparePrevious: e.target.checked,
                newOnly: e.target.checked && opts.newOnly,
              })} />
            <span>
              <strong><GitCompare size={13} /> Compare with previous</strong>
              <span className="muted">
                {hasHistory
                  ? ' — marks each finding as new or existing, and counts what'
                    + ' the baseline had and this scan no longer finds'
                  : ' — this is the first scan; there is nothing to compare'
                    + ' with yet'}
              </span>
            </span>
          </label>

          {opts.comparePrevious && (
            <label className="field lib-baseline-field">
              <span>Compare against</span>
              <select className="review-select" value={opts.baselineReportId}
                onChange={(e) => set({ baselineReportId: e.target.value })}>
                {choices.map((c) => (
                  <option key={c.id || 'default'} value={c.id}>{c.label}</option>
                ))}
              </select>
              {history === null && (
                <span className="muted">Loading this project’s history…</span>
              )}
            </label>
          )}

          <label className={`lib-opt-row ${newOnlyBlocked ? 'muted' : ''}`}>
            <input type="checkbox" checked={opts.newOnly}
              disabled={newOnlyBlocked !== null}
              onChange={(e) => set({ newOnly: e.target.checked })} />
            <span>
              <strong>Gate new findings only</strong>
              <span className="muted">
                {newOnlyBlocked
                  ? ` — ${newOnlyBlocked}`
                  : ' — the verdict counts only findings absent from the'
                    + ' baseline. The report still lists everything.'}
              </span>
            </span>
          </label>
          {opts.newOnly && (
            <p className="lib-note lib-warn-note">
              A pass under this setting means “nothing new”, not “nothing
              wrong”. Existing findings are still in the report.
            </p>
          )}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose} disabled={starting}>
            Cancel
          </button>
          <button className="btn btn-primary" disabled={starting}
            onClick={async () => {
              setStarting(true)
              try { await onStart(opts) } finally { setStarting(false) }
            }}>
            {starting ? <Loader2 className="spin" size={13} /> : null}
            Start scan
          </button>
        </div>
      </div>
    </div>
  )
}

function AddProjectModal({ caps, onClose, onAdd }: {
  caps: LibraryCapabilities | null
  onClose: () => void
  onAdd: (body: { kind: string; name?: string; path?: string; url?: string })
    => Promise<void>
}) {
  const [tab, setTab] = useState<'local' | 'git'>('local')
  const [name, setName] = useState('')
  const [path, setPath] = useState('')
  const [url, setUrl] = useState('')
  const [problem, setProblem] = useState<string | null>(null)
  const [serverError, setServerError] = useState('')
  const [saving, setSaving] = useState(false)

  const submit = async () => {
    const p = tab === 'local' ? localPathProblem(path) : gitUrlProblem(url)
    setProblem(p)
    if (p) return
    setSaving(true)
    setServerError('')
    try {
      await onAdd(tab === 'local'
        ? { kind: 'local', name, path: path.trim() }
        : { kind: 'git', name, url: url.trim() })
    } catch (e) {
      setServerError(String((e as Error)?.message ?? e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal lib-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <strong>Add project</strong>
          <button className="icon-btn" onClick={onClose} title="Close">
            <X size={14} />
          </button>
        </div>
        <nav className="tabs modal-tabs">
          <button className={`tab ${tab === 'local' ? 'active' : ''}`}
            onClick={() => { setTab('local'); setProblem(null) }}>
            <FolderOpen size={13} /> Local folder
          </button>
          <button className={`tab ${tab === 'git' ? 'active' : ''}`}
            onClick={() => { setTab('git'); setProblem(null) }}
            disabled={caps !== null && !caps.gitAvailable}
            title={caps !== null && !caps.gitAvailable
              ? 'git is not installed on this machine' : undefined}>
            <GitBranch size={13} /> Git URL
          </button>
        </nav>
        <div className="modal-body">
          <label className="field">
            <span>Display name (optional)</span>
            <input className="input" value={name} maxLength={100}
              onChange={(e) => setName(e.target.value)} />
          </label>
          {tab === 'local' ? (
            <label className="field">
              <span>Absolute folder path (must be under an allowed root)</span>
              <input className="input mono" value={path}
                placeholder="C:\work\my-project"
                onChange={(e) => { setPath(e.target.value); setProblem(null) }} />
            </label>
          ) : (
            <label className="field">
              <span>
                Public repository URL — github.com, gitlab.com, or
                bitbucket.org over https only, no credentials
              </span>
              <input className="input mono" value={url}
                placeholder="https://github.com/owner/repo.git"
                onChange={(e) => { setUrl(e.target.value); setProblem(null) }} />
            </label>
          )}
          {problem && <div className="lib-field-error">{problem}</div>}
          {serverError && <div className="lib-field-error">{serverError}</div>}
          <p className="muted lib-note">
            Scans run OFFLINE by default. Nothing is uploaded anywhere; the
            optional online mode only checks dependency names against public
            registries.
          </p>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving}>
            {saving ? <Loader2 className="spin" size={13} /> : null}
            {tab === 'local' ? 'Register folder' : 'Add & clone'}
          </button>
        </div>
      </div>
    </div>
  )
}

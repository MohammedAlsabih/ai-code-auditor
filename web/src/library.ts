// W4-A2: the pure Library-mode model — parsers, labels, and light client
// mirrors of the server-side validation (the SERVER decision is final; the
// mirrors only give instant feedback in the add-project modal).
// No React, no fetch — node-testable.

export type LibrarySession = { mode: 'library'; token: string }

export type LibraryCapabilities = {
  gitAvailable: boolean
  semgrepAvailable: boolean
  semgrepEngine: string
  registryDefault: string
  reportsKeptPerProject: number
  storeAvailable: boolean
  storeError: string
}

export type LibraryReportRow = {
  report_id: string
  created_at: string
  verdict: string
  findings: number
  duration_ms: number
  // W4-B. `findings` stays the WHOLE report's count; these describe the
  // comparison with an earlier report and never replace it.
  baseline_report_id: string
  baseline_enabled: boolean
  baseline_findings: number
  new: number
  unchanged: number
  resolved: number
  gate_scope: string
  // The server's committed order. `created_at` is for reading; THIS is what
  // "newer" means — two reports can share a timestamp, never a seq.
  seq: number
}

export type LibraryJobRow = {
  job_id: string
  kind: string
  state: string
  online: boolean
  semgrep: boolean
  created_at: string
  finished_at: string
  error: string
  report_id: string
  baseline_report_id: string
  new_only: boolean
}

export type LibraryProject = {
  project_id: string
  name: string
  kind: 'local' | 'git'
  location: string
  created_at: string
  source_available: boolean
  reports_count: number
  latest_report: LibraryReportRow | null
  last_job: LibraryJobRow | null
}

export const JOB_STATES = [
  'pending', 'running', 'completed', 'failed', 'canceled', 'interrupted',
] as const

const ACTIVE_STATES = new Set(['pending', 'running'])

export function isActiveJobState(state: string): boolean {
  return ACTIVE_STATES.has(state)
}

export function jobStateLabel(state: string): string {
  switch (state) {
    case 'pending': return 'Queued'
    case 'running': return 'Running'
    case 'completed': return 'Completed'
    case 'failed': return 'Failed'
    case 'canceled': return 'Canceled'
    case 'interrupted': return 'Interrupted (server restarted)'
    default: return state || 'Unknown'
  }
}

// ---- parsers (defensive: unknown shapes degrade, never throw) -----------------------

function str(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback
}

function num(v: unknown, fallback = 0): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback
}

function bool(v: unknown): boolean {
  return v === true
}

export function parseSession(raw: unknown): LibrarySession | null {
  if (!raw || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  if (o.mode !== 'library' || typeof o.token !== 'string' || !o.token) {
    return null
  }
  return { mode: 'library', token: o.token }
}

export function parseCapabilities(raw: unknown): LibraryCapabilities {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  return {
    gitAvailable: bool(o.git_available),
    semgrepAvailable: bool(o.semgrep_available),
    semgrepEngine: str(o.semgrep_engine),
    registryDefault: str(o.registry_default, 'offline'),
    reportsKeptPerProject: num(o.reports_kept_per_project, 10),
    storeAvailable: o.store_available !== false,
    storeError: str(o.store_error),
  }
}

function parseReportRow(raw: unknown): LibraryReportRow | null {
  if (!raw || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  if (typeof o.report_id !== 'string' || !o.report_id) return null
  // W4-B: a comparison is shown only when the row says there WAS one and
  // names what it compared against. A row from an older server (no baseline
  // fields at all) degrades to "no comparison" rather than to zeros that
  // would read as "nothing changed".
  const enabled = bool(o.baseline_enabled) && typeof o.baseline_report_id
    === 'string' && o.baseline_report_id !== ''
  const findings = num(o.findings)
  const fresh = enabled ? num(o.new) : 0
  const same = enabled ? num(o.unchanged) : 0
  const gone = enabled ? num(o.resolved) : 0
  // The server refuses to store counts that do not add up, so a row that
  // arrives not adding up did not come from a healthy server. Showing it
  // as "not compared" is the honest degradation: a partial comparison read
  // as a real one is worse than no comparison at all.
  const coherent = enabled && fresh + same === findings
    && same + gone === num(o.baseline_findings)
  return {
    report_id: o.report_id,
    created_at: str(o.created_at),
    verdict: str(o.verdict),
    findings,
    duration_ms: num(o.duration_ms),
    baseline_report_id: coherent ? str(o.baseline_report_id) : '',
    baseline_enabled: coherent,
    baseline_findings: coherent ? num(o.baseline_findings) : 0,
    new: coherent ? fresh : 0,
    unchanged: coherent ? same : 0,
    resolved: coherent ? gone : 0,
    gate_scope: o.gate_scope === 'new' && coherent ? 'new' : 'all',
    seq: num(o.seq),
  }
}

function parseJobRow(raw: unknown): LibraryJobRow | null {
  if (!raw || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  if (typeof o.job_id !== 'string' || !o.job_id) return null
  return {
    job_id: o.job_id,
    kind: str(o.kind),
    state: str(o.state, 'unknown'),
    online: bool(o.online),
    semgrep: bool(o.semgrep),
    created_at: str(o.created_at),
    finished_at: str(o.finished_at),
    error: str(o.error),
    report_id: str(o.report_id),
    baseline_report_id: str(o.baseline_report_id),
    new_only: bool(o.new_only),
  }
}

export function parseProjects(raw: unknown): LibraryProject[] {
  if (!raw || typeof raw !== 'object') return []
  const list = (raw as Record<string, unknown>).projects
  if (!Array.isArray(list)) return []
  const rows: LibraryProject[] = []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const o = item as Record<string, unknown>
    if (typeof o.project_id !== 'string' || !o.project_id) continue
    const kind = o.kind === 'git' ? 'git' : 'local'
    rows.push({
      project_id: o.project_id,
      name: str(o.name, '(unnamed)'),
      kind,
      location: str(o.location),
      created_at: str(o.created_at),
      source_available: bool(o.source_available),
      reports_count: num(o.reports_count),
      latest_report: parseReportRow(o.latest_report),
      last_job: parseJobRow(o.last_job),
    })
  }
  return rows
}

export function parseReports(raw: unknown): LibraryReportRow[] {
  if (!raw || typeof raw !== 'object') return []
  const list = (raw as Record<string, unknown>).reports
  if (!Array.isArray(list)) return []
  return list.map(parseReportRow).filter((r): r is LibraryReportRow => r !== null)
}

export function parseJob(raw: unknown): LibraryJobRow | null {
  if (!raw || typeof raw !== 'object') return null
  return parseJobRow((raw as Record<string, unknown>).job)
}

// ---- W4-B: scan options and the change summary ---------------------------------------

export type ScanOptions = {
  online: boolean
  semgrep: boolean
  comparePrevious: boolean
  baselineReportId: string      // '' = let the server pick the newest
  newOnly: boolean
}

export function defaultScanOptions(hasHistory: boolean): ScanOptions {
  // Comparison is on by default once there is something to compare with, and
  // costs nothing when there is not. Narrowing the gate is never a default:
  // a scan that only gates NEW findings is a deliberate choice.
  return {
    online: false,
    semgrep: false,
    comparePrevious: hasHistory,
    baselineReportId: '',
    newOnly: false,
  }
}

/** The request body, as the server's `ScanIn` expects it. Pure, so the
 * contract is testable without a browser: no path field exists here, and
 * `new_only` can never be sent without a comparison. */
export function scanRequestBody(o: ScanOptions): {
  online: boolean; semgrep: boolean; compare_previous: boolean
  baseline_report_id: string; new_only: boolean
} {
  const compare = o.comparePrevious
  return {
    online: o.online,
    semgrep: o.semgrep,
    compare_previous: compare,
    baseline_report_id: compare ? o.baselineReportId : '',
    new_only: compare && o.newOnly,
  }
}

/** Why "gate new findings only" cannot be chosen, or null when it can. */
export function newOnlyBlockedReason(
  o: ScanOptions, hasHistory: boolean,
): string | null {
  if (!hasHistory) return 'Needs a previous report to compare against.'
  if (!o.comparePrevious) return 'Turn on "Compare with previous" first.'
  return null
}

export type ChangeCounts = { new: number; unchanged: number; resolved: number }

/** The New/Existing/Resolved triple, or null when the report was not
 * compared with anything — a first scan shows "—", never three zeros, which
 * would read as "nothing changed". */
export function changeCounts(row: LibraryReportRow | null): ChangeCounts | null {
  if (!row || !row.baseline_enabled) return null
  return { new: row.new, unchanged: row.unchanged, resolved: row.resolved }
}

export function changeSummary(row: LibraryReportRow | null): string {
  const c = changeCounts(row)
  if (!c) return 'not compared'
  return `${c.new} new · ${c.unchanged} existing · ${c.resolved} resolved`
}

/** True when the verdict counted only the new findings — the badge that
 * stops a "pass" from being read as "this project is clean". */
export function isNewOnlyGate(row: LibraryReportRow | null): boolean {
  return row !== null && row.baseline_enabled && row.gate_scope === 'new'
}

export function gateScopeLabel(row: LibraryReportRow | null): string {
  if (!row) return '—'
  return isNewOnlyGate(row) ? 'new findings only' : 'all findings'
}

export type BaselineChoice = { id: string; label: string; current: boolean }

/** The baseline picker's options: this project's own history, newest first,
 * labelled by TIME only — never by path, and never by another project's
 * report. The first entry is the server's own default.
 *
 * Seconds are included on purpose. Two scans of a small project can finish
 * in the same minute, and a picker whose entries all read alike cannot be
 * used to pick — which is exactly what the minute-precision label produced
 * the first time this screen was looked at. */
export function baselineChoices(
  rows: LibraryReportRow[], selected: string,
): BaselineChoice[] {
  const out: BaselineChoice[] = [{
    id: '',
    label: rows.length > 0
      ? `Most recent (${formatWhenPrecise(rows[0].created_at)})`
      : 'Most recent',
    current: selected === '',
  }]
  for (const r of rows) {
    out.push({
      id: r.report_id,
      label: `${formatWhenPrecise(r.created_at)} · ${r.findings} finding(s)`,
      current: selected === r.report_id,
    })
  }
  return out
}

// ---- client-side pre-validation mirrors ---------------------------------------------

// W4-A3: fixed Alpha host policy — mirrors the server's ALLOWED_GIT_HOSTS.
export const ALLOWED_GIT_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org']

export function gitUrlProblem(url: string): string | null {
  const u = url.trim()
  if (!u) return 'Enter a repository URL.'
  if (!u.toLowerCase().startsWith('https://')) {
    return 'Only public https:// URLs are supported.'
  }
  if (/\s/.test(u) || u.includes('\\')) return 'The URL contains invalid characters.'
  if (u.includes('@')) return 'Credentials in the URL are not allowed.'
  if (u.includes('?') || u.includes('#')) {
    return 'Query strings and fragments are not allowed.'
  }
  const rest = u.slice('https://'.length)
  const slash = rest.indexOf('/')
  if (slash <= 0 || slash === rest.length - 1) {
    return 'The URL must include a host and a repository path.'
  }
  const host = rest.slice(0, slash).toLowerCase()
  if (host.includes(':')) return 'Custom ports are not allowed.'
  if (!ALLOWED_GIT_HOSTS.includes(host)) {
    return 'Only public repositories on github.com, gitlab.com, or '
      + 'bitbucket.org are supported in Alpha.'
  }
  return null
}

export function localPathProblem(path: string): string | null {
  const p = path.trim()
  if (!p) return 'Enter a folder path.'
  if (p.includes('\x00')) return 'The path contains invalid characters.'
  if (p.startsWith('\\\\') || p.startsWith('//')) {
    return 'Network (UNC) paths are not allowed.'
  }
  const looksAbsolute = /^[A-Za-z]:[\\/]/.test(p) || p.startsWith('/')
  if (!looksAbsolute) return 'Enter an absolute folder path.'
  if (p.split(/[\\/]+/).some((seg) => seg === '..')) {
    return 'Path traversal is not allowed.'
  }
  return null
}

// ---- formatting -----------------------------------------------------------------------

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '—'
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`
  const m = Math.floor(s / 60)
  return `${m}m ${Math.round(s - m * 60)}s`
}

export function formatWhen(iso: string): string {
  if (!iso) return '—'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const d = new Date(t)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** Same as `formatWhen`, to the second — for places where two entries must
 * be told apart rather than merely read (the baseline picker). */
export function formatWhenPrecise(iso: string): string {
  if (!iso) return '—'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const d = new Date(t)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${formatWhen(iso)}:${pad(d.getSeconds())}`
}

export function verdictClass(verdict: string): string {
  switch (verdict) {
    case 'pass': return 'verdict-pass'
    case 'review': return 'verdict-review'
    case 'block': return 'verdict-block'
    default: return 'verdict-unknown'
  }
}

// The library screen's filters survive opening/closing a report because the
// state lives in App, not in the panel. This helper applies them purely.
export function filterProjects(
  rows: LibraryProject[], query: string, state: string,
): LibraryProject[] {
  const q = query.trim().toLowerCase()
  return rows.filter((r) => {
    if (q && !`${r.name}\n${r.location}`.toLowerCase().includes(q)) return false
    if (state === 'all') return true
    if (state === 'never') return r.reports_count === 0
    return (r.last_job?.state ?? '') === state
  })
}

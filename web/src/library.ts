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
  return {
    report_id: o.report_id,
    created_at: str(o.created_at),
    verdict: str(o.verdict),
    findings: num(o.findings),
    duration_ms: num(o.duration_ms),
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

// ---- client-side pre-validation mirrors ---------------------------------------------

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

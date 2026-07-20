// Pure Rule Coverage model (W2-B2.7C1). Reads EXCLUSIVELY from the report's
// analysis_manifest.catalog + analysis_manifest.execution — rule execution is
// never inferred from findings, and a v1 report (no execution block) gets NO
// fabricated statuses. Every input is type-guarded: malformed shapes degrade
// to notes, never a crash. "executed" is neutral — the rule RAN; there is
// deliberately no pass/clean/safe anywhere in this module.

export const EXECUTION_STATUSES = [
  'executed', 'partial', 'failed', 'blocked', 'unavailable',
  'skipped', 'not_applicable', 'not_recorded', 'inconsistent',
] as const
export type ExecutionStatus = (typeof EXECUTION_STATUSES)[number]

// "attention" = how much a status needs a human eye. NOT severity of code.
export const ATTENTION_ORDER: Record<ExecutionStatus, number> = {
  inconsistent: 0,
  failed: 1,
  partial: 2,
  blocked: 3,
  unavailable: 4,
  skipped: 5,
  not_recorded: 6,
  not_applicable: 7,
  executed: 8,
}

export interface ExecRecord {
  status: ExecutionStatus
  // counters/reasons are OPTIONAL: a field absent from the report is absent
  // here too — the UI must not display a fabricated zero
  eligible_inputs?: number
  attempted?: number
  failures?: number
  blocked_inputs?: number
  partial_parse_inputs?: number
  not_applicable_reasons?: string[]
  unavailable_reasons?: string[]
  partial_reasons?: string[]
  failure_reasons?: string[]
  skipped_reasons?: string[]
}

export interface RuleContext {
  root: string
  language: string
  status: ExecutionStatus
  record: ExecRecord | null // null = catalog rule with no ledger record here
  // contract errors scoped to THIS project context:
  projectErrors: string[] // project-general (e.g. non-relative root)
  ruleErrors: string[] // exact "rule <id>:" prefix matches only
}

export interface RuleRow {
  rule_id: string
  title: string
  description: string
  source: string
  engine: string
  category: string
  scope: string
  default_level: string
  default_precision: string
  languages: string[]
  frameworks: string[]
  fromCatalog: boolean // false => execution-only id, shown as inconsistent
  contexts: RuleContext[]
  statusCounts: Partial<Record<ExecutionStatus, number>>
}

export interface RuleCoverage {
  rows: RuleRow[]
  executionAvailable: boolean
  catalogAvailable: boolean
  notes: string[] // safe notes about malformed/ignored input shapes
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)
const str = (v: unknown, fallback = ''): string =>
  typeof v === 'string' ? v : fallback
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []

function legalStatus(v: unknown): ExecutionStatus {
  return typeof v === 'string' &&
    (EXECUTION_STATUSES as readonly string[]).includes(v)
    ? (v as ExecutionStatus)
    : 'inconsistent'
}

const COUNTER_FIELDS = ['eligible_inputs', 'attempted', 'failures',
  'blocked_inputs', 'partial_parse_inputs'] as const
const REASON_FIELDS = ['not_applicable_reasons', 'unavailable_reasons',
  'partial_reasons', 'failure_reasons', 'skipped_reasons'] as const

function wellFormed(s: string): boolean {
  // a lone surrogate cannot round-trip as UTF-8 — reject it
  try {
    encodeURIComponent(s)
    return true
  } catch {
    return false
  }
}

function validCounter(n: unknown): n is number {
  return typeof n === 'number' && !Number.isNaN(n) &&
    Number.isInteger(n) && n >= 0
}

function validReasons(v: unknown): v is string[] {
  if (!Array.isArray(v)) return false
  const seen = new Set<string>()
  for (const x of v) {
    if (typeof x !== 'string' || !x.trim() || !wellFormed(x) || seen.has(x)) {
      return false
    }
    seen.add(x)
  }
  return true
}

interface FullRecordV1 {
  eligible_inputs: number
  attempted: number
  failures: number
  blocked_inputs: number
  partial_parse_inputs: number
  not_applicable_reasons: string[]
  unavailable_reasons: string[]
  partial_reasons: string[]
  failure_reasons: string[]
  skipped_reasons: string[]
}

/** PURE mirror of core/execution.py derive_execution_status for a
 * structurally valid execution v1 record. Findings never participate. */
export function deriveExecutionStatusV1(rec: FullRecordV1): ExecutionStatus {
  if (rec.failures > rec.attempted) return 'inconsistent'
  if (rec.blocked_inputs > rec.eligible_inputs) return 'inconsistent'
  if (rec.partial_parse_inputs > rec.attempted) return 'inconsistent'
  if (rec.failure_reasons.length && rec.failures === 0) return 'inconsistent'
  if (rec.partial_reasons.length && rec.attempted === 0) return 'inconsistent'
  if (rec.attempted > 0 && (rec.unavailable_reasons.length ||
      rec.skipped_reasons.length || rec.not_applicable_reasons.length)) {
    return 'inconsistent'
  }
  const categories = [rec.not_applicable_reasons, rec.unavailable_reasons,
    rec.skipped_reasons].filter((r) => r.length).length
  if (categories > 1) return 'inconsistent'
  if (rec.not_applicable_reasons.length &&
      (rec.eligible_inputs > 0 || rec.blocked_inputs > 0)) {
    return 'inconsistent'
  }
  if (rec.attempted > 0) {
    if (rec.failures === rec.attempted) return 'failed'
    if (rec.failures || rec.blocked_inputs || rec.partial_parse_inputs ||
        rec.partial_reasons.length) return 'partial'
    return 'executed'
  }
  if (rec.skipped_reasons.length) return 'skipped'
  if (rec.unavailable_reasons.length) return 'unavailable'
  if (rec.not_applicable_reasons.length) return 'not_applicable'
  if (rec.blocked_inputs > 0) return 'blocked'
  return 'not_recorded'
}

/** SEMANTIC read of one execution v1 record. The v1 contract is fixed: all
 * 11 fields must be present — five non-negative integer counters, five lists
 * of unique non-empty UTF-8 strings, and a status. A malformed shape, OR a
 * stored status that does not match the independently derived one, is
 * "inconsistent"; violating raw values (which could carry paths or secrets)
 * are dropped, never rendered. Malformed data can never remain "executed". */
function toRecord(v: unknown): ExecRecord {
  if (!isObj(v)) return { status: 'inconsistent' }
  let shapeOk = typeof v.status === 'string' &&
    (EXECUTION_STATUSES as readonly string[]).includes(v.status)
  const rec: ExecRecord = { status: legalStatus(v.status) }
  for (const f of COUNTER_FIELDS) {
    if (validCounter(v[f])) rec[f] = v[f] as number
    else shapeOk = false // absent or junk: dropped, never shown raw
  }
  for (const f of REASON_FIELDS) {
    const raw = v[f]
    if (validReasons(raw)) {
      rec[f] = [...raw]
    } else {
      shapeOk = false
      // keep only the SAFE subset for display; junk values never survive
      if (Array.isArray(raw)) {
        const clean: string[] = []
        for (const x of raw) {
          if (typeof x === 'string' && x.trim() && wellFormed(x) &&
              !clean.includes(x)) clean.push(x)
        }
        rec[f] = clean
      }
    }
  }
  if (!shapeOk) {
    rec.status = 'inconsistent'
    return rec
  }
  // full shape present: the stored status must MATCH the derived one
  const derived = deriveExecutionStatusV1(rec as unknown as FullRecordV1)
  rec.status = rec.status === derived ? derived : 'inconsistent'
  return rec
}

// execution project languages are adapter names; descriptors may declare
// finer file languages — the only known alias today is dotnet -> csharp
const PROJECT_LANG_ALIASES: Record<string, string[]> = { dotnet: ['csharp'] }

function languageMatches(projectLang: string, ruleLangs: string[]): boolean {
  if (!ruleLangs.length) return false // unknown declaration: never fabricate
  const effective = [projectLang, ...(PROJECT_LANG_ALIASES[projectLang] ?? [])]
  return effective.some((l) => ruleLangs.includes(l))
}

/** Build the Rules-tab model from a report's analysis_manifest (unknown-shaped
 * on purpose: old/malformed reports must degrade, not throw). */
export function buildRuleCoverage(manifest: unknown): RuleCoverage {
  const notes: string[] = []
  const rowsById = new Map<string, RuleRow>()

  const mf = isObj(manifest) ? manifest : null
  if (manifest !== undefined && manifest !== null && mf === null) {
    notes.push('analysis_manifest has an unexpected shape and was ignored')
  }

  // ---- STRICT schema gate: only the known contracts are interpreted -------
  // manifest v1 = catalog without execution; manifest v2 = + execution v1.
  // Anything else (unknown version, malformed shape) is displayed as NOTHING
  // rather than guessed — no fabricated statuses, no half-read catalog.
  const mfVersion = mf?.schema_version
  const manifestKnown = mf !== null && (mfVersion === 1 || mfVersion === 2)
  if (mf !== null && !manifestKnown) {
    notes.push('analysis_manifest has an unknown schema_version — catalog and '
      + 'execution are not displayed')
  }

  // ---- catalog: capability — every shipped rule, findings or not ----------
  const rawCatalog = manifestKnown ? mf?.catalog : undefined
  const catalogAvailable = Array.isArray(rawCatalog)
  if (manifestKnown && mf?.catalog !== undefined && !catalogAvailable) {
    notes.push('analysis_manifest.catalog has an unexpected shape and was ignored')
  }
  if (catalogAvailable) {
    for (const d of rawCatalog as unknown[]) {
      if (!isObj(d) || typeof d.rule_id !== 'string' || !d.rule_id) {
        notes.push('a catalog entry without a valid rule_id was skipped')
        continue
      }
      if (rowsById.has(d.rule_id)) continue
      rowsById.set(d.rule_id, {
        rule_id: d.rule_id,
        title: str(d.title, d.rule_id),
        description: str(d.description),
        source: str(d.source),
        engine: str(d.engine),
        category: str(d.category),
        scope: str(d.scope),
        default_level: str(d.default_level),
        default_precision: str(d.default_precision),
        languages: strList(d.languages),
        frameworks: strList(d.frameworks),
        fromCatalog: true,
        contexts: [],
        statusCounts: {},
      })
    }
  }

  // ---- execution: per-project evidence ------------------------------------
  // Interpreted ONLY under the known contract: manifest v2 carrying an
  // execution block whose OWN schema_version is 1. An unknown execution
  // version (or execution under manifest v1) is never guessed.
  const rawExec = manifestKnown ? mf?.execution : undefined
  const execObj = isObj(rawExec) ? rawExec : null
  if (rawExec !== undefined && execObj === null) {
    notes.push('analysis_manifest.execution has an unexpected shape and was ignored')
  }
  let executionAvailable = false
  let projects: Array<Record<string, unknown>> = []
  if (execObj !== null) {
    if (mfVersion !== 2) {
      notes.push('an execution block under manifest schema v1 is not a known '
        + 'contract — execution is not displayed')
    } else if (execObj.schema_version !== 1) {
      notes.push('analysis_manifest.execution has an unknown schema_version — '
        + 'execution is not displayed')
    } else if (!Array.isArray(execObj.projects)) {
      notes.push('analysis_manifest.execution.projects has an unexpected shape '
        + 'and was ignored')
    } else {
      // EVERY project entry is validated in full: root string, non-empty
      // language string, rules object, contract_errors list of strings. An
      // invalid entry is skipped ENTIRELY (no not_recorded fabricated from
      // it) with a note naming only its index/field — never the raw value.
      const rawProjects = execObj.projects as unknown[]
      rawProjects.forEach((p, i) => {
        const skip = (field: string) => notes.push(
          `execution project at index ${i} was skipped (invalid ${field})`)
        if (!isObj(p)) { skip('entry') } else if (typeof p.root !== 'string') {
          skip('root')
        } else if (typeof p.language !== 'string' || !p.language) {
          skip('language')
        } else if (!isObj(p.rules)) {
          skip('rules')
        } else if (!Array.isArray(p.contract_errors) ||
            (p.contract_errors as unknown[]).some((x) => typeof x !== 'string')) {
          skip('contract_errors')
        } else {
          projects.push(p)
        }
      })
      // an empty projects list is a legal contract; a NON-empty list whose
      // entries are all invalid is not usable evidence
      executionAvailable = rawProjects.length === 0 || projects.length > 0
      if (!executionAvailable) {
        notes.push('all execution projects were invalid — execution is not displayed')
      }
    }
  }

  if (executionAvailable) {
    for (const proj of projects) {
      const root = str(proj.root, '?')
      const language = str(proj.language, '?')
      const rules = isObj(proj.rules) ? proj.rules : {}
      const contractErrors = strList(proj.contract_errors)
      // project-general errors = everything NOT scoped to a rule id
      const projectErrors = contractErrors.filter((e) => !/^rule [^:]+:/.test(e))
      const recordedIds = new Set(Object.keys(rules))

      // execution ids missing from the catalog: KEPT, clearly inconsistent
      for (const rid of recordedIds) {
        if (!rowsById.has(rid)) {
          rowsById.set(rid, {
            rule_id: rid,
            title: `${rid} (recorded in execution but missing from the rule catalog)`,
            description: '',
            source: '',
            engine: '',
            category: '',
            scope: '',
            default_level: '',
            default_precision: '',
            languages: [],
            frameworks: [],
            fromCatalog: false,
            contexts: [],
            statusCounts: {},
          })
        }
      }

      for (const row of rowsById.values()) {
        const raw = rules[row.rule_id]
        // rule-scoped errors attach on the EXACT "rule <id>:" prefix only —
        // includes() would hand "rule P0011:" errors to P001 as well
        const ruleErrors = contractErrors.filter((e) =>
          e.startsWith(`rule ${row.rule_id}:`))
        let ctx: RuleContext
        if (raw === undefined) {
          // a missing-record context exists ONLY where the rule could apply:
          // the project's language must be among the descriptor's languages —
          // a python project never grows a phantom "not recorded" for a
          // TypeScript-only rule (and never the other way round)
          if (!row.fromCatalog || !languageMatches(language, row.languages)) {
            continue
          }
          // in the catalog, applicable language, but never recorded here:
          // an unrecorded gap — NOT "not applicable"
          ctx = { root, language, status: 'not_recorded', record: null,
                  projectErrors, ruleErrors }
        } else {
          const rec = toRecord(raw)
          // an id absent from the catalog can never claim a clean execution;
          // neither can a record CLAIMING WORK (eligible/attempted > 0) in a
          // language the rule does not declare. A zero-work record there
          // (e.g. not_applicable "no java files in this project") is
          // coherent evidence, not a contradiction.
          let status = row.fromCatalog ? rec.status : 'inconsistent'
          const claimsWork = (rec.eligible_inputs ?? 0) > 0 ||
            (rec.attempted ?? 0) > 0
          if (row.fromCatalog && claimsWork &&
              !languageMatches(language, row.languages)) {
            status = 'inconsistent'
            ruleErrors.push(`recorded for a ${language} project, but the rule `
              + 'does not declare that language')
          }
          ctx = { root, language, status, record: rec, projectErrors, ruleErrors }
        }
        row.contexts.push(ctx)
        row.statusCounts[ctx.status] = (row.statusCounts[ctx.status] ?? 0) + 1
      }
    }
  }
  // v1 report (no execution block): contexts stay EMPTY — no fabricated
  // statuses; the UI shows the rescan message instead.

  const rows = Array.from(rowsById.values()).sort((a, b) =>
    a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0)
  return { rows, executionAvailable, catalogAvailable, notes }
}

// ---- filtering: OR inside a category, AND across categories ----------------

export interface RuleFilters {
  query?: string
  statuses?: Set<string>
  languages?: Set<string>
  engines?: Set<string>
  categories?: Set<string>
  levels?: Set<string>
  precisions?: Set<string>
}

export function filterRuleRows(rows: RuleRow[], f: RuleFilters): RuleRow[] {
  const q = (f.query ?? '').trim().toLowerCase()
  return rows.filter((r) => {
    if (q) {
      const hay = `${r.rule_id}\n${r.title}\n${r.description}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    if (f.statuses?.size) {
      const own = r.contexts.map((c) => c.status)
      if (!own.some((s) => f.statuses!.has(s))) return false
    }
    if (f.languages?.size && !r.languages.some((l) => f.languages!.has(l))) return false
    if (f.engines?.size && !f.engines.has(r.engine)) return false
    if (f.categories?.size && !f.categories.has(r.category)) return false
    if (f.levels?.size && !f.levels.has(r.default_level)) return false
    if (f.precisions?.size && !f.precisions.has(r.default_precision)) return false
    return true
  })
}

export type RuleSortKey = 'id' | 'title' | 'engine' | 'attention'

export function sortRuleRows(rows: RuleRow[], key: RuleSortKey): RuleRow[] {
  const attention = (r: RuleRow): number =>
    r.contexts.length
      ? Math.min(...r.contexts.map((c) => ATTENTION_ORDER[c.status]))
      : 99
  const val = (r: RuleRow): string | number =>
    key === 'title' ? r.title.toLowerCase()
      : key === 'engine' ? r.engine
        : key === 'attention' ? attention(r)
          : r.rule_id
  return [...rows].sort((a, b) => {
    const x = val(a)
    const y = val(b)
    if (x !== y) return x < y ? -1 : 1
    return a.rule_id < b.rule_id ? -1 : 1 // stable tiebreak by id
  })
}

// ---- Findings rule-filter labels ------------------------------------------

const SHORT_TITLE_MAX = 46

export function shortTitle(title: string): string {
  const t = title.trim()
  if (t.length <= SHORT_TITLE_MAX) return t
  return `${t.slice(0, SHORT_TITLE_MAX - 1).trimEnd()}…`
}

/** Label for the Findings rule filter: "<rule_id> — <short title>". The
 * catalog is the first source; for OLD reports the first finding title for
 * that rule is the fallback; a rule with neither still shows its id (a
 * finding is never dropped for lacking a descriptor). */
export function ruleFilterOptions(
  ruleIds: string[],
  catalogRows: RuleRow[],
  findingTitleById: Record<string, string>,
): Array<{ id: string; label: string; full: string }> {
  const byId = new Map(catalogRows.map((r) => [r.rule_id, r]))
  return ruleIds.map((id) => {
    const full = byId.get(id)?.title || findingTitleById[id] || ''
    return {
      id,
      label: full ? `${id} — ${shortTitle(full)}` : id,
      full: full || id,
    }
  })
}

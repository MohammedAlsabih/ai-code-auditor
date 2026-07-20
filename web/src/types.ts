export interface RawFinding {
  rule_id: string
  severity: string // DEPRECATED legacy color (red/yellow/blue)
  level?: string // SARIF-compatible: error/warning/note
  title: string
  file: string
  line: number
  snippet?: string
  detail?: string
  language?: string
  precision?: string
  engine?: string
}

export interface Project {
  language: string
  root: string
  frameworks?: string[]
  file_count?: number
  score?: number
  counts?: Record<string, number>
  findings?: RawFinding[]
}

export interface Summary {
  overall_score?: number
  analysis_confidence?: number
  verdict?: string
  counts?: { red?: number; yellow?: number; blue?: number } // DEPRECATED
  level_counts?: { error?: number; warning?: number; note?: number }
}

export interface Report {
  summary: Summary
  projects: Project[]
  target?: string
  generated_at?: string
  // deliberately unknown-shaped: old reports lack it, malformed reports may
  // carry anything — rulecov.ts type-guards every access
  analysis_manifest?: unknown
}

// One numbered line of a source window from /api/source.
export interface SourceLine {
  number: number
  text: string
}

// The /api/source response: a WINDOW around the finding's line, never the
// whole file.
export interface SourceWindow {
  path: string
  requested_line: number
  start_line: number
  end_line: number
  total_lines: number
  lines: SourceLine[]
}

// A finding flattened out of its project, carrying the project context needed
// by the table (project + resolved language).
export interface Finding {
  rule_id: string
  severity: string // DEPRECATED legacy color, display fallback only
  level: string // canonical: error/warning/note, or '' when unclassified
  precision: string
  language: string
  project: string
  file: string
  line: number
  title: string
  detail: string
  snippet: string
  engine?: string
  review_id?: string
}

// One saved review decision (W2-B1). unreviewed = no record at all.
export interface Review {
  status: string // 'confirmed' | 'false_positive' | 'accepted_risk'
  note: string
  updated_at: string
}

export interface ReviewsResponse {
  available: boolean
  error: string | null
  reviews: Record<string, Review>
}

// Coverage & Methodology payload (W2-B2) — evidence-only; absent data is
// "not_recorded", never guessed.
export interface CoverageStage {
  key: string
  label: string
  status: 'complete' | 'partial' | 'failed' | 'unavailable' | 'not_recorded'
  evidence: string
  issues: string[]
}

export interface CoverageProject {
  root: string
  language: string
  frameworks: string[]
  file_count: number | null
  score: number | null
  findings_count: number | null
}

export interface ObservedRule {
  rule_id: string
  count: number
  languages: string[]
  precisions: string[]
  levels: string[]
}

export interface Coverage {
  provenance: {
    tool: string | null
    version: string | null
    generated_at: string | null
    target: string | null
    engines: Record<string, string>
  }
  projects: CoverageProject[]
  stages: CoverageStage[]
  diagnostics: {
    manifest_errors: string[]
    manifest_incomplete: string[]
    skipped_files: string[]
    parse_error_files: string[]
    rule_errors: string[]
    rule_attempted: number | null
    rule_failures: number | null
    registry_attempted: number | null
    registry_failures: number | null
    notes: string[]
    include_gaps: string[]
  }
  limitations: string[]
  observed_rules: ObservedRule[]
  observed_rules_disclaimer: string
}

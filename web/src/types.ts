export interface RawFinding {
  rule_id: string
  severity: string
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
  counts?: { red?: number; yellow?: number; blue?: number }
}

export interface Report {
  summary: Summary
  projects: Project[]
  target?: string
  generated_at?: string
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
  severity: string
  precision: string
  language: string
  project: string
  file: string
  line: number
  title: string
  detail: string
  snippet: string
  engine?: string
}

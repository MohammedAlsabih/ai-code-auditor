// SARIF-compatible level normalization — mirror of the backend's single
// source (auditor/core/levels.py). Contract:
// - the legacy-severity fallback applies ONLY when `level` is ABSENT
//   (undefined/null);
// - a VALID present level (error/warning/note) wins, even over a conflicting
//   legacy severity;
// - a PRESENT but invalid level ('none', '', 'bogus', objects, ...) yields ''
//   — unclassified; it never falls back to severity and is never promoted.

export const CANONICAL_LEVELS = ['error', 'warning', 'note'] as const

const LEGACY_TO_LEVEL: Record<string, string> = {
  red: 'error',
  yellow: 'warning',
  blue: 'note',
}

export function normalizeLevel(level: unknown, severity: string): string {
  if (level === undefined || level === null) {
    return LEGACY_TO_LEVEL[severity] ?? ''
  }
  if (
    typeof level === 'string' &&
    (CANONICAL_LEVELS as readonly string[]).includes(level)
  ) {
    return level
  }
  return '' // present but invalid: unclassified, no severity fallback
}

// visual derivation ONLY — the color is never the contract value
export function levelColor(level: string): 'red' | 'yellow' | 'blue' | '' {
  if (level === 'error') return 'red'
  if (level === 'warning') return 'yellow'
  if (level === 'note') return 'blue'
  return ''
}

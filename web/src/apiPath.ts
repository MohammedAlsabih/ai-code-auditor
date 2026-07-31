// Where an API request actually goes. Its own module, with no imports, so
// the rule can be tested directly under `node --test` — api.ts itself pulls
// in the whole app model and is not importable there.

/**
 * Library endpoints are server-global. Everything else is a REPORT endpoint,
 * and in Library mode it is served under that report's own prefix
 * `/api/library/reports/<rid>`, where the server appends its own `/api`
 * before dispatching — so the caller's leading `/api` has to come off, or
 * the request arrives as `/api/api/report` and 404s. In single-report
 * `serve` mode the base is empty and the path is used unchanged.
 *
 * This composition was previously inlined in `apiFetch` with the leading
 * `/api` left on, which broke opening ANY report from the library while
 * every server-side test still passed — the tests called the correct URL
 * directly, so nothing exercised how the browser built it.
 */
export function resolveApiPath(base: string, path: string): string {
  if (path.startsWith('/api/library/') || !base) return path
  return `${base}${path.startsWith('/api/') ? path.slice(4) : path}`
}

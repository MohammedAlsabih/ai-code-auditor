// Pure AI-providers model (W3-A) — Node-testable, no React, no network.
//
// The tab NEVER contacts a provider on open: GET /api/ai/providers is local
// server metadata, and only the explicit Refresh-models / Test-connection
// buttons trigger the POST endpoints. API keys never exist in the browser —
// no fields, no storage.

export interface AIProviderInfo {
  provider: string
  display: string
  configured: boolean
  key_present: boolean
  locality: 'local' | 'remote'
}

export const AI_STATUSES = [
  'ok',
  'not_configured',
  'authentication_failed',
  'model_not_found',
  'rate_limited',
  'timeout',
  'connection_failed',
  'invalid_response',
] as const

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

/** Strict guard over GET /api/ai/providers — malformed rows are dropped,
 * never guessed into the list. */
export function parseProviders(payload: unknown): AIProviderInfo[] {
  if (!isObj(payload) || !Array.isArray(payload.providers)) return []
  const out: AIProviderInfo[] = []
  for (const raw of payload.providers) {
    if (!isObj(raw)) continue
    const provider = raw.provider
    const display = raw.display
    const locality = raw.locality
    if (typeof provider !== 'string' || !provider) continue
    if (typeof display !== 'string' || !display) continue
    if (locality !== 'local' && locality !== 'remote') continue
    out.push({
      provider,
      display,
      configured: raw.configured === true,
      key_present: raw.key_present === true,
      locality,
    })
  }
  return out
}

/** Model ids from POST /api/ai/models — strings only, defensive. */
export function parseModelIds(payload: unknown): string[] {
  if (!isObj(payload) || !Array.isArray(payload.models)) return []
  return payload.models.filter(
    (m): m is string => typeof m === 'string' && m.length > 0,
  )
}

/** One safe status → short human line for the tooltip. Unknown statuses get
 * a generic line — nothing from the wire is echoed. */
export function statusTooltip(status: string): string {
  switch (status) {
    case 'ok':
      return 'Connection test passed.'
    case 'not_configured':
      return 'Not configured: set the provider API key or base URL in the server environment.'
    case 'authentication_failed':
      return 'The provider rejected the API key.'
    case 'model_not_found':
      return 'The selected model does not exist on this provider.'
    case 'rate_limited':
      return 'The provider rate-limited the request. Try again later.'
    case 'timeout':
      return 'The request timed out.'
    case 'connection_failed':
      return 'Could not reach the provider.'
    case 'invalid_response':
      return 'The provider returned an unexpected response.'
    default:
      return 'The request failed.'
  }
}

export const PROBE_NOTICE =
  'Connection tests send a fixed probe only. Reports and source code are not sent.'

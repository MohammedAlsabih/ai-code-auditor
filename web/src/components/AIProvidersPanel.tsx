import { useEffect, useState } from 'react'
import { Bot, CircleCheck, CircleX, Loader2, Plug, RefreshCw } from 'lucide-react'

import {
  type AIProviderInfo,
  PROBE_NOTICE,
  parseModelIds,
  parseProviders,
  statusTooltip,
} from '../ai'
import { fetchAIProviders, postAIModels, postAITest } from '../api'

interface RowState {
  models: string[]
  model: string
  modelsStatus: 'idle' | 'loading' | 'ok' | 'error'
  modelsError: string
  testStatus: 'idle' | 'loading' | 'ok' | 'error'
  testCode: string
  latency: number | null
}

const emptyRow = (): RowState => ({
  models: [],
  model: '',
  modelsStatus: 'idle',
  modelsError: '',
  testStatus: 'idle',
  testCode: '',
  latency: null,
})

export function AIProvidersPanel() {
  const [providers, setProviders] = useState<AIProviderInfo[]>([])
  const [loadError, setLoadError] = useState('')
  const [rows, setRows] = useState<Record<string, RowState>>({})

  // GET /api/ai/providers is LOCAL server metadata — the server contacts no
  // provider for it. Refresh/Test below are the only outbound triggers.
  useEffect(() => {
    fetchAIProviders()
      .then((p) => setProviders(parseProviders(p)))
      .catch((e) => setLoadError(String((e as Error)?.message ?? e)))
  }, [])

  const patch = (id: string, part: Partial<RowState>) =>
    setRows((prev) => ({ ...prev, [id]: { ...(prev[id] ?? emptyRow()), ...part } }))

  const refreshModels = async (id: string) => {
    patch(id, { modelsStatus: 'loading', modelsError: '' })
    try {
      const body = (await postAIModels(id)) as { status?: string; message?: string }
      if (body.status !== 'ok') {
        patch(id, {
          modelsStatus: 'error',
          modelsError: body.status ?? 'error',
        })
        return
      }
      const models = parseModelIds(body)
      patch(id, { modelsStatus: 'ok', models, model: models[0] ?? '' })
    } catch (e) {
      patch(id, { modelsStatus: 'error', modelsError: String((e as Error)?.message ?? e) })
    }
  }

  const testConnection = async (id: string, model: string) => {
    patch(id, { testStatus: 'loading', testCode: '', latency: null })
    try {
      const r = await postAITest(id, model)
      if (r.status === 'ok') {
        patch(id, { testStatus: 'ok', testCode: 'ok', latency: r.latency_ms ?? null })
      } else {
        patch(id, { testStatus: 'error', testCode: r.status })
      }
    } catch (e) {
      patch(id, { testStatus: 'error', testCode: String((e as Error)?.message ?? e) })
    }
  }

  if (loadError) {
    return <div className="fatal">Could not load AI providers: {loadError}</div>
  }

  return (
    <div className="ai-panel">
      <div className="ai-head">
        <h2>
          <Bot size={17} /> AI Providers
        </h2>
        <p className="ai-notice">{PROBE_NOTICE}</p>
        <p className="cov-muted">
          Keys and base URLs are configured in the server environment only —
          nothing is entered or stored in the browser. Nothing is contacted
          when this tab opens; only the buttons below start a request.
        </p>
      </div>
      <table className="ai-table">
        <thead>
          <tr>
            <th>Provider</th>
            <th>Configured</th>
            <th>Location</th>
            <th>Model</th>
            <th>Actions</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {providers.map((p) => {
            const row = rows[p.provider] ?? emptyRow()
            const busy = row.modelsStatus === 'loading' || row.testStatus === 'loading'
            return (
              <tr key={p.provider}>
                <td>
                  <b>{p.display}</b>
                  <div className="cov-muted mono">{p.provider}</div>
                </td>
                <td>
                  {p.configured ? (
                    <span className="ai-ok">configured</span>
                  ) : (
                    <span
                      className="ai-muted"
                      title="Set the provider's key/base URL in the server environment"
                    >
                      not configured
                    </span>
                  )}
                </td>
                <td>{p.locality === 'local' ? 'Local' : 'Remote'}</td>
                <td>
                  {row.models.length > 0 ? (
                    <select
                      value={row.model}
                      onChange={(e) => patch(p.provider, { model: e.target.value })}
                    >
                      {row.models.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      className="ai-model-input"
                      placeholder="model id…"
                      value={row.model}
                      onChange={(e) => patch(p.provider, { model: e.target.value })}
                    />
                  )}
                </td>
                <td className="ai-actions">
                  <button
                    className="btn"
                    disabled={busy}
                    onClick={() => refreshModels(p.provider)}
                    title="Fetch the provider's model list (network call)"
                  >
                    {row.modelsStatus === 'loading' ? (
                      <Loader2 className="spin" size={13} />
                    ) : (
                      <RefreshCw size={13} />
                    )}{' '}
                    Refresh models
                  </button>
                  <button
                    className="btn"
                    disabled={busy || !row.model.trim()}
                    onClick={() => testConnection(p.provider, row.model.trim())}
                    title="Send the fixed connection probe (network call)"
                  >
                    {row.testStatus === 'loading' ? (
                      <Loader2 className="spin" size={13} />
                    ) : (
                      <Plug size={13} />
                    )}{' '}
                    Test connection
                  </button>
                </td>
                <td>
                  {row.modelsStatus === 'error' && (
                    <span className="ai-err" title={statusTooltip(row.modelsError)}>
                      <CircleX size={13} /> models: {row.modelsError}
                    </span>
                  )}
                  {row.modelsStatus === 'ok' && row.models.length === 0 && (
                    <span className="ai-muted">no models reported</span>
                  )}
                  {row.testStatus === 'ok' && (
                    <span className="ai-ok" title={statusTooltip('ok')}>
                      <CircleCheck size={13} /> ok
                      {row.latency !== null ? ` · ${row.latency} ms` : ''}
                    </span>
                  )}
                  {row.testStatus === 'error' && (
                    <span className="ai-err" title={statusTooltip(row.testCode)}>
                      <CircleX size={13} /> {row.testCode}
                    </span>
                  )}
                </td>
              </tr>
            )
          })}
          {providers.length === 0 && (
            <tr>
              <td colSpan={6} className="empty">
                Loading provider metadata…
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

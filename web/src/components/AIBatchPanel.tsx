import { useEffect, useRef, useState } from 'react'
import { Loader2, Sparkles, X } from 'lucide-react'

import {
  AIPrivacyGate,
  cancelAIBatch,
  fetchAIBatch,
  fetchAIProviders,
  postAIBatch,
  postAIBatchPreview,
} from '../api'
import { parseProviders, type AIProviderInfo } from '../ai'
import {
  defaultLimitsFor,
  parseBatchPreview,
  parseBatchStatus,
  type AIBatchPreview,
  type AIBatchStatus,
} from '../aiBatch'

type PanelState = 'idle' | 'previewing' | 'confirm' | 'running' | 'done' | 'error'

// W3-D: batch AI review from the bulk selection. The review_ids snapshot is
// FROZEN when the preview opens — later filter/selection changes do not
// change a running batch. Results stay advisory.
export function AIBatchPanel({
  selectedIds,
  onOpenFinding,
  onBatchSettled,
}: {
  selectedIds: string[]
  onOpenFinding: (rid: string) => void
  onBatchSettled: () => void
}) {
  const [providers, setProviders] = useState<AIProviderInfo[]>([])
  const [provider, setProvider] = useState('ollama')
  const [model, setModel] = useState('')
  const [state, setState] = useState<PanelState>('idle')
  const [msg, setMsg] = useState('')
  const [preview, setPreview] = useState<AIBatchPreview | null>(null)
  const [status, setStatus] = useState<AIBatchStatus | null>(null)
  const frozenIds = useRef<string[]>([])
  const batchId = useRef('')
  const pollTimer = useRef<number | null>(null)

  useEffect(() => {
    let alive = true
    fetchAIProviders()
      .then((p) => {
        if (alive) setProviders(parseProviders(p))
      })
      .catch(() => {})
    return () => {
      alive = false
      if (pollTimer.current !== null) window.clearInterval(pollTimer.current)
    }
  }, [])

  const isRemote = (() => {
    const info = providers.find((p) => p.provider === provider)
    return info ? info.locality === 'remote' : provider !== 'ollama'
  })()

  const openPreview = async () => {
    if (!model.trim() || selectedIds.length === 0) return
    frozenIds.current = [...selectedIds] // snapshot — filters cannot change it
    setState('previewing')
    setMsg('')
    try {
      const raw = await postAIBatchPreview(frozenIds.current, provider, model.trim())
      const parsed = parseBatchPreview(raw)
      if (!parsed) throw new Error('unexpected preview shape')
      setPreview(parsed)
      setState('confirm')
    } catch (e) {
      setMsg(
        e instanceof AIPrivacyGate
          ? `Blocked by the privacy gate: ${e.message}`
          : String((e as Error)?.message ?? e),
      )
      setState('error')
    }
  }

  const poll = (id: string) => {
    pollTimer.current = window.setInterval(async () => {
      try {
        const st = parseBatchStatus(await fetchAIBatch(id))
        if (!st) return
        setStatus(st)
        if (st.state !== 'running' && st.state !== 'pending') {
          if (pollTimer.current !== null) window.clearInterval(pollTimer.current)
          pollTimer.current = null
          setState('done')
          onBatchSettled()
        }
      } catch {
        /* transient poll errors are ignored; the next tick retries */
      }
    }, 700)
  }

  const startBatch = async () => {
    if (!preview) return
    setState('running')
    setMsg('')
    try {
      const res = (await postAIBatch(
        preview.review_ids,
        provider,
        model.trim(),
        defaultLimitsFor(preview),
        preview.consent_token,
      )) as { batch_id?: string }
      if (!res.batch_id) throw new Error('the server did not return a batch id')
      batchId.current = res.batch_id
      poll(res.batch_id)
    } catch (e) {
      setMsg(
        e instanceof AIPrivacyGate
          ? `Blocked by the privacy gate: ${e.message}`
          : String((e as Error)?.message ?? e),
      )
      setState('error')
    }
  }

  const cancel = async () => {
    if (!batchId.current) return
    try {
      await cancelAIBatch(batchId.current)
    } catch {
      /* the poll loop reports the final state either way */
    }
  }

  const reset = () => {
    setState('idle')
    setPreview(null)
    setStatus(null)
    setMsg('')
  }

  return (
    <div className="ai-batch">
      <select
        className="review-select"
        value={provider}
        onChange={(e) => setProvider(e.target.value)}
        aria-label="Batch AI provider"
        disabled={state === 'running'}
      >
        {(providers.length
          ? providers
          : [{ provider: 'ollama', display: 'Ollama', configured: true, key_present: false, locality: 'local' as const }]
        ).map((p) => (
          <option key={p.provider} value={p.provider}>
            {p.display}
            {p.locality === 'remote' ? ' (consent required)' : ''}
          </option>
        ))}
      </select>
      <input
        className="review-select ai-model"
        placeholder="model id"
        value={model}
        onChange={(e) => setModel(e.target.value)}
        aria-label="Batch AI model"
        disabled={state === 'running'}
      />
      <button
        className="btn btn-primary"
        onClick={openPreview}
        disabled={!model.trim() || selectedIds.length === 0 || state === 'running' || state === 'previewing'}
        title="Preview, then AI-review every selected finding (one request per finding)"
      >
        {state === 'previewing' ? (
          <>
            <Loader2 className="spin" size={13} /> Preparing…
          </>
        ) : (
          <>
            <Sparkles size={13} /> AI Review selected ({selectedIds.length})
          </>
        )}
      </button>
      {msg && <span className="review-msg err">{msg}</span>}
      {state === 'error' && (
        <button className="btn" onClick={reset}>
          Dismiss
        </button>
      )}

      {state === 'confirm' && preview && (
        <div className="consent-overlay" role="dialog" aria-modal="true">
          <div className="consent-modal">
            <div className="ai-sub">
              Batch AI review — {preview.findings} finding(s)
              {isRemote ? ' → REMOTE provider' : ' (local)'}
            </div>
            <dl className="consent-facts">
              <div>
                <dt>Provider / model</dt>
                <dd>
                  {provider} · {model.trim()}
                </dd>
              </div>
              <div>
                <dt>Requests</dt>
                <dd>{preview.request_count} (one per finding, no pooling)</dd>
              </div>
              <div>
                <dt>Payload</dt>
                <dd>
                  {preview.input_bytes} bytes (~{preview.estimated_input_tokens} tokens in, ≤
                  {preview.max_output_tokens} tokens out)
                </dd>
              </div>
              <div>
                <dt>Cache</dt>
                <dd>
                  {preview.cached} cached · {preview.fresh} fresh · {preview.stale} stale
                </dd>
              </div>
              <div>
                <dt>Redactions</dt>
                <dd>{preview.redaction_total} value(s) masked before sending</dd>
              </div>
              <div>
                <dt>Cost</dt>
                <dd>
                  {preview.cost_status === 'estimated'
                    ? `~$${preview.estimated_cost_usd} (local pricing config)`
                    : 'unknown (no local pricing config)'}
                </dd>
              </div>
            </dl>
            <div className="review-actions">
              <button className="btn btn-primary" onClick={startBatch}>
                {isRemote ? 'Confirm send' : 'Start batch'}
              </button>
              <button className="btn" onClick={reset}>
                Cancel — send nothing
              </button>
            </div>
          </div>
        </div>
      )}

      {(state === 'running' || state === 'done') && status && (
        <div className="ai-batch-status">
          <span className={`ai-badge ai-${status.state === 'completed' ? 'good' : status.state === 'running' ? 'warn' : 'bad'}`}>
            {status.state}
          </span>
          <span className="ai-conf">
            {status.counts.completed ?? 0} done · {status.counts.failed ?? 0} failed ·{' '}
            {status.remaining} remaining
          </span>
          <span className="ai-conf">
            ✓{status.assessments.confirmed ?? 0} · FP {status.assessments.false_positive ?? 0} ·
            ? {status.assessments.uncertain ?? 0}
          </span>
          {state === 'running' && (
            <button className="btn" onClick={cancel}>
              <X size={12} /> Cancel
            </button>
          )}
          {state === 'done' && (
            <>
              {status.items
                .filter((i) => i.state === 'completed')
                .slice(0, 1)
                .map((i) => (
                  <button key={i.review_id} className="btn" onClick={() => onOpenFinding(i.review_id)}>
                    Open first result
                  </button>
                ))}
              <button className="btn" onClick={reset}>
                Close
              </button>
            </>
          )}
        </div>
      )}
    </div>
  )
}

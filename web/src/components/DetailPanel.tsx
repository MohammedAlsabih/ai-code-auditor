import { useEffect, useState } from 'react'
import { Loader2, Sparkles, X } from 'lucide-react'

import {
  AIPrivacyGate,
  SourceUnavailable,
  deleteReview,
  fetchAIProviders,
  fetchAIReview,
  fetchSource,
  levelColor,
  postAIConsentPreview,
  postAIModels,
  postAIReview,
  putReview,
  sourcePathFor,
  type AIConsentPreview,
} from '../api'
import { parseModelIds, parseProviders, type AIProviderInfo } from '../ai'
import {
  AI_ADVISORY_NOTICE,
  assessmentTone,
  parseAIReviewResult,
  pickStoredResult,
  type AIReviewResult,
} from '../aiReview'
import type { Finding, Review, SourceWindow } from '../types'

type SrcState = 'idle' | 'loading' | 'ok' | 'unavailable' | 'error'
type RevState = 'idle' | 'saving' | 'saved' | 'error'
type AIState = 'idle' | 'running' | 'completed' | 'error'

const STATUS_OPTIONS: Array<[string, string]> = [
  ['confirmed', 'Confirmed'],
  ['false_positive', 'False positive'],
  ['accepted_risk', 'Accepted risk'],
]

// Note: detail, snippet and source lines are rendered as PLAIN TEXT (React
// escapes children). dangerouslySetInnerHTML is intentionally never used here.
export function DetailPanel({
  finding,
  review,
  reviewsOk,
  reviewsError,
  onReviewChange,
  onClose,
}: {
  finding: Finding
  review: Review | undefined
  reviewsOk: boolean
  reviewsError: string
  onReviewChange: (rid: string, review: Review | null) => void
  onClose: () => void
}) {
  const [src, setSrc] = useState<SourceWindow | null>(null)
  const [srcState, setSrcState] = useState<SrcState>('idle')
  const [srcMsg, setSrcMsg] = useState('')
  const [status, setStatus] = useState(review?.status ?? '')
  const [note, setNote] = useState(review?.note ?? '')
  const [revState, setRevState] = useState<RevState>('idle')
  const [revMsg, setRevMsg] = useState('')
  const [aiProviders, setAIProviders] = useState<AIProviderInfo[]>([])
  const [aiProvider, setAIProvider] = useState('ollama')
  const [aiModel, setAIModel] = useState('')
  const [aiModels, setAIModels] = useState<string[]>([])
  const [aiState, setAIState] = useState<AIState>('idle')
  const [aiMsg, setAIMsg] = useState('')
  const [aiResult, setAIResult] = useState<AIReviewResult | null>(null)
  const [aiConsent, setAIConsent] = useState<AIConsentPreview | null>(null)

  useEffect(() => {
    // re-seed the form whenever another finding (or its saved review) arrives
    setStatus(review?.status ?? '')
    setNote(review?.note ?? '')
    setRevState('idle')
    setRevMsg('')
  }, [finding, review])

  const saveReview = async () => {
    if (!finding.review_id || !status) return
    setRevState('saving')
    try {
      const saved = await putReview(finding.review_id, status, note)
      onReviewChange(finding.review_id, saved)
      setRevState('saved')
    } catch (e) {
      setRevMsg(String((e as Error)?.message ?? e))
      setRevState('error')
    }
  }

  const clearReview = async () => {
    if (!finding.review_id) return
    setRevState('saving')
    try {
      await deleteReview(finding.review_id)
      onReviewChange(finding.review_id, null)
      setStatus('')
      setNote('')
      setRevState('idle')
    } catch (e) {
      setRevMsg(String((e as Error)?.message ?? e))
      setRevState('error')
    }
  }

  useEffect(() => {
    setSrc(null)
    setSrcMsg('')
    // project-level findings (line 0) or findings with no file have no source
    if (!finding.file || finding.line <= 0) {
      setSrcState('idle')
      return
    }
    const ctl = new AbortController()
    setSrcState('loading')
    fetchSource(sourcePathFor(finding), finding.line, ctl.signal)
      .then((w) => {
        setSrc(w)
        setSrcState('ok')
      })
      .catch((e) => {
        if (ctl.signal.aborted) return
        setSrcMsg(String(e?.message ?? e))
        setSrcState(e instanceof SourceUnavailable ? 'unavailable' : 'error')
      })
    return () => ctl.abort()
  }, [finding])

  // providers list = LOCAL server metadata (no outbound call on open)
  useEffect(() => {
    let alive = true
    fetchAIProviders()
      .then((p) => {
        if (alive) setAIProviders(parseProviders(p))
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  // cached AI result for this finding (local sidecar read, no provider call)
  useEffect(() => {
    setAIResult(null)
    setAIState('idle')
    setAIMsg('')
    if (!finding.review_id) return
    let alive = true
    fetchAIReview(finding.review_id)
      .then((payload) => {
        if (!alive) return
        const stored = pickStoredResult(payload)
        if (stored) {
          setAIResult(stored)
          setAIState('completed')
        }
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [finding])

  const loadAIModels = async () => {
    setAIMsg('')
    try {
      setAIModels(parseModelIds(await postAIModels(aiProvider)))
    } catch (e) {
      setAIMsg(String((e as Error)?.message ?? e))
    }
  }

  const executeAIReview = async (consentToken: string) => {
    if (!finding.review_id) return
    setAIState('running')
    setAIMsg('')
    try {
      const raw = await postAIReview(finding.review_id, aiProvider, aiModel.trim(), consentToken)
      const parsed = parseAIReviewResult(raw)
      if (!parsed) throw new Error('the server returned an unexpected result shape')
      setAIResult(parsed)
      setAIState('completed')
    } catch (e) {
      setAIMsg(
        e instanceof AIPrivacyGate
          ? `Blocked by the privacy gate: ${e.message}`
          : String((e as Error)?.message ?? e),
      )
      setAIState('error')
    }
  }

  const runAIReview = async () => {
    if (!finding.review_id || !aiModel.trim() || aiState === 'running') return
    const info = aiProviders.find((p) => p.provider === aiProvider)
    const isRemote = info ? info.locality === 'remote' : aiProvider !== 'ollama'
    if (!isRemote) {
      void executeAIReview('')
      return
    }
    // remote: the user must approve the EXACT payload first — the modal
    // shows what would be sent; Cancel means zero network to the provider.
    setAIMsg('')
    try {
      const preview = await postAIConsentPreview([finding.review_id], aiProvider, aiModel.trim())
      setAIConsent(preview)
    } catch (e) {
      setAIMsg(
        e instanceof AIPrivacyGate
          ? `Blocked by the privacy gate: ${e.message}`
          : String((e as Error)?.message ?? e),
      )
      setAIState('error')
    }
  }

  const confirmConsent = () => {
    if (!aiConsent) return
    const token = aiConsent.consent_token
    setAIConsent(null)
    void executeAIReview(token)
  }

  const showSnippet = srcState !== 'ok' && Boolean(finding.snippet)

  return (
    <section className="detail">
      <div className="detail-head">
        <span className={`sev sev-${levelColor(finding.level)}`}>
          {finding.level || finding.severity || 'unclassified'}
        </span>
        <span className="mono">{finding.rule_id}</span>
        <button className="close" onClick={onClose} title="Close details">
          <X size={16} />
        </button>
      </div>
      <h2 className="detail-title">{finding.title}</h2>
      <dl className="detail-meta">
        <div>
          <dt>File</dt>
          <dd className="mono">
            {finding.file}:{finding.line}
          </dd>
        </div>
        <div>
          <dt>Project</dt>
          <dd className="mono">{finding.project || '(root)'}</dd>
        </div>
        <div>
          <dt>Language</dt>
          <dd>{finding.language}</dd>
        </div>
        <div>
          <dt>Precision</dt>
          <dd>{finding.precision}</dd>
        </div>
      </dl>
      {finding.detail && (
        <>
          <div className="detail-label">Detail</div>
          <p className="detail-body">{finding.detail}</p>
        </>
      )}
      {srcState !== 'idle' && (
        <>
          <div className="detail-label">
            Source{src ? ` (lines ${src.start_line}–${src.end_line} of ${src.total_lines})` : ''}
          </div>
          {srcState === 'loading' && (
            <div className="src-note">
              <Loader2 className="spin" size={13} /> Loading source…
            </div>
          )}
          {srcState === 'unavailable' && (
            <div className="src-note">Source unavailable — start the server with --repo.</div>
          )}
          {srcState === 'error' && <div className="src-note">Could not load source: {srcMsg}</div>}
          {srcState === 'ok' && src && (
            <div className="src-window">
              {src.lines.map((l) => (
                <div
                  key={l.number}
                  className={`src-line ${l.number === src.requested_line ? 'hit' : ''}`}
                >
                  <span className="src-num">{l.number}</span>
                  <span className="src-text">{l.text || ' '}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {showSnippet && (
        <>
          <div className="detail-label">Snippet</div>
          <pre className="snippet">{finding.snippet}</pre>
        </>
      )}
      {finding.review_id && (
        <>
          <div className="detail-label">Review</div>
          {!reviewsOk ? (
            <div className="src-note">
              Reviews unavailable{reviewsError ? `: ${reviewsError}` : ''}
            </div>
          ) : (
            <div className="review-box">
              <select
                className="review-select"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
              >
                <option value="">— set status —</option>
                {STATUS_OPTIONS.map(([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ))}
              </select>
              <textarea
                className="review-note"
                placeholder="Optional note (max 2000 chars)"
                maxLength={2000}
                rows={3}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
              <div className="review-actions">
                <button
                  className="btn btn-primary"
                  onClick={saveReview}
                  disabled={!status || revState === 'saving'}
                >
                  {revState === 'saving' ? 'Saving…' : 'Save'}
                </button>
                <button
                  className="btn"
                  onClick={clearReview}
                  disabled={revState === 'saving' || (!review && !status)}
                >
                  Clear
                </button>
                {revState === 'saved' && <span className="review-msg ok">Saved.</span>}
                {revState === 'error' && (
                  <span className="review-msg err">Save failed: {revMsg}</span>
                )}
              </div>
              {review && (
                <div className="review-meta">
                  saved: {review.status} · {review.updated_at}
                </div>
              )}
            </div>
          )}
          <div className="detail-label">AI Review</div>
          <div className="ai-box">
            <div className="ai-notice">{AI_ADVISORY_NOTICE}</div>
            <div className="ai-controls">
              <select
                className="review-select"
                value={aiProvider}
                onChange={(e) => {
                  setAIProvider(e.target.value)
                  setAIModels([])
                }}
                aria-label="AI provider"
              >
                {(aiProviders.length
                  ? aiProviders
                  : [{ provider: 'ollama', display: 'Ollama', configured: true, key_present: false, locality: 'local' as const }]
                ).map((p) => (
                  <option key={p.provider} value={p.provider}>
                    {p.display}
                    {p.locality === 'remote' ? ' (blocked until the privacy gate)' : ''}
                  </option>
                ))}
              </select>
              <input
                className="review-select ai-model"
                list="ai-model-options"
                placeholder="model id"
                value={aiModel}
                onChange={(e) => setAIModel(e.target.value)}
                aria-label="AI model"
              />
              <datalist id="ai-model-options">
                {aiModels.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
              <button className="btn" onClick={loadAIModels} disabled={aiState === 'running'}>
                Load models
              </button>
              <button
                className="btn btn-primary"
                onClick={runAIReview}
                disabled={!aiModel.trim() || aiState === 'running'}
                title="Run the fixed AI review for this finding"
              >
                {aiState === 'running' ? (
                  <>
                    <Loader2 className="spin" size={13} /> Reviewing…
                  </>
                ) : (
                  <>
                    <Sparkles size={13} /> AI Review
                  </>
                )}
              </button>
            </div>
            {aiState === 'error' && <div className="review-msg err">{aiMsg}</div>}
            {aiMsg && aiState !== 'error' && <div className="review-msg err">{aiMsg}</div>}
            {aiConsent && (
              <div className="consent-overlay" role="dialog" aria-modal="true">
                <div className="consent-modal">
                  <div className="ai-sub">Send to a remote provider?</div>
                  <dl className="consent-facts">
                    <div>
                      <dt>Provider / model</dt>
                      <dd>
                        {aiConsent.provider} · {aiConsent.model} ({aiConsent.locality})
                      </dd>
                    </div>
                    <div>
                      <dt>Findings / files</dt>
                      <dd>
                        {aiConsent.findings} finding(s), {aiConsent.files} file excerpt(s)
                      </dd>
                    </div>
                    <div>
                      <dt>Payload</dt>
                      <dd>
                        {aiConsent.input_bytes} bytes (~{aiConsent.estimated_input_tokens} tokens,
                        conservative)
                      </dd>
                    </div>
                    <div>
                      <dt>Redactions applied</dt>
                      <dd>{aiConsent.redaction_total} value(s) masked before sending</dd>
                    </div>
                    <div>
                      <dt>Retention / cost</dt>
                      <dd>
                        {aiConsent.retention} / {aiConsent.cost}
                      </dd>
                    </div>
                  </dl>
                  <div className="review-actions">
                    <button className="btn btn-primary" onClick={confirmConsent}>
                      Confirm send
                    </button>
                    <button className="btn" onClick={() => setAIConsent(null)}>
                      Cancel — send nothing
                    </button>
                  </div>
                </div>
              </div>
            )}
            {aiState === 'completed' && aiResult && (
              <div className="ai-result">
                {aiResult.stale && (
                  <div className="ai-stale">
                    Stale: the finding&apos;s context changed since this review — re-run for a
                    fresh assessment.
                  </div>
                )}
                <div className="ai-verdict">
                  <span className={`ai-badge ai-${assessmentTone(aiResult.assessment)}`}>
                    {aiResult.assessment}
                  </span>
                  <span className="ai-conf">confidence: {aiResult.confidence}</span>
                  <span className="ai-conf">action: {aiResult.suggested_action}</span>
                </div>
                <p className="detail-body">{aiResult.summary}</p>
                {aiResult.evidence.length > 0 && (
                  <ul className="ai-evidence">
                    {aiResult.evidence.map((e, i) => (
                      <li key={i}>
                        <span className="ai-chip mono">{e.context_id}</span> {e.statement}
                      </li>
                    ))}
                  </ul>
                )}
                {aiResult.missing_context.length > 0 && (
                  <>
                    <div className="ai-sub">Missing context</div>
                    <ul className="ai-evidence">
                      {aiResult.missing_context.map((m, i) => (
                        <li key={i}>{m}</li>
                      ))}
                    </ul>
                  </>
                )}
                <div className="review-meta">
                  {aiResult.provider} · {aiResult.model} · {aiResult.prompt_version} ·{' '}
                  {aiResult.latency_ms} ms · {aiResult.created_at}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  )
}

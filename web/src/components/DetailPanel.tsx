import { useEffect, useState } from 'react'
import { Loader2, X } from 'lucide-react'

import { SourceUnavailable, deleteReview, fetchSource, putReview, sourcePathFor } from '../api'
import type { Finding, Review, SourceWindow } from '../types'

type SrcState = 'idle' | 'loading' | 'ok' | 'unavailable' | 'error'
type RevState = 'idle' | 'saving' | 'saved' | 'error'

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

  const showSnippet = srcState !== 'ok' && Boolean(finding.snippet)

  return (
    <section className="detail">
      <div className="detail-head">
        <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
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
        </>
      )}
    </section>
  )
}

import { useEffect, useState } from 'react'
import { Loader2, X } from 'lucide-react'

import { SourceUnavailable, fetchSource, sourcePathFor } from '../api'
import type { Finding, SourceWindow } from '../types'

type SrcState = 'idle' | 'loading' | 'ok' | 'unavailable' | 'error'

// Note: detail, snippet and source lines are rendered as PLAIN TEXT (React
// escapes children). dangerouslySetInnerHTML is intentionally never used here.
export function DetailPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const [src, setSrc] = useState<SourceWindow | null>(null)
  const [srcState, setSrcState] = useState<SrcState>('idle')
  const [srcMsg, setSrcMsg] = useState('')

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
    </section>
  )
}

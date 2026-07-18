import { X } from 'lucide-react'

import type { Finding } from '../types'

// Note: detail + snippet are rendered as PLAIN TEXT (React escapes children).
// dangerouslySetInnerHTML is intentionally never used here.
export function DetailPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
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
      {finding.snippet && (
        <>
          <div className="detail-label">Snippet</div>
          <pre className="snippet">{finding.snippet}</pre>
        </>
      )}
    </section>
  )
}

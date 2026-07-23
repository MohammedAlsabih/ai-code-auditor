import { useEffect, useRef, useState } from 'react'
import { Loader2, ShieldQuestion, Sparkles, X } from 'lucide-react'

import {
  AIPrivacyGate,
  cancelAIAudit,
  fetchAIAudit,
  fetchAIAuditResults,
  fetchAIProviders,
  postAIAudit,
  postAIAuditPreview,
  putAICandidateReview,
} from '../api'
import { parseProviders, type AIProviderInfo } from '../ai'
import {
  AUDIT_ABSENCE_NOTE,
  AUDIT_ADVISORY_BADGE,
  AUDIT_PROFILES,
  CANDIDATE_DECISIONS,
  parseAuditCandidates,
  parseAuditPreview,
  parseAuditStatus,
  type AIAuditCandidate,
  type AIAuditPreview,
  type AIAuditStatus,
  type AuditProfile,
} from '../aiAudit'

type PanelState = 'idle' | 'previewing' | 'confirm' | 'running' | 'done' | 'error'

// W3-E2: the Independent AI Audit tab. No prompt box exists anywhere: the
// user picks a profile, projects, provider/model and limits; the versioned
// query catalog and the deterministic index do the rest. Every result is an
// ADVISORY candidate — findings, scoring and the verdict never change.
export function AIAuditPanel({ projects }: { projects: string[] }) {
  const [providers, setProviders] = useState<AIProviderInfo[]>([])
  const [provider, setProvider] = useState('ollama')
  const [model, setModel] = useState('')
  const [profile, setProfile] = useState<AuditProfile>('security')
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [state, setState] = useState<PanelState>('idle')
  const [msg, setMsg] = useState('')
  const [preview, setPreview] = useState<AIAuditPreview | null>(null)
  const [status, setStatus] = useState<AIAuditStatus | null>(null)
  const [candidates, setCandidates] = useState<AIAuditCandidate[]>([])
  const [selected, setSelected] = useState<AIAuditCandidate | null>(null)
  const [note, setNote] = useState('')
  const auditId = useRef('')
  const pollTimer = useRef<number | null>(null)

  const refreshCandidates = () => {
    fetchAIAuditResults()
      .then((raw) => setCandidates(parseAuditCandidates(raw)))
      .catch(() => {})
  }

  useEffect(() => {
    let alive = true
    fetchAIProviders()
      .then((p) => {
        if (alive) setProviders(parseProviders(p))
      })
      .catch(() => {})
    refreshCandidates()
    return () => {
      alive = false
      if (pollTimer.current !== null) window.clearInterval(pollTimer.current)
    }
  }, [])

  const isRemote = (() => {
    const info = providers.find((p) => p.provider === provider)
    return info ? info.locality === 'remote' : provider !== 'ollama'
  })()

  const toggleProject = (p: string) => {
    setPicked((prev) => {
      const next = new Set(prev)
      if (next.has(p)) next.delete(p)
      else next.add(p)
      return next
    })
  }

  const openPreview = async () => {
    if (!model.trim()) return
    setState('previewing')
    setMsg('')
    try {
      const raw = await postAIAuditPreview(profile, provider, model.trim(), [...picked])
      const parsed = parseAuditPreview(raw)
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
        const st = parseAuditStatus(await fetchAIAudit(id))
        if (!st) return
        setStatus(st)
        if (st.state !== 'running' && st.state !== 'pending') {
          if (pollTimer.current !== null) window.clearInterval(pollTimer.current)
          pollTimer.current = null
          setState('done')
          refreshCandidates()
        }
      } catch {
        /* transient poll errors: the next tick retries */
      }
    }, 700)
  }

  const startAudit = async () => {
    if (!preview) return
    setState('running')
    setMsg('')
    try {
      const res = (await postAIAudit(
        profile,
        provider,
        model.trim(),
        [...picked],
        {
          max_requests: preview.request_count,
          max_output_tokens: preview.max_output_tokens,
          max_input_bytes: Math.max(preview.input_bytes, 1),
        },
        preview.consent_token,
      )) as { audit_id?: string }
      if (!res.audit_id) throw new Error('the server did not return an audit id')
      auditId.current = res.audit_id
      poll(res.audit_id)
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
    if (!auditId.current) return
    try {
      await cancelAIAudit(auditId.current)
    } catch {
      /* the poll loop reports the final state */
    }
  }

  const classify = async (decision: string) => {
    if (!selected) return
    try {
      await putAICandidateReview(selected.candidate_id, decision, note)
      refreshCandidates()
      setSelected(null)
      setNote('')
    } catch (e) {
      setMsg(String((e as Error)?.message ?? e))
    }
  }

  return (
    <div className="audit-panel">
      <div className="ai-notice">
        Independent AI audit: predefined review queries only — you never write a prompt.{' '}
        {AUDIT_ABSENCE_NOTE}
      </div>
      <div className="ai-controls">
        <select
          className="review-select"
          value={profile}
          onChange={(e) => setProfile(e.target.value as AuditProfile)}
          aria-label="Audit profile"
          disabled={state === 'running'}
        >
          {AUDIT_PROFILES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select
          className="review-select"
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          aria-label="Audit provider"
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
          aria-label="Audit model"
          disabled={state === 'running'}
        />
        <button
          className="btn btn-primary"
          onClick={openPreview}
          disabled={!model.trim() || state === 'running' || state === 'previewing'}
        >
          {state === 'previewing' ? (
            <>
              <Loader2 className="spin" size={13} /> Preparing…
            </>
          ) : (
            <>
              <ShieldQuestion size={13} /> Preview AI audit
            </>
          )}
        </button>
        {state === 'error' && (
          <button className="btn" onClick={() => setState('idle')}>
            Dismiss
          </button>
        )}
      </div>
      <div className="audit-projects">
        <span className="ai-conf">Projects ({picked.size === 0 ? 'all' : picked.size}):</span>
        {projects.map((p) => (
          <label key={p} className="audit-project">
            <input
              type="checkbox"
              checked={picked.has(p)}
              onChange={() => toggleProject(p)}
              disabled={state === 'running'}
            />
            <span className="mono">{p || '(root)'}</span>
          </label>
        ))}
      </div>
      {msg && <div className="review-msg err">{msg}</div>}

      {state === 'confirm' && preview && (
        <div className="consent-overlay" role="dialog" aria-modal="true">
          <div className="consent-modal">
            <div className="ai-sub">
              AI audit — {preview.units} unit(s){isRemote ? ' → REMOTE provider' : ' (local)'}
            </div>
            <dl className="consent-facts">
              <div>
                <dt>Queries / projects</dt>
                <dd>
                  {preview.queries.join(', ') || '—'} · {preview.projects.length} project(s)
                </dd>
              </div>
              <div>
                <dt>Requests</dt>
                <dd>{preview.request_count} (one per unit, no pooling)</dd>
              </div>
              <div>
                <dt>Payload</dt>
                <dd>
                  {preview.files} file excerpt(s), {preview.input_bytes} bytes (~
                  {preview.estimated_input_tokens} tokens in, ≤{preview.max_output_tokens} out)
                </dd>
              </div>
              <div>
                <dt>Runtime</dt>
                <dd>
                  concurrency {preview.concurrency} · timeout {preview.request_timeout_seconds}s ·{' '}
                  {preview.cached} cached / {preview.fresh} fresh
                </dd>
              </div>
              <div>
                <dt>Redactions</dt>
                <dd>{preview.redaction_total} value(s) masked before sending</dd>
              </div>
              <div>
                <dt>Retention / cost</dt>
                <dd>
                  {preview.retention} /{' '}
                  {preview.cost_status === 'estimated'
                    ? `~$${preview.estimated_cost_usd}`
                    : 'unknown'}
                </dd>
              </div>
            </dl>
            <div className="review-actions">
              <button className="btn btn-primary" onClick={startAudit}>
                {isRemote ? 'Confirm send' : 'Start audit'}
              </button>
              <button className="btn" onClick={() => setState('idle')}>
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
            issues {status.outcomes.issues_found ?? 0} · none-observed{' '}
            {status.outcomes.no_issue_observed ?? 0} · insufficient{' '}
            {status.outcomes.insufficient_context ?? 0}
          </span>
          {state === 'running' && (
            <button className="btn" onClick={cancel}>
              <X size={12} /> Cancel
            </button>
          )}
        </div>
      )}

      <div className="detail-label">
        AI candidates ({candidates.length}) — <Sparkles size={11} /> {AUDIT_ADVISORY_BADGE}
      </div>
      {candidates.length === 0 ? (
        <div className="src-note">No candidates stored. {AUDIT_ABSENCE_NOTE}</div>
      ) : (
        <div className="audit-grid">
          <table className="findings audit-table">
            <thead>
              <tr>
                <th>Query</th>
                <th>Project</th>
                <th>File:Line</th>
                <th>Title</th>
                <th>Conf.</th>
                <th>Review</th>
              </tr>
            </thead>
            <tbody>
              {candidates.map((c) => (
                <tr
                  key={c.candidate_id}
                  className={selected?.candidate_id === c.candidate_id ? 'selected' : ''}
                  onClick={() => {
                    setSelected(c)
                    setNote(c.review?.note ?? '')
                  }}
                >
                  <td className="mono">{c.query_id}</td>
                  <td className="mono ellip">{c.project}</td>
                  <td className="mono ellip">
                    {c.file}:{c.line}
                  </td>
                  <td className="ellip">{c.title}</td>
                  <td>{c.confidence}</td>
                  <td>{c.review?.decision ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {selected && (
            <div className="audit-detail">
              <div className="ai-verdict">
                <span className="ai-badge ai-warn">{AUDIT_ADVISORY_BADGE}</span>
              </div>
              <h3 className="detail-title">{selected.title}</h3>
              <div className="ai-conf">
                {selected.query_id} · {selected.category} · confidence {selected.confidence} ·
                action {selected.suggested_action}
              </div>
              <p className="detail-body">{selected.summary}</p>
              <div className="detail-label">Evidence</div>
              <ul className="ai-evidence">
                {selected.evidence.map((e, i) => (
                  <li key={i}>
                    <span className="ai-chip mono">
                      {e.file}:{e.line_start}-{e.line_end}
                    </span>{' '}
                    {e.statement}
                  </li>
                ))}
              </ul>
              {selected.missing_context.length > 0 && (
                <>
                  <div className="detail-label">Missing context</div>
                  <ul className="ai-evidence">
                    {selected.missing_context.map((m, i) => (
                      <li key={i}>{m}</li>
                    ))}
                  </ul>
                </>
              )}
              {selected.related_static_findings.length > 0 && (
                <div className="ai-conf">
                  Linked static findings: {selected.related_static_findings.length} (same
                  file/line — links only, nothing merged)
                </div>
              )}
              <div className="detail-label">Your review (does not change the report)</div>
              <textarea
                className="review-note"
                rows={2}
                maxLength={2000}
                placeholder="Optional note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
              <div className="review-actions">
                {CANDIDATE_DECISIONS.map((d) => (
                  <button key={d} className="btn" onClick={() => classify(d)}>
                    {d.replace('_', ' ')}
                  </button>
                ))}
                <button className="btn" onClick={() => setSelected(null)}>
                  Close
                </button>
              </div>
              {selected.review && (
                <div className="review-meta">
                  saved: {selected.review.decision} · {selected.review.updated_at}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

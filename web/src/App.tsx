import { useEffect, useMemo, useState } from 'react'
import { Loader2, TriangleAlert } from 'lucide-react'

import { aggregate, fetchReport, fetchReviews } from './api'
import { DetailPanel } from './components/DetailPanel'
import { FindingsTable } from './components/FindingsTable'
import { Sidebar } from './components/Sidebar'
import { TopBar } from './components/TopBar'
import type { Finding, Report, Review } from './types'

export default function App() {
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [project, setProject] = useState<string | null>(null)
  const [language, setLanguage] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [selected, setSelected] = useState<Finding | null>(null)
  const [reviews, setReviews] = useState<Record<string, Review>>({})
  const [reviewsOk, setReviewsOk] = useState(true)
  const [reviewsError, setReviewsError] = useState('')
  const [reviewFilter, setReviewFilter] = useState<string | null>(null)

  useEffect(() => {
    fetchReport().then(setReport).catch((e) => setError(String(e?.message ?? e)))
    fetchReviews()
      .then((r) => {
        setReviews(r.reviews)
        setReviewsOk(r.available)
        setReviewsError(r.error ?? '')
      })
      .catch((e) => {
        setReviewsOk(false)
        setReviewsError(String(e?.message ?? e))
      })
  }, [])

  const allRows = useMemo(() => (report ? aggregate(report) : []), [report])
  const projects = useMemo(
    () => Array.from(new Set(allRows.map((r) => r.project))).sort(),
    [allRows],
  )
  const languages = useMemo(
    () => Array.from(new Set(allRows.map((r) => r.language).filter(Boolean))).sort(),
    [allRows],
  )
  const rows = useMemo(
    () =>
      allRows.filter((r) => {
        if (project && r.project !== project) return false
        if (language && r.language !== language) return false
        if (severity && r.severity !== severity) return false
        if (reviewFilter) {
          const rv = r.review_id ? reviews[r.review_id] : undefined
          if (reviewFilter === 'unreviewed' ? Boolean(rv) : rv?.status !== reviewFilter)
            return false
        }
        return true
      }),
    [allRows, project, language, severity, reviewFilter, reviews],
  )

  const onReviewChange = (rid: string, review: Review | null) => {
    setReviews((prev) => {
      const next = { ...prev }
      if (review === null) delete next[rid]
      else next[rid] = review
      return next
    })
  }

  if (error) {
    return (
      <div className="fatal">
        <TriangleAlert size={18} />
        <span>Could not load report: {error}</span>
      </div>
    )
  }
  if (!report) {
    return (
      <div className="loading">
        <Loader2 className="spin" size={18} /> Loading report…
      </div>
    )
  }

  return (
    <div className="app">
      <TopBar
        summary={report.summary}
        target={report.target}
        total={allRows.length}
        shown={rows.length}
        activeSeverity={severity}
        onSeverity={setSeverity}
      />
      <div className="body">
        <Sidebar
          projects={projects}
          languages={languages}
          activeProject={project}
          activeLanguage={language}
          onProject={setProject}
          onLanguage={setLanguage}
          reviewFilter={reviewFilter}
          onReviewFilter={setReviewFilter}
        />
        <main className="main">
          <FindingsTable
            rows={rows}
            reviews={reviews}
            selected={selected}
            onSelect={setSelected}
          />
        </main>
        {selected && (
          <DetailPanel
            finding={selected}
            review={selected.review_id ? reviews[selected.review_id] : undefined}
            reviewsOk={reviewsOk}
            reviewsError={reviewsError}
            onReviewChange={onReviewChange}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  )
}

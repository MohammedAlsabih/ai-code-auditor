import { useEffect, useMemo, useState } from 'react'
import { Loader2, TriangleAlert } from 'lucide-react'

import { aggregate, fetchReport } from './api'
import { DetailPanel } from './components/DetailPanel'
import { FindingsTable } from './components/FindingsTable'
import { Sidebar } from './components/Sidebar'
import { TopBar } from './components/TopBar'
import type { Finding, Report } from './types'

export default function App() {
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [project, setProject] = useState<string | null>(null)
  const [language, setLanguage] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [selected, setSelected] = useState<Finding | null>(null)

  useEffect(() => {
    fetchReport().then(setReport).catch((e) => setError(String(e?.message ?? e)))
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
      allRows.filter(
        (r) =>
          (!project || r.project === project) &&
          (!language || r.language === language) &&
          (!severity || r.severity === severity),
      ),
    [allRows, project, language, severity],
  )

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
        />
        <main className="main">
          <FindingsTable rows={rows} selected={selected} onSelect={setSelected} />
        </main>
        {selected && <DetailPanel finding={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  )
}

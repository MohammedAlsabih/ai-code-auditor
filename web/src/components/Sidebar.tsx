const REVIEW_FILTERS: Array<[string | null, string]> = [
  [null, 'All'],
  ['unreviewed', 'Unreviewed'],
  ['confirmed', 'Confirmed'],
  ['false_positive', 'False positive'],
  ['accepted_risk', 'Accepted risk'],
]

export function Sidebar({
  projects,
  languages,
  activeProject,
  activeLanguage,
  onProject,
  onLanguage,
  reviewFilter,
  onReviewFilter,
}: {
  projects: string[]
  languages: string[]
  activeProject: string | null
  activeLanguage: string | null
  onProject: (p: string | null) => void
  onLanguage: (l: string | null) => void
  reviewFilter: string | null
  onReviewFilter: (f: string | null) => void
}) {
  const item = (label: string, active: boolean, onClick: () => void) => (
    <button
      key={label}
      className={`side-item ${active ? 'active' : ''}`}
      onClick={onClick}
      title={label}
    >
      {label}
    </button>
  )

  return (
    <aside className="sidebar">
      <div className="side-group">
        <div className="side-head">Projects</div>
        {item('All projects', !activeProject, () => onProject(null))}
        {projects.map((p) =>
          item(p || '(root)', activeProject === p, () =>
            onProject(activeProject === p ? null : p),
          ),
        )}
      </div>
      <div className="side-group">
        <div className="side-head">Languages</div>
        {item('All languages', !activeLanguage, () => onLanguage(null))}
        {languages.map((l) =>
          item(l, activeLanguage === l, () => onLanguage(activeLanguage === l ? null : l)),
        )}
      </div>
      <div className="side-group">
        <div className="side-head">Review</div>
        {REVIEW_FILTERS.map(([value, label]) =>
          item(label, reviewFilter === value, () => onReviewFilter(value)),
        )}
      </div>
    </aside>
  )
}

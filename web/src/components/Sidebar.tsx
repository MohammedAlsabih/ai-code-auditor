const REVIEW_FILTERS: Array<[string, string]> = [
  ['unreviewed', 'Unreviewed'],
  ['confirmed', 'Confirmed'],
  ['false_positive', 'False positive'],
  ['accepted_risk', 'Accepted risk'],
]

// Multi-select facets: OR inside each group, AND across groups (applied in
// App's filter pipeline). "All …" clears the group's set.
export function Sidebar({
  projects,
  languages,
  projectF,
  languageF,
  reviewF,
  onToggleProject,
  onToggleLanguage,
  onToggleReview,
  onClearProjects,
  onClearLanguages,
  onClearReviews,
}: {
  projects: string[]
  languages: string[]
  projectF: Set<string>
  languageF: Set<string>
  reviewF: Set<string>
  onToggleProject: (p: string) => void
  onToggleLanguage: (l: string) => void
  onToggleReview: (s: string) => void
  onClearProjects: () => void
  onClearLanguages: () => void
  onClearReviews: () => void
}) {
  const item = (label: string, active: boolean, onClick: () => void, key?: string) => (
    <button
      key={key ?? label}
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
        {item('All projects', projectF.size === 0, onClearProjects)}
        {projects.map((p) =>
          item(p || '(root)', projectF.has(p), () => onToggleProject(p), `p:${p}`),
        )}
      </div>
      <div className="side-group">
        <div className="side-head">Languages</div>
        {item('All languages', languageF.size === 0, onClearLanguages)}
        {languages.map((l) => item(l, languageF.has(l), () => onToggleLanguage(l), `l:${l}`))}
      </div>
      <div className="side-group">
        <div className="side-head">Review</div>
        {item('All', reviewF.size === 0, onClearReviews)}
        {REVIEW_FILTERS.map(([value, label]) =>
          item(label, reviewF.has(value), () => onToggleReview(value), `r:${value}`),
        )}
      </div>
    </aside>
  )
}

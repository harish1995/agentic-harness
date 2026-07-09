import type { Finding } from './ReportView'

interface CategorySummaryProps {
  findings: Finding[]
  groupBy: 'owasp' | 'stride'
}

interface CategoryRow {
  category: string
  count: number
  /** DOM id of the first matching real finding, for scroll-anchoring. */
  targetId: string | null
}

function buildRows(findings: Finding[], groupBy: 'owasp' | 'stride'): CategoryRow[] {
  const key = groupBy === 'owasp' ? 'owasp_category' : 'stride_category'
  const counts = new Map<string, { count: number; targetId: string | null }>()

  findings.forEach((f, idx) => {
    if (f.no_evidence_marker) return
    const category = f[key]
    if (!category) return
    const existing = counts.get(category)
    if (existing) {
      existing.count += 1
    } else {
      counts.set(category, { count: 1, targetId: `finding-${idx}` })
    }
  })

  return Array.from(counts.entries())
    .map(([category, { count, targetId }]) => ({ category, count, targetId }))
    .sort((a, b) => b.count - a.count)
}

/**
 * Real table of category -> finding count (OWASP Top 10 or STRIDE), spec/ui.md
 * -> Screen: Report -> "OWASP Top 10 Summary" / "STRIDE Summary". Clicking a
 * row scroll-anchors to that category's first finding.
 */
export function CategorySummary({ findings, groupBy }: CategorySummaryProps) {
  const rows = buildRows(findings, groupBy)

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-blue-100 bg-blue-50 p-4 text-sm text-blue-800">
        No {groupBy === 'owasp' ? 'OWASP-categorized' : 'STRIDE-categorized'} findings for this scan.
      </div>
    )
  }

  function handleActivate(targetId: string | null) {
    if (!targetId) return
    document.getElementById(targetId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
      <table className="w-full text-sm">
        <thead className="border-b border-gray-200 bg-gray-50 text-left text-xs font-semibold text-gray-500 uppercase">
          <tr>
            <th className="px-4 py-2">{groupBy === 'owasp' ? 'OWASP Category' : 'STRIDE Category'}</th>
            <th className="px-4 py-2">Findings</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(row => (
            <tr
              key={row.category}
              role="button"
              tabIndex={0}
              onClick={() => handleActivate(row.targetId)}
              onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  handleActivate(row.targetId)
                }
              }}
              className="cursor-pointer border-b border-gray-100 last:border-0 hover:bg-gray-50 focus:bg-gray-50 focus:outline-none"
            >
              <td className="px-4 py-2.5 text-gray-800">{row.category}</td>
              <td className="px-4 py-2.5 font-medium text-gray-800">{row.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

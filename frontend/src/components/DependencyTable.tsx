import type { DependencyInfo, Finding } from './ReportView'

interface DependencyTableProps {
  dependencies: DependencyInfo[]
  findings: Finding[]
}

const CONFIDENCE_ORDER: Record<string, number> = { High: 3, Medium: 2, Low: 1 }

function findSuspectedFindings(dep: DependencyInfo, dependencyFindings: Finding[]): Finding[] {
  const needle = dep.artifact_id.toLowerCase()
  return dependencyFindings.filter(f =>
    `${f.title} ${f.description} ${f.evidence} ${f.affected_classes.join(' ')}`.toLowerCase().includes(needle)
  )
}

function highestConfidence(matches: Finding[]): string | null {
  if (matches.length === 0) return null
  return matches.reduce((best, f) => {
    return (CONFIDENCE_ORDER[f.confidence] ?? 0) > (CONFIDENCE_ORDER[best] ?? 0) ? f.confidence : best
  }, matches[0].confidence)
}

/**
 * Real table: Library | Version | Suspected CVE(s)/Severity | Confidence
 * (spec/ui.md -> Screen: Report -> Dependency Summary). Cross-references
 * `findings` whose category_source === "review_dependencies" against each
 * dependency's artifact_id.
 */
export function DependencyTable({ dependencies, findings }: DependencyTableProps) {
  const dependencyFindings = findings.filter(f => f.category_source === 'review_dependencies' && !f.no_evidence_marker)

  if (dependencies.length === 0) {
    return (
      <div className="rounded-lg border border-blue-100 bg-blue-50 p-4 text-sm text-blue-800">
        No dependencies were extracted for this JAR.
      </div>
    )
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
      <table className="w-full text-sm">
        <caption className="border-b border-gray-200 bg-gray-50 px-4 py-2 text-left text-xs text-gray-500">
          Based on model reasoning over extracted dependency versions — not a live CVE database lookup
        </caption>
        <thead className="border-b border-gray-200 text-left text-xs font-semibold text-gray-500 uppercase">
          <tr>
            <th className="px-4 py-2">Library</th>
            <th className="px-4 py-2">Version</th>
            <th className="px-4 py-2">Suspected CVE(s) / Severity</th>
            <th className="px-4 py-2">Confidence</th>
          </tr>
        </thead>
        <tbody>
          {dependencies.map((dep, i) => {
            const matches = findSuspectedFindings(dep, dependencyFindings)
            const confidence = highestConfidence(matches)
            return (
              <tr key={`${dep.artifact_id}-${dep.version ?? i}`} className="border-b border-gray-100 last:border-0">
                <td className="px-4 py-2.5 font-medium text-gray-800">{dep.artifact_id}</td>
                <td className="px-4 py-2.5 text-gray-600">{dep.version ?? '—'}</td>
                <td className="px-4 py-2.5 text-gray-600">
                  {matches.length === 0 ? (
                    <span className="text-gray-400 italic">No suspected issues</span>
                  ) : (
                    <ul className="space-y-1">
                      {matches.map((m, mi) => (
                        <li key={mi}>
                          {m.title} <span className="text-xs text-gray-400">({m.severity}{m.cwe_id ? `, ${m.cwe_id}` : ''})</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </td>
                <td className="px-4 py-2.5 text-gray-600">{confidence ?? '—'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

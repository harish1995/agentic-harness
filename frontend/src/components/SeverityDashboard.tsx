import type { Finding, Severity } from './ReportView'

const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational']

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; bar: string }> = {
  Critical: { bg: 'bg-red-50', text: 'text-red-700', bar: 'bg-red-600' },
  High: { bg: 'bg-orange-50', text: 'text-orange-700', bar: 'bg-orange-500' },
  Medium: { bg: 'bg-yellow-50', text: 'text-yellow-800', bar: 'bg-yellow-400' },
  Low: { bg: 'bg-blue-50', text: 'text-blue-700', bar: 'bg-blue-500' },
  Informational: { bg: 'bg-gray-50', text: 'text-gray-600', bar: 'bg-gray-400' },
}

/** Defensive normalization — `Finding.severity` is typed `string` for cross-slice
 * structural compatibility (see ReportView.tsx), but the pipeline only ever emits one
 * of the five Severity literals; anything else falls back to Informational. */
function normalizeSeverity(value: string): Severity {
  return (SEVERITY_ORDER as string[]).includes(value) ? (value as Severity) : 'Informational'
}

function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0,
  }
  for (const f of findings) {
    if (f.no_evidence_marker) continue
    const severity = normalizeSeverity(f.severity)
    counts[severity] = (counts[severity] ?? 0) + 1
  }
  return counts
}

/**
 * Real table + bar visualization of Critical/High/Medium/Low/Informational
 * finding counts (spec/ui.md -> Screen: Report -> Severity Dashboard).
 * Counts are computed client-side, excluding `no_evidence_marker: true`
 * placeholder entries, per the pinned instructions.
 */
export function SeverityDashboard({ findings }: { findings: Finding[] }) {
  const counts = severityCounts(findings)
  const max = Math.max(1, ...SEVERITY_ORDER.map(s => counts[s]))
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + counts[s], 0)

  if (total === 0) {
    return (
      <div className="rounded-lg border border-blue-100 bg-blue-50 p-4 text-sm text-blue-800">
        No findings were recorded for this scan — every category reported &quot;No evidence found.&quot;
      </div>
    )
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
      <table className="w-full text-sm">
        <thead className="border-b border-gray-200 bg-gray-50 text-left text-xs font-semibold text-gray-500 uppercase">
          <tr>
            <th className="px-4 py-2">Severity</th>
            <th className="px-4 py-2">Count</th>
            <th className="px-4 py-2">Distribution</th>
          </tr>
        </thead>
        <tbody>
          {SEVERITY_ORDER.map(severity => {
            const count = counts[severity]
            const colors = SEVERITY_COLORS[severity]
            const widthPct = Math.max(2, Math.round((count / max) * 100))
            return (
              <tr key={severity} className="border-b border-gray-100 last:border-0">
                <td className="px-4 py-2.5">
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${colors.bg} ${colors.text}`}>
                    {severity}
                  </span>
                </td>
                <td className="px-4 py-2.5 font-medium text-gray-800" data-testid={`severity-count-${severity.toLowerCase()}`}>
                  {count}
                </td>
                <td className="px-4 py-2.5">
                  <div className="h-2 w-full max-w-xs rounded-full bg-gray-100">
                    <div
                      className={`h-2 rounded-full ${colors.bar}`}
                      style={{ width: count > 0 ? `${widthPct}%` : '0%' }}
                    />
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

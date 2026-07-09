import type { Confidence, Finding, Severity } from './ReportView'
import { CodeSnippet } from './CodeSnippet'

const SEVERITY_BADGE: Record<Severity, string> = {
  Critical: 'bg-red-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-yellow-400 text-gray-900',
  Low: 'bg-blue-500 text-white',
  Informational: 'bg-gray-400 text-white',
}

const CONFIDENCE_BADGE: Record<Confidence, string> = {
  High: 'bg-green-100 text-green-800',
  Medium: 'bg-yellow-100 text-yellow-800',
  Low: 'bg-gray-100 text-gray-600',
}

/** Defensive normalization — `Finding.severity`/`confidence` are typed `string` for
 * cross-slice structural compatibility (see ReportView.tsx); anything unrecognized
 * falls back to a safe default rather than crashing the lookup. */
function normalizeSeverity(value: string): Severity {
  return (Object.keys(SEVERITY_BADGE) as string[]).includes(value) ? (value as Severity) : 'Informational'
}

function normalizeConfidence(value: string): Confidence {
  return (Object.keys(CONFIDENCE_BADGE) as string[]).includes(value) ? (value as Confidence) : 'Low'
}

function Tag({ children }: { children: React.ReactNode }) {
  if (!children) return null
  return (
    <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 text-xs font-medium text-gray-600">
      {children}
    </span>
  )
}

function ProseDetails({ label, text, defaultOpen = false }: { label: string; text: string; defaultOpen?: boolean }) {
  if (!text || !text.trim()) return null
  return (
    <details open={defaultOpen} className="rounded-md border border-gray-100 bg-gray-50 p-3">
      <summary className="cursor-pointer text-sm font-semibold text-gray-700">{label}</summary>
      <p className="mt-2 text-sm whitespace-pre-wrap text-gray-700">{text}</p>
    </details>
  )
}

interface FindingCardProps {
  finding: Finding
  anchorId?: string
}

/**
 * Every one of the 20 required Finding fields (spec/agent.md -> Finding
 * TypedDict), rendered per spec/ui.md -> Screen: Report -> FindingCard.
 */
export function FindingCard({ finding: f, anchorId }: FindingCardProps) {
  return (
    <article id={anchorId} className="scroll-mt-24 rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
      {/* Header row: Title + Severity + CVSS + OWASP/STRIDE/CWE tags */}
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <h3 className="text-base font-semibold text-gray-900">{f.title}</h3>
        <span className={`shrink-0 rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_BADGE[normalizeSeverity(f.severity)]}`}>
          {f.severity}
        </span>
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Tag>CVSS {f.cvss_score !== null ? f.cvss_score.toFixed(1) : 'N/A'}</Tag>
        {f.owasp_category && <Tag>{f.owasp_category}</Tag>}
        {f.stride_category && <Tag>{f.stride_category}</Tag>}
        {f.cwe_id && <Tag>{f.cwe_id}</Tag>}
        <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${CONFIDENCE_BADGE[normalizeConfidence(f.confidence)]}`}>
          Confidence: {f.confidence}
        </span>
      </div>

      {/* Affected Classes / Methods */}
      {(f.affected_classes.length > 0 || f.affected_methods.length > 0) && (
        <div className="mb-4 grid gap-3 sm:grid-cols-2">
          {f.affected_classes.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold text-gray-500 uppercase">Affected Classes</p>
              <ul className="space-y-1">
                {f.affected_classes.map((c, i) => (
                  <li key={i}>
                    <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-800">{c}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {f.affected_methods.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold text-gray-500 uppercase">Affected Methods</p>
              <ul className="space-y-1">
                {f.affected_methods.map((m, i) => (
                  <li key={i}>
                    <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-800">{m}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Description (always visible) */}
      {f.description && <p className="mb-4 text-sm text-gray-700">{f.description}</p>}

      {/* Collapsible longer prose fields */}
      <div className="mb-4 space-y-2">
        <ProseDetails label="Business Impact" text={f.business_impact} />
        <ProseDetails label="Technical Impact" text={f.technical_impact} />
        <ProseDetails label="Attack Scenario" text={f.attack_scenario} />
        <ProseDetails label="Why It Is Vulnerable" text={f.why_vulnerable} />
        <ProseDetails label="How An Attacker Can Exploit It" text={f.how_exploitable} />
        <ProseDetails label="Recommended Fix" text={f.recommended_fix} defaultOpen />
      </div>

      {/* Evidence + Code Snippet + Secure Code Example */}
      <div className="mb-4 space-y-3">
        <CodeSnippet code={f.evidence} language="java" label="Evidence" />
        <CodeSnippet code={f.code_snippet} language="java" label="Code Snippet" />
        <CodeSnippet code={f.secure_code_example} language="java" label="Secure Code Example" />
      </div>

      {/* References */}
      {f.references.length > 0 && (
        <div className="mb-4">
          <p className="mb-1 text-xs font-semibold text-gray-500 uppercase">References</p>
          <ul className="space-y-1">
            {f.references.map((ref, i) => (
              <li key={i}>
                <a
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-blue-600 underline hover:text-blue-800"
                >
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Phase 1 labelled stub */}
      <button
        type="button"
        disabled
        title="Coming soon"
        aria-disabled="true"
        className="cursor-not-allowed rounded-md border border-gray-200 bg-gray-100 px-3 py-1.5 text-xs font-medium text-gray-400"
      >
        Mark as accepted risk
      </button>
    </article>
  )
}

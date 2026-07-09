'use client'

import { useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { SeverityDashboard } from './SeverityDashboard'
import { CategorySummary } from './CategorySummary'
import { DependencyTable } from './DependencyTable'
import { FindingCard } from './FindingCard'

// ---------------------------------------------------------------------------
// Types — mirror spec/api.md's `GET /scans/{scan_id}` "completed" response
// `data` shape verbatim, and spec/agent.md's `Finding` TypedDict (public
// fields only — `verified`/`verification_note` are internal pipeline state,
// not part of the API response). This is the pinned cross-slice contract
// documented in spec/ui.md -> "Frontend Component Contract".
// ---------------------------------------------------------------------------

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
export type Confidence = 'High' | 'Medium' | 'Low'
export type ScanStatus = 'processing' | 'completed' | 'failed'

export interface Finding {
  title: string
  // Typed as `string` (not the stricter `Severity`/`Confidence` literal unions) so this
  // structurally matches upload-progress-ui's independently-defined ScanDetailResponse
  // (frontend/src/lib/api.ts) per spec/ui.md -> Frontend Component Contract — both slices
  // build against the same spec/api.md JSON shape without importing each other's types.
  // Values are always one of Severity/Confidence at runtime (server-enforced); components
  // below normalize defensively before using them as lookup keys.
  severity: string
  cvss_score: number | null
  owasp_category: string | null
  stride_category: string | null
  cwe_id: string | null
  affected_classes: string[]
  affected_methods: string[]
  description: string
  business_impact: string
  technical_impact: string
  attack_scenario: string
  evidence: string
  code_snippet: string
  why_vulnerable: string
  how_exploitable: string
  recommended_fix: string
  secure_code_example: string
  references: string[]
  confidence: string
  category_source: string
  no_evidence_marker: boolean
}

export interface DependencyInfo {
  artifact_id: string
  group_id: string | null
  version: string | null
  source: string
}

export interface ScanDetailResponse {
  scan_id: string
  original_filename: string
  uploaded_at: string
  status: ScanStatus
  current_phase: string
  is_spring_boot: boolean | null
  class_count: number | null
  triaged_class_count: number | null
  risk_score: number | null
  report_markdown: string | null
  findings: Finding[] | null
  dependencies: DependencyInfo[] | null
  total_input_tokens: number | null
  total_output_tokens: number | null
  estimated_cost_usd: number | null
  error: string | null
}

// ---------------------------------------------------------------------------
// Per-category finding-section bucketing (client-side mirror of
// assemble_report's bucketing logic, spec/agent.md -> assemble_report
// Behaviour). Exactly the 7 sections spec/agent.md's Required Report
// Structure dedicates to individual findings (Dependency Vulnerabilities is
// rendered separately via DependencyTable, not here).
// ---------------------------------------------------------------------------

type SectionKey =
  | 'sensitive_data_exposure'
  | 'authentication'
  | 'authorization'
  | 'cryptography'
  | 'injection'
  | 'configuration'
  | 'logging'

const SECTION_ORDER: SectionKey[] = [
  'sensitive_data_exposure',
  'authentication',
  'authorization',
  'cryptography',
  'injection',
  'configuration',
  'logging',
]

const SECTION_LABELS: Record<SectionKey, string> = {
  sensitive_data_exposure: 'Sensitive Data Exposure',
  authentication: 'Authentication Issues',
  authorization: 'Authorization Issues',
  cryptography: 'Cryptography Issues',
  injection: 'Injection Issues',
  configuration: 'Configuration Issues',
  logging: 'Logging Issues',
}

function textBlob(f: Finding): string {
  return `${f.title} ${f.owasp_category ?? ''} ${f.description}`.toLowerCase()
}

function classifyFinding(f: Finding): SectionKey {
  const src = f.category_source
  const text = textBlob(f)

  if (src === 'review_injection') return 'injection'

  if (src === 'review_authn_authz') {
    const authzKeywords = [
      'authoriz', 'access control', 'permission', 'privilege', 'role-based',
      'preauthorize', '@secured', 'idor', 'elevation of privilege', 'broken access control',
    ]
    return authzKeywords.some(k => text.includes(k)) ? 'authorization' : 'authentication'
  }

  if (src === 'review_crypto_secrets') {
    const dataExposureKeywords = [
      'hardcoded', 'secret', 'credential', 'api key', 'password in',
      'exposed', 'plaintext', 'sensitive data',
    ]
    return dataExposureKeywords.some(k => text.includes(k)) ? 'sensitive_data_exposure' : 'cryptography'
  }

  if (src === 'review_config_logging') {
    const loggingKeywords = ['log', 'logger', 'logging', 'audit trail']
    return loggingKeywords.some(k => text.includes(k)) ? 'logging' : 'configuration'
  }

  if (src === 'review_deserialization_upload') {
    // spec/agent.md's Required Report Structure has no dedicated Deserialization/
    // File-Upload section; these are injection-class vulnerabilities (CWE-502 etc.)
    // so they fold into Injection Issues instead of being silently dropped.
    return 'injection'
  }

  // Defensive fallback — should not occur given the fixed pipeline's category_source
  // values, but never silently drop a finding.
  if (text.includes('inject')) return 'injection'
  if (text.includes('crypto') || text.includes('encrypt')) return 'cryptography'
  if (text.includes('auth')) return 'authentication'
  return 'configuration'
}

function bucketFindings(findings: Finding[]): Record<SectionKey, Finding[]> {
  const buckets: Record<SectionKey, Finding[]> = {
    sensitive_data_exposure: [],
    authentication: [],
    authorization: [],
    cryptography: [],
    injection: [],
    configuration: [],
    logging: [],
  }
  for (const f of findings) {
    if (f.category_source === 'review_dependencies') continue
    if (f.no_evidence_marker) continue
    buckets[classifyFinding(f)].push(f)
  }
  return buckets
}

// ---------------------------------------------------------------------------
// Risk band (spec/agent.md -> assemble_report Behaviour: risk_score bands)
// ---------------------------------------------------------------------------

function riskBand(score: number): { label: string; className: string } {
  if (score >= 80) return { label: 'Critical Risk', className: 'bg-red-600 text-white' }
  if (score >= 60) return { label: 'High Risk', className: 'bg-orange-500 text-white' }
  if (score >= 35) return { label: 'Medium Risk', className: 'bg-yellow-400 text-gray-900' }
  if (score >= 15) return { label: 'Low Risk', className: 'bg-blue-500 text-white' }
  return { label: 'Minimal Risk', className: 'bg-green-500 text-white' }
}

// ---------------------------------------------------------------------------
// report_markdown section extraction — splits the full assembled report on
// its verbatim `# Section Name` headers (spec/agent.md -> Required Report
// Structure) so free-text prose sections without individual JSON fields
// (Executive Summary, Secure Coding Recommendations, Developer Remediation
// Plan, Appendix) can still be rendered as real markdown.
// ---------------------------------------------------------------------------

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function extractSection(markdown: string, heading: string): string {
  if (!markdown) return ''
  const lines = markdown.split('\n')
  const headingPattern = new RegExp(`^#\\s+${escapeRegExp(heading)}\\s*$`)
  let start = -1
  for (let i = 0; i < lines.length; i++) {
    if (headingPattern.test(lines[i].trim())) {
      start = i + 1
      break
    }
  }
  if (start === -1) return ''
  let end = lines.length
  for (let i = start; i < lines.length; i++) {
    if (/^#\s+\S/.test(lines[i].trim())) {
      end = i
      break
    }
  }
  return lines.slice(start, end).join('\n').trim()
}

/** Best-effort structured split of the Developer Remediation Plan section into its
 * Priority 1-4 groups (spec/ui.md: "rendered as real ordered lists/tables, not raw
 * markdown"). Falls back to a plain markdown render of the whole section — still real
 * markdown, never a raw string dump — if no "Priority N" markers are found. */
function splitPriorityGroups(section: string): { title: string; body: string }[] | null {
  if (!section) return null
  const lines = section.split('\n')
  const priorityPattern = /^#{0,4}\s*\*{0,2}Priority\s*([1-4])\b.*$/i
  const markers: { index: number; title: string }[] = []
  lines.forEach((line, i) => {
    const trimmed = line.trim()
    const m = priorityPattern.exec(trimmed)
    if (m) markers.push({ index: i, title: trimmed.replace(/^#+\s*/, '').replace(/\*+/g, '') })
  })
  if (markers.length === 0) return null
  const groups: { title: string; body: string }[] = []
  for (let i = 0; i < markers.length; i++) {
    const start = markers[i].index + 1
    const end = i + 1 < markers.length ? markers[i + 1].index : lines.length
    groups.push({ title: markers[i].title, body: lines.slice(start, end).join('\n').trim() })
  }
  return groups
}

// ---------------------------------------------------------------------------
// Cost footer formatting (exact format pinned in spec/ui.md -> Screen: Report)
// ---------------------------------------------------------------------------

function formatCostFooter(scan: ScanDetailResponse): string {
  const inputTokens = (scan.total_input_tokens ?? 0).toLocaleString('en-US')
  const outputTokens = (scan.total_output_tokens ?? 0).toLocaleString('en-US')
  const cost = (scan.estimated_cost_usd ?? 0).toFixed(2)
  return `~${inputTokens} input / ${outputTokens} output tokens · est. $${cost} (approximate)`
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ReportView({ scan }: { scan: ScanDetailResponse }) {
  const [fullReportOpen, setFullReportOpen] = useState(false)
  const findings = scan.findings ?? []
  const dependencies = scan.dependencies ?? []
  const reportMarkdown = scan.report_markdown ?? ''

  const executiveSummary = extractSection(reportMarkdown, 'Executive Summary')
  const secureCodingRecommendations = extractSection(reportMarkdown, 'Secure Coding Recommendations')
  const developerRemediationPlan = extractSection(reportMarkdown, 'Developer Remediation Plan')
  const appendix = extractSection(reportMarkdown, 'Appendix')
  const priorityGroups = splitPriorityGroups(developerRemediationPlan)

  const buckets = bucketFindings(findings)
  const band = riskBand(scan.risk_score ?? 0)

  return (
    <div className="mx-auto max-w-4xl px-4 pb-28 pt-10">
      <div className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-900">
            Security Report — {scan.original_filename}
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            Uploaded {new Date(scan.uploaded_at).toLocaleString()}
            {scan.is_spring_boot ? ' · Spring Boot detected' : ''}
          </p>
        </div>
      </div>

      {/* 1. Executive Summary */}
      <section id="executive-summary" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">Executive Summary</h2>
        {executiveSummary ? (
          <div className="prose prose-sm max-w-none rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{executiveSummary}</ReactMarkdown>
          </div>
        ) : (
          <p className="text-sm text-gray-400 italic">No executive summary was produced for this scan.</p>
        )}

        <details className="mt-3" open={fullReportOpen} onToggle={e => setFullReportOpen(e.currentTarget.open)}>
          <summary className="cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-800">
            View full report (raw markdown)
          </summary>
          <div className="prose prose-sm mt-3 max-w-none rounded-lg border border-gray-200 bg-gray-50 p-5">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{reportMarkdown || '_No report content._'}</ReactMarkdown>
          </div>
        </details>
      </section>

      {/* 2. Risk Score */}
      <section id="risk-score" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">Risk Score</h2>
        <div className="flex items-center gap-4 rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
          <span className="text-5xl font-bold text-gray-900">{scan.risk_score ?? '—'}</span>
          <span className={`rounded-full px-3 py-1 text-sm font-semibold ${band.className}`}>{band.label}</span>
        </div>
      </section>

      {/* 3. Severity Dashboard */}
      <section id="severity-dashboard" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">Severity Dashboard</h2>
        <SeverityDashboard findings={findings} />
      </section>

      {/* 4. OWASP / STRIDE summaries */}
      <section id="owasp-summary" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">OWASP Top 10 Summary</h2>
        <CategorySummary findings={findings} groupBy="owasp" />
      </section>

      <section id="stride-summary" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">STRIDE Summary</h2>
        <CategorySummary findings={findings} groupBy="stride" />
      </section>

      {/* 5. Dependency Summary */}
      <section id="dependency-summary" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">Dependency Summary</h2>
        <DependencyTable dependencies={dependencies} findings={findings} />
      </section>

      {/* 6/7. Per-category finding sections */}
      {SECTION_ORDER.map(key => {
        const sectionFindings = buckets[key]
        return (
          <section key={key} id={`section-${key}`} className="mb-10 scroll-mt-24">
            <h2 className="mb-3 text-lg font-semibold text-gray-900">{SECTION_LABELS[key]}</h2>
            {sectionFindings.length === 0 ? (
              <div className="rounded-lg border border-blue-100 bg-blue-50 p-4 text-sm text-blue-800">
                No evidence found.
              </div>
            ) : (
              <div className="space-y-4">
                {sectionFindings.map(f => (
                  <FindingCard key={findings.indexOf(f)} finding={f} anchorId={`finding-${findings.indexOf(f)}`} />
                ))}
              </div>
            )}
          </section>
        )
      })}

      {/* 9. Secure Coding Recommendations */}
      <section id="secure-coding-recommendations" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">Secure Coding Recommendations</h2>
        {secureCodingRecommendations ? (
          <div className="prose prose-sm max-w-none rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{secureCodingRecommendations}</ReactMarkdown>
          </div>
        ) : (
          <p className="text-sm text-gray-400 italic">No recommendations section was produced for this scan.</p>
        )}
      </section>

      {/* 9. Developer Remediation Plan */}
      <section id="developer-remediation-plan" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">Developer Remediation Plan</h2>
        {priorityGroups ? (
          <div className="space-y-3">
            {priorityGroups.map((g, i) => (
              <div key={i} className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
                <h3 className="mb-2 text-sm font-semibold text-gray-800">{g.title}</h3>
                <div className="prose prose-sm max-w-none">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{g.body || '_Nothing at this priority._'}</ReactMarkdown>
                </div>
              </div>
            ))}
          </div>
        ) : developerRemediationPlan ? (
          <div className="prose prose-sm max-w-none rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{developerRemediationPlan}</ReactMarkdown>
          </div>
        ) : (
          <p className="text-sm text-gray-400 italic">No remediation plan was produced for this scan.</p>
        )}
      </section>

      {/* 10. Appendix */}
      <section id="appendix" className="mb-10 scroll-mt-24">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">Appendix</h2>
        {appendix ? (
          <div className="prose prose-sm max-w-none rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{appendix}</ReactMarkdown>
          </div>
        ) : (
          <p className="text-sm text-gray-400 italic">No appendix was produced for this scan.</p>
        )}
      </section>

      {/* 13. Labelled stub buttons (Phase 1) */}
      <section className="mb-24">
        <h2 className="mb-3 text-sm font-semibold text-gray-500 uppercase tracking-wide">Coming soon</h2>
        <div className="flex flex-wrap gap-3">
          {['Export JSON/SARIF', 'Ask a follow-up', 'Compare with another scan'].map(label => (
            <button
              key={label}
              type="button"
              disabled
              title="Coming soon"
              aria-disabled="true"
              className="cursor-not-allowed rounded-lg border border-gray-200 bg-gray-100 px-4 py-2 text-sm font-medium text-gray-400"
            >
              {label}
            </button>
          ))}
        </div>
      </section>

      {/* 12. Download button + 11. Cost footer (sticky, bottom) */}
      <div className="fixed inset-x-0 bottom-0 z-10 border-t border-gray-200 bg-white/95 backdrop-blur">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <p className="text-xs text-gray-500">{formatCostFooter(scan)}</p>
          <a
            href={`/scans/${scan.scan_id}/download`}
            download
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-700"
          >
            Download .md
          </a>
        </div>
      </div>
    </div>
  )
}

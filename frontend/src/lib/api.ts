/**
 * Typed fetch helpers for the JAR security scanner API.
 *
 * Contract source of truth: spec/api.md (PINNED). All requests are relative
 * paths — the frontend is served single-origin by FastAPI at :8001/app/, so
 * `/scans` resolves against the same origin (harness/patterns/tech-stack.md).
 */

// ---------------------------------------------------------------------------
// Types (mirror spec/api.md JSON shapes verbatim)
// ---------------------------------------------------------------------------

export type ScanStatus = 'processing' | 'completed' | 'failed'

/** Response `data` shape for `POST /scans`. */
export interface UploadScanResponse {
  scan_id: string
  status: ScanStatus
  current_phase: string
}

/** Response `data` shape for `GET /scans/{id}/status` — the polling contract. */
export interface ScanStatusResponse {
  scan_id: string
  status: ScanStatus
  current_phase: string
  is_spring_boot: boolean | null
  class_count: number | null
  error: string | null
}

/** One entry of the `findings` array on a completed scan (spec/api.md -> Finding). */
export interface Finding {
  title: string
  severity: string
  cvss_score: number | null
  owasp_category: string
  stride_category: string
  cwe_id: string
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

export interface Dependency {
  artifact_id: string
  group_id: string | null
  version: string
  source: string
}

/** Response `data` shape for `GET /scans/{id}` (both processing and completed cases). */
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
  dependencies: Dependency[] | null
  total_input_tokens: number | null
  total_output_tokens: number | null
  estimated_cost_usd: number | null
  error: string | null
}

interface ApiEnvelope<T> {
  data: T
  error: null
}

interface ApiErrorDetail {
  code?: string
  message?: string
}

/**
 * Thrown for any non-2xx response. `message` is the server-provided
 * `detail.message` when present, else a clear generic fallback — never a
 * raw stack trace or bare "Error 500" (harness/patterns/ui-ux.md -> Copy).
 */
export class ApiError extends Error {
  status: number
  code: string | undefined

  constructor(status: number, message: string, code?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

async function parseErrorMessage(res: Response): Promise<{ message: string; code?: string }> {
  try {
    const body = await res.json()
    const detail: ApiErrorDetail | undefined = body?.detail
    if (detail?.message) {
      return { message: detail.message, code: detail.code }
    }
  } catch {
    // response body wasn't JSON — fall through to generic message
  }
  return { message: `Request failed (${res.status})` }
}

/**
 * Wraps `fetch` for the `{"data": ..., "error": null}` success envelope and
 * `{"detail": {"code", "message"}}` error envelope used throughout the API.
 */
async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, init)
  } catch {
    throw new ApiError(0, 'Network error — is the server running?')
  }

  if (!res.ok) {
    const { message, code } = await parseErrorMessage(res)
    throw new ApiError(res.status, message, code)
  }

  const body: ApiEnvelope<T> = await res.json()
  return body.data
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/** `POST /scans` — upload a JAR and start a scan. */
export async function uploadScan(file: File): Promise<UploadScanResponse> {
  const formData = new FormData()
  formData.append('file', file)
  return apiFetch<UploadScanResponse>('/scans', {
    method: 'POST',
    body: formData,
  })
}

/** `GET /scans/{id}/status` — the 2-second polling endpoint. */
export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  return apiFetch<ScanStatusResponse>(`/scans/${scanId}/status`)
}

/** `GET /scans/{id}` — full scan record, including the report once completed. */
export async function getScanDetail(scanId: string): Promise<ScanDetailResponse> {
  return apiFetch<ScanDetailResponse>(`/scans/${scanId}`)
}

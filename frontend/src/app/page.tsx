'use client'

import { useEffect, useRef, useState } from 'react'
import { UploadForm } from '@/components/UploadForm'
import { ProgressPanel } from '@/components/ProgressPanel'
import { ReportView } from '@/components/ReportView'
import {
  ApiError,
  getScanDetail,
  getScanStatus,
  type ScanDetailResponse,
  type ScanStatusResponse,
  type UploadScanResponse,
} from '@/lib/api'

const POLL_INTERVAL_MS = 2000

export default function Home() {
  const [scan, setScan] = useState<UploadScanResponse | null>(null)
  const [status, setStatus] = useState<ScanStatusResponse | null>(null)
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null)
  const [detailError, setDetailError] = useState<string | null>(null)
  const [networkError, setNetworkError] = useState(false)
  const startedAtRef = useRef<number | null>(null)
  // Remembers the last *real* (non-terminal) current_phase seen across polls.
  // current_phase flips to "failed" (spec/agent.md -> handle_error) or briefly
  // sits at "completed" while fetchDetail is in flight — neither value maps to
  // any macro-step's `phases` array, so ProgressPanel must be given this
  // remembered phase instead of the raw terminal one to freeze the stepper at
  // the phase the scan actually reached (spec/ui.md -> Screen: Progress -> Error).
  const lastRealPhaseRef = useRef<string | null>(null)

  function recordPhaseIfReal(phase: string) {
    if (phase !== 'failed' && phase !== 'completed') {
      lastRealPhaseRef.current = phase
    }
  }

  function handleScanStarted(result: UploadScanResponse) {
    startedAtRef.current = Date.now()
    lastRealPhaseRef.current = null
    recordPhaseIfReal(result.current_phase)
    setDetail(null)
    setDetailError(null)
    setNetworkError(false)
    setStatus({
      scan_id: result.scan_id,
      status: result.status,
      current_phase: result.current_phase,
      is_spring_boot: null,
      class_count: null,
      error: null,
    })
    setScan(result)
  }

  function handleReset() {
    setScan(null)
    setStatus(null)
    setDetail(null)
    setDetailError(null)
    setNetworkError(false)
    startedAtRef.current = null
    lastRealPhaseRef.current = null
  }

  async function fetchDetail(scanId: string) {
    try {
      const full = await getScanDetail(scanId)
      setDetail(full)
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : 'Network error — is the server running?')
    }
  }

  // Owns all polling/fetching state — UploadForm/ProgressPanel/ReportView are
  // pure presentational components (spec/ui.md -> Frontend Component Contract).
  useEffect(() => {
    if (!scan) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    async function tick() {
      if (!scan) return
      try {
        const result = await getScanStatus(scan.scan_id)
        if (cancelled) return
        setNetworkError(false)
        recordPhaseIfReal(result.current_phase)
        setStatus(result)

        if (result.status === 'completed') {
          await fetchDetail(scan.scan_id)
          return
        }
        if (result.status === 'failed') {
          return
        }
        timer = setTimeout(tick, POLL_INTERVAL_MS)
      } catch {
        if (cancelled) return
        setNetworkError(true)
        timer = setTimeout(tick, POLL_INTERVAL_MS)
      }
    }

    tick()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan])

  return (
    <>
      {networkError && (
        <div
          role="status"
          className="fixed inset-x-0 top-0 z-50 bg-amber-100 px-4 py-2 text-center text-sm font-medium text-amber-800 shadow-sm"
        >
          Can&apos;t reach the server — retrying…
        </div>
      )}

      {detail ? (
        <ReportView scan={detail} />
      ) : detailError ? (
        <div className="mx-auto max-w-2xl px-4 py-16">
          <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
            <p className="mb-2 font-medium">Couldn&apos;t load the finished report</p>
            <p className="mb-3">{detailError}</p>
            <button
              type="button"
              onClick={() => scan && fetchDetail(scan.scan_id)}
              className="rounded-md border border-red-300 bg-white px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-100"
            >
              Try again
            </button>
          </div>
        </div>
      ) : status && scan ? (
        <ProgressPanel
          status={status}
          startedAt={startedAtRef.current ?? undefined}
          lastRealPhase={lastRealPhaseRef.current}
          onUploadDifferentFile={handleReset}
        />
      ) : (
        <UploadForm onScanStarted={handleScanStarted} />
      )}
    </>
  )
}

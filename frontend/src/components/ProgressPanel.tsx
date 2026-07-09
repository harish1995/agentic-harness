'use client'

import { useEffect, useRef, useState } from 'react'
import type { ScanStatusResponse } from '@/lib/api'

interface ProgressPanelProps {
  status: ScanStatusResponse
  /** ms epoch timestamp the scan started at; falls back to mount time if omitted. */
  startedAt?: number
  /**
   * The last non-terminal `current_phase` observed across polls (tracked by
   * the caller — see frontend/src/app/page.tsx). `current_phase` becomes
   * "failed" on error (spec/agent.md -> handle_error) or briefly sits at
   * "completed" while the detail fetch is in flight; neither value appears in
   * any macro-step's `phases` array, so this remembered phase is what the
   * stepper freezes on instead (spec/ui.md -> Screen: Progress -> Error).
   */
  lastRealPhase?: string | null
  onUploadDifferentFile: () => void
}

interface MacroStep {
  key: string
  label: string
  phases: string[]
}

/**
 * Fixed current_phase -> macro-step lookup, copied verbatim from
 * spec/ui.md -> Screen: Progress.
 */
const MACRO_STEPS: MacroStep[] = [
  { key: 'decompiling', label: 'Decompiling', phases: ['queued', 'decompiling'] },
  { key: 'dependency_scan', label: 'Dependency Scan', phases: ['scanning_dependencies'] },
  { key: 'secret_scan', label: 'Secret Scan', phases: ['scanning_secrets'] },
  { key: 'config_extraction', label: 'Config Extraction', phases: ['extracting_config'] },
  { key: 'triage', label: 'Triage', phases: ['triaging'] },
  {
    key: 'llm_review',
    label: 'LLM Security Review',
    phases: [
      'reviewing_injection',
      'reviewing_authn_authz',
      'reviewing_crypto_secrets',
      'reviewing_deserialization_upload',
      'reviewing_config_logging',
      'reviewing_dependencies',
    ],
  },
  { key: 'verification', label: 'Verification', phases: ['verifying'] },
  { key: 'report_generation', label: 'Report Generation', phases: ['assembling_report'] },
]

const SUB_LABELS: Record<string, string> = {
  triaging: 'Selecting security-relevant code',
  reviewing_injection: 'Injection',
  reviewing_authn_authz: 'Authentication & Authorization',
  reviewing_crypto_secrets: 'Cryptography & Secrets',
  reviewing_deserialization_upload: 'Deserialization & File Upload',
  reviewing_config_logging: 'Configuration & Logging',
  reviewing_dependencies: 'Dependency Vulnerabilities',
}

function activeStepIndex(currentPhase: string): number {
  return MACRO_STEPS.findIndex(step => step.phases.includes(currentPhase))
}

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-5 w-5">
      <path strokeLinecap="round" strokeLinejoin="round" d="m4.5 12.75 6 6 9-13.5" />
    </svg>
  )
}

function SpinnerIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className="h-5 w-5 animate-spin"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth={3} className="opacity-25" />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        stroke="currentColor"
        strokeWidth={3}
        strokeLinecap="round"
        className="opacity-90"
      />
    </svg>
  )
}

function ErrorIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-5 w-5">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 9v3.75m0 3.75h.008M10.29 3.86 1.82 18a1.5 1.5 0 0 0 1.29 2.25h17.78A1.5 1.5 0 0 0 22.18 18L13.71 3.86a1.5 1.5 0 0 0-2.42 0Z"
      />
    </svg>
  )
}

export function ProgressPanel({ status, startedAt, lastRealPhase, onUploadDifferentFile }: ProgressPanelProps) {
  const mountedAt = useRef<number>(startedAt ?? Date.now())
  const [elapsedSeconds, setElapsedSeconds] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - mountedAt.current) / 1000))
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const isFailed = status.status === 'failed'
  // "failed" and "completed" are terminal current_phase values that never
  // appear in any macro-step's `phases` array (see MACRO_STEPS above) — look
  // up the remembered last-real-phase instead so the stepper freezes on the
  // phase actually reached rather than resetting to a blank, dimmed list.
  const isTerminalPhase = status.current_phase === 'failed' || status.current_phase === 'completed'
  const effectivePhase = isTerminalPhase ? (lastRealPhase ?? status.current_phase) : status.current_phase
  const activeIndex = activeStepIndex(effectivePhase)
  const subLabel = SUB_LABELS[effectivePhase]

  return (
    <div className="mx-auto max-w-2xl px-4 py-16">
      <h1 className="mb-2 text-3xl font-bold tracking-tight text-gray-900">Scanning…</h1>
      <p className="mb-8 text-sm text-gray-500">
        Elapsed: <span className="font-mono">{formatElapsed(elapsedSeconds)}</span>
      </p>

      {isFailed && (
        <div role="alert" className="mb-8 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <p className="mb-2 font-medium">Scan failed</p>
          <p className="mb-3">{status.error ?? 'An unexpected error occurred during the scan.'}</p>
          <button
            type="button"
            onClick={onUploadDifferentFile}
            className="rounded-md border border-red-300 bg-white px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-100"
          >
            Upload a different file
          </button>
        </div>
      )}

      <ol className="space-y-4" aria-label="Scan progress">
        {MACRO_STEPS.map((step, index) => {
          const isFailedHere = isFailed && index === activeIndex
          // Not gated by !isFailed: on a failed scan every macro-step before
          // the failure point must still show its checkmark (spec/ui.md ->
          // Screen: Progress -> Error: "the stepper freezes on the phase it
          // failed at ... " — steps before it stay completed, not reset).
          const isDone = activeIndex >= 0 && index < activeIndex
          const isActive = !isFailed && index === activeIndex
          const isFuture = !isFailedHere && !isDone && !isActive

          return (
            <li
              key={step.key}
              className={`flex items-start gap-3 rounded-lg border p-4 transition-colors ${
                isFailedHere
                  ? 'border-red-300 bg-red-50'
                  : isActive
                    ? 'border-blue-300 bg-blue-50'
                    : isDone
                      ? 'border-green-200 bg-green-50'
                      : 'border-gray-200 bg-white'
              }`}
            >
              <span
                className={`mt-0.5 flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full ${
                  isFailedHere
                    ? 'bg-red-500 text-white'
                    : isActive
                      ? 'bg-blue-500 text-white'
                      : isDone
                        ? 'bg-green-500 text-white'
                        : 'bg-gray-200 text-gray-400'
                }`}
              >
                {isFailedHere ? <ErrorIcon /> : isActive ? <SpinnerIcon /> : isDone ? <CheckIcon /> : (
                  <span className="text-xs font-semibold">{index + 1}</span>
                )}
              </span>
              <div>
                <p
                  className={`text-sm font-medium ${
                    isFuture ? 'text-gray-400' : 'text-gray-800'
                  }`}
                >
                  {step.label}
                </p>
                {isActive && subLabel && <p className="text-xs text-blue-600">{subLabel}</p>}
                {isFailedHere && <p className="text-xs text-red-600">Failed here</p>}
              </div>
            </li>
          )
        })}
      </ol>

      {(status.is_spring_boot !== null || status.class_count !== null) && (
        <p className="mt-8 text-sm text-gray-500">
          {status.class_count !== null ? `Scanning ${status.class_count} classes` : 'Scanning classes'}
          {' · '}
          {status.is_spring_boot ? 'Spring Boot detected' : 'Plain JAR'}
        </p>
      )}

      <div className="mt-10">
        <button
          type="button"
          disabled
          title="Not available yet"
          className="cursor-not-allowed rounded-lg border border-gray-300 bg-gray-100 px-4 py-2 text-sm font-medium text-gray-400"
        >
          Cancel
        </button>
      </div>
    </div>
  )
}

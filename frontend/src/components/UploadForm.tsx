'use client'

import { useCallback, useRef, useState } from 'react'
import { ApiError, uploadScan, type UploadScanResponse } from '@/lib/api'

interface UploadFormProps {
  onScanStarted: (scan: UploadScanResponse) => void
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function UploadForm({ onScanStarted }: UploadFormProps) {
  const [file, setFile] = useState<File | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFileChosen = useCallback((chosen: File | null) => {
    setError(null)
    if (!chosen) {
      setFile(null)
      return
    }
    setFile(chosen)
  }, [])

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setIsDragging(false)
    const dropped = e.dataTransfer.files?.[0] ?? null
    handleFileChosen(dropped)
  }

  function handleDragOver(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setIsDragging(true)
  }

  function handleDragLeave(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setIsDragging(false)
  }

  function handleBrowseClick() {
    inputRef.current?.click()
  }

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    handleFileChosen(e.target.files?.[0] ?? null)
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!file || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      const result = await uploadScan(file)
      onScanStarted(result)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Network error — is the server running?')
      }
      setSubmitting(false)
    }
  }

  function handleTryAgain() {
    setError(null)
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-16">
      <nav className="mb-10 flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-gray-900">JAR Security Scanner</h1>
        <span
          aria-disabled="true"
          title="Coming soon"
          className="cursor-not-allowed rounded-md px-3 py-1.5 text-sm font-medium text-gray-400 select-none"
        >
          Scan History
        </span>
      </nav>

      <p className="mb-6 text-sm text-gray-600">
        Drop a Java/Spring Boot JAR to run a local decompile, static analysis, and an
        exhaustive AI-driven security review. The JAR and everything decompiled from it
        stay on this machine.
      </p>

      {error && (
        <div
          role="alert"
          className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700"
        >
          <p className="mb-2 font-medium">Couldn&apos;t start the scan</p>
          <p className="mb-3">{error}</p>
          <button
            type="button"
            onClick={handleTryAgain}
            className="rounded-md border border-red-300 bg-white px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-100"
          >
            Try again
          </button>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={handleBrowseClick}
          role="button"
          tabIndex={0}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              handleBrowseClick()
            }
          }}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-12 text-center transition-colors ${
            isDragging
              ? 'border-blue-500 bg-blue-50'
              : 'border-gray-300 bg-white hover:border-blue-400 hover:bg-gray-50'
          }`}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            className="mb-4 h-12 w-12 text-gray-400"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3"
            />
          </svg>
          <p className="mb-1 text-base font-medium text-gray-700">
            Drop your JAR here, or click to browse
          </p>
          <p className="text-sm text-gray-400">.jar files only</p>
          <input
            ref={inputRef}
            type="file"
            accept=".jar"
            className="hidden"
            onChange={handleInputChange}
          />
        </div>

        {file && (
          <div className="flex items-center justify-between rounded-lg border border-gray-200 bg-white p-4 text-sm shadow-sm">
            <div>
              <p className="font-medium text-gray-800">{file.name}</p>
              <p className="text-gray-500">{formatBytes(file.size)}</p>
            </div>
            <button
              type="button"
              onClick={() => handleFileChosen(null)}
              className="text-sm text-gray-400 hover:text-gray-600"
              aria-label="Remove selected file"
            >
              Remove
            </button>
          </div>
        )}

        <button
          type="submit"
          disabled={!file || submitting}
          className="w-full rounded-lg bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-300"
        >
          {submitting ? 'Starting…' : 'Start Scan'}
        </button>
      </form>
    </div>
  )
}

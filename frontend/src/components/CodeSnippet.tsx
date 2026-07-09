'use client'

import { useState } from 'react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'

interface CodeSnippetProps {
  code: string
  language?: string
  /** Optional small label shown above the block, e.g. "Evidence" / "Secure Code Example". */
  label?: string
}

/**
 * Syntax-highlighted code block with a copy-to-clipboard button.
 * Used for Evidence / Code Snippet / Secure Code Example fields on a Finding,
 * per spec/ui.md -> Screen: Report -> FindingCard.
 */
export function CodeSnippet({ code, language = 'java', label }: CodeSnippetProps) {
  const [copied, setCopied] = useState(false)

  const hasContent = Boolean(code && code.trim().length > 0)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard API unavailable — silently ignore, copy is a convenience, not core behavior
    }
  }

  if (!hasContent) {
    return (
      <div className="rounded-md border border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-400 italic">
        No code provided.
      </div>
    )
  }

  return (
    <div className="overflow-hidden rounded-md border border-gray-700">
      <div className="flex items-center justify-between bg-gray-800 px-3 py-1.5">
        <span className="text-xs font-medium text-gray-300">{label ?? language}</span>
        <button
          type="button"
          onClick={handleCopy}
          className="rounded px-2 py-0.5 text-xs font-medium text-gray-200 hover:bg-gray-700"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <SyntaxHighlighter
        language={language}
        style={oneDark}
        customStyle={{ margin: 0, fontSize: '0.8rem', maxHeight: '24rem' }}
        wrapLongLines
      >
        {code}
      </SyntaxHighlighter>
    </div>
  )
}

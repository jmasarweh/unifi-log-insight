/**
 * TEMPORARY — delete after #27 self-hosted firewall support is implemented.
 *
 * In-app diagnostics panel for self-hosted controller API exploration.
 * Probes every relevant classic API endpoint and displays raw JSON results
 * so a tester can share the output for analysis.
 */
import { useState } from 'react'
import { runSelfHostedDiagnostics } from '../api'

const STATUS_COLORS = {
  200: 'bg-green-500/20 text-green-400 border-green-500/30',
  401: 'bg-red-500/20 text-red-400 border-red-500/30',
  403: 'bg-red-500/20 text-red-400 border-red-500/30',
  404: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
}

function StatusBadge({ status, error }) {
  if (error) {
    return (
      <span className="px-2 py-0.5 rounded text-xs font-mono border bg-red-500/20 text-red-400 border-red-500/30">
        Error
      </span>
    )
  }
  const color = STATUS_COLORS[status] || 'bg-gray-500/20 text-gray-400 border-gray-500/30'
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono border ${color}`}>
      {status}
    </span>
  )
}

function EndpointCard({ name, result }) {
  const [expanded, setExpanded] = useState(false)
  const { url, description, status, data, error, elapsed_ms, note } = result

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900/50 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-800/40 transition-colors"
      >
        <svg
          className={`w-3.5 h-3.5 text-gray-500 shrink-0 transition-transform ${expanded ? 'rotate-90' : ''}`}
          viewBox="0 0 20 20" fill="currentColor"
        >
          <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clipRule="evenodd" />
        </svg>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-200 truncate">{description || name}</span>
            <StatusBadge status={status} error={error} />
            {elapsed_ms != null && (
              <span className="text-xs text-gray-500">{elapsed_ms}ms</span>
            )}
          </div>
          {url && <p className="text-xs text-gray-500 font-mono truncate mt-0.5">{url}</p>}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-700 px-4 py-3">
          {note && <p className="text-xs text-yellow-400 mb-2">{note}</p>}
          {error ? (
            <p className="text-xs text-red-400 font-mono break-all">{error}</p>
          ) : (
            <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap break-all max-h-80 overflow-y-auto bg-gray-950 rounded p-3">
              {JSON.stringify(data, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

export default function SettingsDiagnostics() {
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)

  const runDiagnostics = async () => {
    setLoading(true)
    setError(null)
    setResults(null)
    try {
      const data = await runSelfHostedDiagnostics()
      setResults(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const fullJson = results ? JSON.stringify(results, null, 2) : ''

  const handleCopy = () => {
    navigator.clipboard.writeText(fullJson).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {
      setCopied('failed')
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const handleDownload = () => {
    const blob = new Blob([fullJson], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'selfhosted-diagnostics.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  const meta = results?._meta
  const endpointKeys = results
    ? Object.keys(results).filter(k => k !== '_meta').sort()
    : []

  return (
    <div>
      <h2 className="text-sm font-semibold text-gray-300 mb-1 uppercase tracking-wider">
        Self-Hosted Diagnostics
      </h2>
      <p className="text-xs text-gray-500 mb-4">
        Probe API endpoints on your self-hosted controller. Results help us build firewall support.
      </p>

      {/* Run button */}
      {!results && !loading && (
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center">
          <svg className="w-10 h-10 mx-auto text-gray-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          <p className="text-sm text-gray-400 mb-4">
            This will probe ~16 API endpoints on your controller and show the raw responses.
            It may take 15–30 seconds.
          </p>
          <button
            onClick={runDiagnostics}
            className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors"
          >
            Run Diagnostics
          </button>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-8 text-center">
          <div className="inline-block w-8 h-8 border-2 border-gray-600 border-t-blue-400 rounded-full animate-spin mb-3" />
          <p className="text-sm text-gray-400">
            Probing controller API endpoints&hellip;
          </p>
          <p className="text-xs text-gray-500 mt-1">This may take 15–30 seconds</p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 mb-4">
          <p className="text-sm text-red-400">{error}</p>
          <button
            onClick={runDiagnostics}
            className="mt-2 px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Meta info */}
          {meta && (
            <div className="rounded-lg border border-gray-700 bg-gray-950 p-4 mb-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div>
                  <span className="text-gray-500">Controller</span>
                  <p className="text-gray-200 font-medium">{meta.controller_version || 'Unknown'}</p>
                </div>
                <div>
                  <span className="text-gray-500">Host</span>
                  <p className="text-gray-200 font-mono truncate">{meta.host}</p>
                </div>
                <div>
                  <span className="text-gray-500">Site</span>
                  <p className="text-gray-200">{meta.site_name} ({meta.site_id})</p>
                </div>
                <div>
                  <span className="text-gray-500">SSL Verify</span>
                  <p className="text-gray-200">{meta.verify_ssl ? 'Yes' : 'No'}</p>
                </div>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2 mb-4">
            <button
              onClick={handleCopy}
              className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
            >
              {copied === 'failed' ? 'Copy failed' : copied ? 'Copied!' : 'Copy All JSON'}
            </button>
            <button
              onClick={handleDownload}
              className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
            >
              Download JSON
            </button>
            <button
              onClick={runDiagnostics}
              className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors ml-auto"
            >
              Re-run
            </button>
          </div>

          {/* Endpoint cards */}
          <div className="space-y-2">
            {endpointKeys.map(key => (
              <EndpointCard key={key} name={key} result={results[key]} />
            ))}
          </div>
        </>
      )}
    </div>
  )
}

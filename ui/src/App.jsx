import React, { useState, useEffect } from 'react'
import LogStream from './components/LogStream'
import Dashboard from './components/Dashboard'
import { fetchHealth } from './api'

const TABS = [
  { id: 'logs', label: 'Log Stream' },
  { id: 'dashboard', label: 'Dashboard' },
]

function formatShortDate(isoStr) {
  if (!isoStr) return '—'
  try {
    const d = new Date(isoStr)
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) +
      ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  } catch { return '—' }
}

function formatAbuseIPDB(abuseipdb) {
  if (!abuseipdb) return '—'

  // Check if paused (429 rate limited)
  if (abuseipdb.paused_until) {
    const pausedDate = new Date(abuseipdb.paused_until * 1000)
    if (pausedDate > new Date()) {
      const resumeStr = pausedDate.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
      return `⏸ Paused · Resumes ${resumeStr}`
    }
  }

  const limit = abuseipdb.limit
  const remaining = abuseipdb.remaining
  if (limit == null || remaining == null) return '—'
  const used = limit - remaining
  const reset = abuseipdb.reset_at ? formatShortDate(abuseipdb.reset_at) : '—'
  return `${used.toLocaleString()}/${limit.toLocaleString()} · Reset ${reset}`
}

export default function App() {
  const [activeTab, setActiveTab] = useState('logs')
  const [health, setHealth] = useState(null)

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => {})
    const interval = setInterval(() => {
      fetchHealth().then(setHealth).catch(() => {})
    }, 15000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="h-screen flex flex-col bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-900/50 shrink-0">
        <div className="flex items-center gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
              <span className="text-blue-400 text-xs font-bold">U</span>
            </div>
            <span className="text-sm font-semibold text-gray-200">UniFi Log Insight</span>
          </div>

          {/* Tabs */}
          <nav className="flex items-center gap-0.5 ml-4">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-all ${
                  activeTab === tab.id
                    ? 'bg-gray-800 text-white'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Status */}
        <div className="flex items-center gap-3">
          {health && (
            <>
              <span className="text-[10px] text-gray-600">
                AbuseIPDB: {formatAbuseIPDB(health.abuseipdb)}
              </span>
              <span className="text-[10px] text-gray-700">|</span>
              <span className="text-[10px] text-gray-600">
                MaxMind: {formatShortDate(health.maxmind_last_update)}
              </span>
              <span className="text-[10px] text-gray-700">|</span>
              <span className="text-[10px] text-gray-600">
                Next pull: {formatShortDate(health.maxmind_next_update)}
              </span>
              <span className="text-[10px] text-gray-700">|</span>
              <span className="text-[10px] text-gray-600">
                {health.total_logs?.toLocaleString()} logs
              </span>
              <span className={`w-1.5 h-1.5 rounded-full ${
                health.status === 'ok' ? 'bg-emerald-400' : 'bg-red-400'
              }`} />
            </>
          )}
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 overflow-hidden">
        {activeTab === 'logs' && <LogStream />}
        {activeTab === 'dashboard' && <Dashboard />}
      </main>
    </div>
  )
}

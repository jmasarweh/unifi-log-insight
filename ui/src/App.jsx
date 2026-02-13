import React, { Suspense, useState, useEffect } from 'react'
import LogStream from './components/LogStream'
import SetupWizard from './components/SetupWizard'
import { DashboardSkeleton } from './components/Dashboard'

const Dashboard = React.lazy(() => import('./components/Dashboard'))
import { fetchHealth, fetchConfig, fetchLatestRelease } from './api'
import { loadInterfaceLabels } from './utils'

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
  // reset_at from AbuseIPDB is a Unix timestamp (seconds), not ISO string
  let reset = '—'
  if (abuseipdb.reset_at) {
    const ts = Number(abuseipdb.reset_at)
    const d = !isNaN(ts) && ts > 1e9 ? new Date(ts * 1000) : new Date(abuseipdb.reset_at)
    reset = isNaN(d.getTime()) ? '—' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) +
      ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  }
  return `${used.toLocaleString()}/${limit.toLocaleString()} · Reset ${reset}`
}

export default function App() {
  const [activeTab, setActiveTab] = useState('logs')
  const [health, setHealth] = useState(null)
  const [latestRelease, setLatestRelease] = useState(null)
  const [showWizard, setShowWizard] = useState(false)
  const [showReconfig, setShowReconfig] = useState(false)
  const [config, setConfig] = useState(null)
  const [configLoaded, setConfigLoaded] = useState(false)
  const [showMigrationBanner, setShowMigrationBanner] = useState(false)

  // Load config + interface labels in a single fetch
  useEffect(() => {
    let mounted = true
    fetchConfig()
      .then(cfg => {
        if (!mounted) return
        setConfig(cfg)
        loadInterfaceLabels(cfg)
        if (cfg.setup_complete === false) {
          setShowWizard(true)
        }
        // Check for auto-migrated users (empty labels = defaults)
        if (cfg.setup_complete !== false &&
            Object.keys(cfg.interface_labels || {}).length === 0 &&
            !localStorage.getItem('migration_banner_dismissed')) {
          setShowMigrationBanner(true)
        }
        setConfigLoaded(true)
      })
      .catch(err => {
        console.error('Config load failed:', err)
        if (mounted) setConfigLoaded(true) // show app, not infinite loading
      })
    return () => { mounted = false }
  }, [])

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => {})
    const interval = setInterval(() => {
      fetchHealth().then(setHealth).catch(() => {})
    }, 15000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const cached = sessionStorage.getItem('latest_release')
    if (cached) {
      try {
        const { data, ts } = JSON.parse(cached)
        if (Date.now() - ts < 3600000) { setLatestRelease(data); return }
      } catch { /* ignore */ }
    }
    fetchLatestRelease().then(release => {
      if (release) {
        setLatestRelease(release)
        sessionStorage.setItem('latest_release', JSON.stringify({ data: release, ts: Date.now() }))
      }
    })
  }, [])

  if (!configLoaded) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-950 text-gray-300 text-sm">
        Loading configuration...
      </div>
    )
  }

  // Show setup wizard if not configured
  if (showWizard) {
    return <SetupWizard onComplete={() => {
      fetchConfig().then(cfg => {
        setConfig(cfg)
        loadInterfaceLabels(cfg)
      }).catch(() => {})
      setShowWizard(false)
    }} />
  }

  // Show reconfigure wizard as overlay
  if (showReconfig) {
    return <SetupWizard
      reconfigMode
      onComplete={() => {
        fetchConfig().then(cfg => {
          setConfig(cfg)
          loadInterfaceLabels(cfg)
        }).catch(() => {})
        setShowReconfig(false)
      }}
      onCancel={() => setShowReconfig(false)}
    />
  }

  return (
    <div className="h-screen flex flex-col bg-gray-950">
      {/* Migration banner */}
      {showMigrationBanner && (
        <div className="flex items-center justify-between px-4 py-2 bg-blue-500/10 border-b border-blue-500/30 text-xs text-blue-400">
          <span>
            Your network configuration was auto-detected with default settings. Click the
            <button
              onClick={() => { setShowMigrationBanner(false); setShowReconfig(true) }}
              className="underline mx-1 hover:text-blue-300"
            >
              Settings
            </button>
            gear to review and customize interface labels.
          </span>
          <button
            onClick={() => {
              setShowMigrationBanner(false)
              localStorage.setItem('migration_banner_dismissed', '1')
            }}
            className="text-blue-400 hover:text-blue-300 ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {/* Header */}
      <header className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-900/50 shrink-0">
        <div className="flex items-center gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <svg viewBox="0 0 24 24" className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor">
              <circle cx="12" cy="12" r="10.5" strokeWidth="1.5" strokeOpacity="0.4" />
              <path d="M8.5 7.5v5.5a3.5 3.5 0 0 0 7 0V7.5" strokeWidth="2.2" strokeLinecap="round" />
            </svg>
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
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Status + Settings gear */}
        <div className="flex items-center gap-3">
          {health && (
            <>
              <span className="text-[10px] text-gray-400">
                AbuseIPDB: {formatAbuseIPDB(health.abuseipdb)}
              </span>
              <span className="text-[10px] text-gray-600">|</span>
              <span className="text-[10px] text-gray-400">
                MaxMind: {formatShortDate(health.maxmind_last_update)}
              </span>
              <span className="text-[10px] text-gray-600">|</span>
              <span className="text-[10px] text-gray-400">
                Next pull: {formatShortDate(health.maxmind_next_update)}
              </span>
              <span className="text-[10px] text-gray-600">|</span>
              <span className="text-[10px] text-gray-400">
                {health.total_logs?.toLocaleString()} logs
              </span>
              <span className={`w-1.5 h-1.5 rounded-full ${
                health.status === 'ok' ? 'bg-emerald-400' : 'bg-red-400'
              }`} />
            </>
          )}
          <button
            onClick={() => setShowReconfig(true)}
            className="ml-2 p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
            title="Network Settings"
          >
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
              <path fillRule="evenodd" d="M7.84 1.804A1 1 0 0 1 8.82 1h2.36a1 1 0 0 1 .98.804l.331 1.652a6.993 6.993 0 0 1 1.929 1.115l1.598-.54a1 1 0 0 1 1.186.447l1.18 2.044a1 1 0 0 1-.205 1.251l-1.267 1.113a7.047 7.047 0 0 1 0 2.228l1.267 1.113a1 1 0 0 1 .206 1.25l-1.18 2.045a1 1 0 0 1-1.187.447l-1.598-.54a6.993 6.993 0 0 1-1.929 1.115l-.33 1.652a1 1 0 0 1-.98.804H8.82a1 1 0 0 1-.98-.804l-.331-1.652a6.993 6.993 0 0 1-1.929-1.115l-1.598.54a1 1 0 0 1-1.186-.447l-1.18-2.044a1 1 0 0 1 .205-1.251l1.267-1.114a7.05 7.05 0 0 1 0-2.227L1.821 7.773a1 1 0 0 1-.206-1.25l1.18-2.045a1 1 0 0 1 1.187-.447l1.598.54A6.992 6.992 0 0 1 7.51 3.456l.33-1.652ZM10 13a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" clipRule="evenodd" />
            </svg>
          </button>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 overflow-hidden">
        {activeTab === 'logs' && <LogStream version={health?.version} latestRelease={latestRelease} />}
        <Suspense fallback={<DashboardSkeleton />}>
          {activeTab === 'dashboard' && <Dashboard />}
        </Suspense>
      </main>
    </div>
  )
}

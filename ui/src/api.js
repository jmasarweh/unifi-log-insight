const BASE = '/api'

export async function fetchLogs(params = {}) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v)
  }
  const resp = await fetch(`${BASE}/logs?${qs}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchLog(id) {
  const resp = await fetch(`${BASE}/logs/${id}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchStats(timeRange = '24h') {
  const resp = await fetch(`${BASE}/stats?time_range=${timeRange}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchHealth() {
  const resp = await fetch(`${BASE}/health`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchAbuseIPDBStatus() {
  const resp = await fetch(`${BASE}/abuseipdb/status`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function enrichIP(ip) {
  const resp = await fetch(`${BASE}/enrich/${encodeURIComponent(ip)}`, { method: 'POST' })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function fetchServices() {
  const resp = await fetch(`${BASE}/services`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export function getExportUrl(params = {}) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v)
  }
  return `${BASE}/export?${qs}`
}

// ── Setup Wizard API ──────────────────────────────────────────────────────────

export async function fetchConfig() {
  const resp = await fetch(`${BASE}/config`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchWANCandidates() {
  const resp = await fetch(`${BASE}/setup/wan-candidates`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchNetworkSegments(wanInterfaces = []) {
  const qs = wanInterfaces.length ? `?wan_interfaces=${wanInterfaces.join(',')}` : ''
  const resp = await fetch(`${BASE}/setup/network-segments${qs}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function saveSetupConfig(config) {
  const resp = await fetch(`${BASE}/setup/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchInterfaces() {
  const resp = await fetch(`${BASE}/interfaces`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── Version Check ────────────────────────────────────────────────────────────

export async function fetchLatestRelease() {
  const resp = await fetch(
    'https://api.github.com/repos/jmasarweh/unifi-log-insight/releases/latest'
  )
  if (!resp.ok) return null
  const data = await resp.json()
  return { tag: data.tag_name, url: data.html_url, body: data.body || '' }
}

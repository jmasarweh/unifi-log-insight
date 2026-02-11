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

export function getExportUrl(params = {}) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v)
  }
  return `${BASE}/export?${qs}`
}

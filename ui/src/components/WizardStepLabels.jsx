import React, { useState, useEffect, useRef, useMemo } from 'react'
import { fetchNetworkSegments } from '../api'

function isLocalIP(ip) {
  if (!ip) return false
  // IPv6 private/reserved ranges
  if (ip.includes(':')) {
    const lower = ip.toLowerCase()
    if (lower === '::1' || lower === '::') return true
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true
    if (lower.startsWith('fe80')) return true
    if (lower.startsWith('ff')) return true
    return false
  }
  // IPv4
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(p => isNaN(p))) return false
  const [a, b] = parts
  // RFC1918
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  // Loopback (127.0.0.0/8)
  if (a === 127) return true
  // Link-local (169.254.0.0/16)
  if (a === 169 && b === 254) return true
  // Carrier-grade NAT (100.64.0.0/10 → 100.64–127.x.x)
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

const LABEL_REGEX = /[^a-zA-Z0-9 _-]/g

function vlanIdToInterface(id) {
  if (id === 1) return 'br0'
  if (id >= 2 && id <= 4094) return `br${id}`
  return null
}

function getVlanId(iface) {
  if (iface === 'br0') return 1
  const match = iface.match(/^br(\d+)$/)
  return match ? parseInt(match[1]) : null
}

export default function WizardStepLabels({ wanInterfaces, labels, onUpdate, onNext, onBack }) {
  const [segments, setSegments] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [vlanId, setVlanId] = useState('')
  const [vlanLabel, setVlanLabel] = useState('')
  const initializedRef = useRef(false)

  useEffect(() => {
    if (initializedRef.current) return
    initializedRef.current = true
    fetchNetworkSegments(wanInterfaces || [])
      .then(data => {
        const segs = data.segments || []

        // Re-add manually-added interfaces from saved labels that the API didn't return
        const discoveredSet = new Set(segs.map(s => s.interface))
        const wanSet = new Set(wanInterfaces || [])
        for (const iface of Object.keys(labels)) {
          if (!discoveredSet.has(iface) && !wanSet.has(iface) && /^br\d+$/.test(iface)) {
            segs.push({ interface: iface, sample_local_ip: null, suggested_label: '', is_wan: false, manual: true })
          }
        }
        setSegments(segs)

        // Pre-populate labels with suggested values if not already set
        const initial = { ...labels }
        let changed = false
        for (const seg of segs) {
          if (seg.suggested_label && !initial[seg.interface]) {
            initial[seg.interface] = seg.suggested_label
            changed = true
          }
        }
        if (changed) onUpdate(initial)

        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [wanInterfaces, onUpdate])

  const handleLabelChange = (iface, value) => {
    // Strip disallowed characters
    const sanitized = value.replace(LABEL_REGEX, '')
    onUpdate({ ...labels, [iface]: sanitized })
  }

  // Detect duplicate labels
  const duplicateLabels = useMemo(() => {
    const seen = {}
    const dupes = new Set()
    for (const [iface, label] of Object.entries(labels)) {
      if (!label || !label.trim()) continue
      const normalized = label.trim().toLowerCase()
      if (seen[normalized]) {
        dupes.add(seen[normalized])
        dupes.add(iface)
      } else {
        seen[normalized] = iface
      }
    }
    return dupes
  }, [labels])

  const handleAddVlan = () => {
    const id = parseInt(vlanId)
    const iface = vlanIdToInterface(id)
    if (!iface) return
    if (segments.some(s => s.interface === iface)) return
    setSegments(prev => [...prev, { interface: iface, sample_local_ip: null, suggested_label: '', is_wan: false, manual: true }])
    // Set label immediately if provided
    const trimmedLabel = vlanLabel.replace(LABEL_REGEX, '').trim()
    if (trimmedLabel) {
      onUpdate({ ...labels, [iface]: trimmedLabel })
    }
    setVlanId('')
    setVlanLabel('')
  }

  const isValidVlanId = () => {
    const id = parseInt(vlanId)
    if (isNaN(id) || id < 1 || id > 4094) return false
    const iface = vlanIdToInterface(id)
    return iface && !segments.some(s => s.interface === iface)
  }

  const handleRemoveManualInterface = (iface) => {
    setSegments(prev => prev.filter(s => s.interface !== iface))
    const updated = { ...labels }
    delete updated[iface]
    onUpdate(updated)
  }

  const hasValidationErrors = duplicateLabels.size > 0

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-200 mb-2">Label your network interfaces</h2>
        <p className="text-sm text-gray-300">
          Give each interface a friendly name so the UI shows "IoT" instead
          of "br20". Suggested labels are pre-filled. Edit or clear any field.
        </p>
      </div>

      {loading && (
        <div className="text-center py-12 text-gray-400">
          Discovering network interfaces...
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <p className="text-sm text-red-400">Failed to load network segments: {error}</p>
        </div>
      )}

      {!loading && !error && segments.length === 0 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
          <p className="text-sm text-yellow-400">No network interfaces found. Make sure logs are being received.</p>
        </div>
      )}

      {!loading && !error && segments.length > 0 && (
        <div className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left text-xs font-medium text-gray-300 px-4 py-3">Interface</th>
                <th className="text-left text-xs font-medium text-gray-300 px-4 py-3">Sample IP</th>
                <th className="text-left text-xs font-medium text-gray-300 px-4 py-3">Label</th>
              </tr>
            </thead>
            <tbody>
              {segments.map((seg, idx) => (
                <tr key={seg.interface} className={`border-b border-gray-800/50 ${idx % 2 === 0 ? 'bg-gray-800/20' : ''}`}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono text-gray-300">{seg.interface}</span>
                      {seg.is_wan && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                          WAN
                        </span>
                      )}
                      {getVlanId(seg.interface) !== null && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30">
                          VLAN {getVlanId(seg.interface)}
                        </span>
                      )}
                      {seg.manual && (
                        <button
                          onClick={() => handleRemoveManualInterface(seg.interface)}
                          className="text-gray-500 hover:text-red-400 text-xs transition-colors"
                          title="Remove"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-gray-400">
                        {seg.sample_local_ip || '—'}
                      </span>
                      {seg.sample_local_ip && isLocalIP(seg.sample_local_ip) && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                          Local
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div>
                      <input
                        type="text"
                        maxLength={20}
                        value={labels[seg.interface] || ''}
                        onChange={(e) => handleLabelChange(seg.interface, e.target.value)}
                        placeholder={seg.suggested_label || 'e.g., Main LAN, IoT, Guest'}
                        className={`w-full px-3 py-1.5 bg-gray-800 border rounded text-sm text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
                          duplicateLabels.has(seg.interface) ? 'border-yellow-500/50' : 'border-gray-700'
                        }`}
                      />
                      {duplicateLabels.has(seg.interface) && (
                        <p className="text-[11px] text-yellow-400 mt-1">Duplicate label</p>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add VLAN interface */}
      {!loading && !error && (
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-2">Add VLAN interface</h3>
          <p className="text-xs text-gray-400 mb-3">
            If a VLAN isn't listed above (no logs yet), enter its ID and label.
            VLAN 1 maps to br0, all others map to br&lt;ID&gt;.
          </p>
          <div className="flex items-center gap-3">
            <input
              type="number"
              min={1}
              max={4094}
              value={vlanId}
              onChange={(e) => setVlanId(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddVlan()}
              placeholder="VLAN ID"
              className="w-28 px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm font-mono text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            />
            {vlanId && vlanIdToInterface(parseInt(vlanId)) && (
              <span className="text-xs font-mono text-gray-400 shrink-0">
                {vlanIdToInterface(parseInt(vlanId))}
              </span>
            )}
            <input
              type="text"
              maxLength={20}
              value={vlanLabel}
              onChange={(e) => setVlanLabel(e.target.value.replace(LABEL_REGEX, ''))}
              onKeyDown={(e) => e.key === 'Enter' && handleAddVlan()}
              placeholder="Label (e.g., IoT, Guest)"
              className="flex-1 max-w-xs px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            />
            <button
              onClick={handleAddVlan}
              disabled={!isValidVlanId()}
              className={`px-4 py-1.5 rounded font-medium text-sm transition-all ${
                isValidVlanId()
                  ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              Add
            </button>
          </div>
        </div>
      )}

      {!loading && !error && (
        <div className="flex justify-between">
          <button
            onClick={onBack}
            className="px-6 py-2.5 rounded-lg font-medium text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 transition-all"
          >
            Back
          </button>
          <button
            onClick={onNext}
            disabled={hasValidationErrors}
            className={`px-6 py-2.5 rounded-lg font-medium text-sm transition-all ${
              hasValidationErrors
                ? 'bg-gray-800 text-gray-400 cursor-not-allowed'
                : 'bg-blue-500 hover:bg-blue-600 text-white'
            }`}
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}

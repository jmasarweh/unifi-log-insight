import React, { useState } from 'react'
import { saveSetupConfig } from '../api'

export default function WizardStepSummary({ wanInterfaces, interfaceLabels, onComplete, onBack }) {
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleComplete = async () => {
    setSaving(true)
    setError(null)

    try {
      await saveSetupConfig({
        wan_interfaces: wanInterfaces,
        interface_labels: interfaceLabels,
      })
      // Success - trigger completion callback
      onComplete()
    } catch (err) {
      setError(err.message)
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-200 mb-2">Step 3: Summary</h2>
        <p className="text-sm text-gray-300">
          Review your configuration before completing setup.
        </p>
      </div>

      {/* WAN Interfaces */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">WAN Interfaces</h3>
        {wanInterfaces.length === 0 ? (
          <p className="text-sm text-gray-400">None selected</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {wanInterfaces.map(iface => (
              <span key={iface} className="px-3 py-1.5 bg-blue-500/10 border border-blue-500/30 rounded text-sm font-mono text-blue-400">
                {iface}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Interface Labels */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Interface Labels</h3>
        {Object.keys(interfaceLabels).length === 0 ? (
          <p className="text-sm text-gray-400">No custom labels (using raw interface names)</p>
        ) : (
          <div className="space-y-2">
            {Object.entries(interfaceLabels).map(([iface, label]) => (
              label && (
                <div key={iface} className="flex items-center justify-between py-2 border-b border-gray-800/50 last:border-0">
                  <span className="text-sm font-mono text-gray-300">{iface}</span>
                  <span className="text-sm text-gray-300">{label}</span>
                </div>
              )
            ))}
          </div>
        )}
      </div>

      {/* API key note */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
        <p className="text-xs text-gray-400">
          AbuseIPDB and MaxMind API keys are configured via environment variables
          in docker-compose.yml. See documentation for setup.
        </p>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <p className="text-sm text-red-400">Failed to save configuration: {error}</p>
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-between">
        <button
          onClick={onBack}
          disabled={saving}
          className={`px-6 py-2.5 rounded-lg font-medium text-sm transition-all ${
            saving
              ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
              : 'bg-gray-800 hover:bg-gray-700 text-gray-300'
          }`}
        >
          ← Back
        </button>
        <button
          onClick={handleComplete}
          disabled={saving || wanInterfaces.length === 0}
          className={`px-6 py-2.5 rounded-lg font-medium text-sm transition-all ${
            saving
              ? 'bg-blue-500/50 text-white cursor-wait'
              : wanInterfaces.length === 0
              ? 'bg-gray-800 text-gray-400 cursor-not-allowed'
              : 'bg-emerald-500 hover:bg-emerald-600 text-white'
          }`}
        >
          {saving ? 'Saving...' : 'Complete Setup ✓'}
        </button>
      </div>
    </div>
  )
}

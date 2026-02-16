import React, { useState, useEffect } from 'react'
import UniFiConnectionForm from './UniFiConnectionForm'
import WizardStepWAN from './WizardStepWAN'
import WizardStepLabels from './WizardStepLabels'
import FirewallRules from './FirewallRules'
import { fetchConfig, fetchUniFiNetworkConfig, fetchUniFiSettings, saveSetupConfig } from '../api'

const LABEL_REGEX = /[^a-zA-Z0-9 _-]/g

export default function SetupWizard({ onComplete, reconfigMode, onCancel }) {
  const [step, setStep] = useState(1)
  const [wizardPath, setWizardPath] = useState(null) // 'unifi_api' or 'log_detection'
  const [wanInterfaces, setWanInterfaces] = useState([])
  const [interfaceLabels, setInterfaceLabels] = useState({})
  const [loading, setLoading] = useState(!!reconfigMode)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState(null)
  const [envApiKey, setEnvApiKey] = useState(false)
  const [envHost, setEnvHost] = useState('')
  const [savedHost, setSavedHost] = useState('')
  const [savedApiKey, setSavedApiKey] = useState(false)
  const [settingsLoaded, setSettingsLoaded] = useState(false)

  // Full network config from UniFi API (for API-path steps 2-3)
  const [apiNetConfig, setApiNetConfig] = useState(null)

  // Pre-populate with current config in reconfigure mode
  useEffect(() => {
    if (!reconfigMode) return
    fetchConfig()
      .then(cfg => {
        setWanInterfaces(cfg.wan_interfaces || [])
        setInterfaceLabels(cfg.interface_labels || {})
        if (cfg.unifi_enabled) setWizardPath('unifi_api')
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [reconfigMode])

  // Detect env vars on mount
  useEffect(() => {
    fetchUniFiSettings().then(settings => {
      if (settings.api_key_source === 'env') setEnvApiKey(true)
      else if (settings.api_key_set) setSavedApiKey(true)
      if (settings.host_source === 'env') setEnvHost(settings.host)
      if (settings.host && settings.host_source !== 'env') setSavedHost(settings.host)
      setSettingsLoaded(true)
    }).catch(() => setSettingsLoaded(true))
  }, [])

  const getSteps = () => {
    if (wizardPath === 'unifi_api') {
      return [
        { num: 1, label: 'UniFi Connection' },
        { num: 2, label: 'WAN Configuration' },
        { num: 3, label: 'Network Labels' },
        { num: 4, label: 'Firewall Rules' },
      ]
    }
    if (wizardPath === 'log_detection') {
      return [
        { num: 1, label: 'UniFi Connection' },
        { num: 2, label: 'WAN Detection' },
        { num: 3, label: 'Network Labels' },
      ]
    }
    // Before path is chosen
    return [
      { num: 1, label: 'UniFi Connection' },
      { num: 2, label: 'WAN Config' },
      { num: 3, label: 'Network Labels' },
    ]
  }

  const steps = getSteps()
  const handleBack = () => setStep(s => Math.max(s - 1, 1))

  // Step 1: UniFi connection success
  const handleUniFiSuccess = async () => {
    setWizardPath('unifi_api')

    // Auto-populate WAN + Networks from API
    try {
      const netConfig = await fetchUniFiNetworkConfig()
      setApiNetConfig(netConfig)
      if (netConfig.wan_interfaces?.length) {
        // Only select active WANs (those with a wan_ip); inactive WANs shown dimmed
        setWanInterfaces(
          netConfig.wan_interfaces.filter(w => w.active || w.wan_ip).map(w => w.physical_interface)
        )
        const newLabels = { ...interfaceLabels }
        const totalWans = netConfig.wan_interfaces.length
        netConfig.wan_interfaces.forEach((w, idx) => {
          newLabels[w.physical_interface] = totalWans === 1 ? 'WAN' : `WAN ${idx + 1}`
        })
        for (const n of netConfig.networks || []) {
          newLabels[n.interface] = n.name || n.interface
        }
        setInterfaceLabels(newLabels)
      }
    } catch (err) {
      console.error('Failed to fetch network config:', err)
    }

    setStep(2)
  }

  // Step 1: Skip to log detection
  const handleSkip = () => {
    setWizardPath('log_detection')
    setStep(2)
  }

  // API path: update a WAN physical interface name
  const handleApiWanInterfaceChange = (idx, value) => {
    if (idx < 0 || idx >= wanInterfaces.length) return
    const oldIface = wanInterfaces[idx]
    const newIface = value.trim()
    if (!newIface || newIface === oldIface) return
    // Update wanInterfaces list
    const updated = [...wanInterfaces]
    updated[idx] = newIface
    setWanInterfaces(updated)
    // Move label from old key to new key
    const newLabels = { ...interfaceLabels }
    if (newLabels[oldIface]) {
      newLabels[newIface] = newLabels[oldIface]
      delete newLabels[oldIface]
    }
    setInterfaceLabels(newLabels)
  }

  // API path: update a network label
  const handleApiNetworkLabelChange = (iface, value) => {
    setInterfaceLabels(prev => ({ ...prev, [iface]: value.replace(LABEL_REGEX, '') }))
  }

  // Final step: save and complete
  const handleFinish = async () => {
    setSaving(true)
    setSaveError(null)
    try {
      // wanInterfaces already only contains active WANs (inactive excluded at selection time)
      await saveSetupConfig({
        wan_interfaces: wanInterfaces,
        interface_labels: interfaceLabels,
        wizard_path: wizardPath,
      })
      onComplete()
    } catch (err) {
      setSaveError(err.message)
      setSaving(false)
    }
  }

  return (
    <div className="h-screen flex flex-col bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950 shrink-0">
        <div className="flex items-center gap-3">
          <svg viewBox="0 0 24 24" className="w-7 h-7 text-blue-400" fill="none" stroke="currentColor">
            <circle cx="12" cy="12" r="10.5" strokeWidth="1.5" strokeOpacity="0.4" />
            <path d="M8.5 7.5v5.5a3.5 3.5 0 0 0 7 0V7.5" strokeWidth="2.2" strokeLinecap="round" />
          </svg>
          <div>
            <h1 className="text-lg font-semibold text-gray-200">UniFi Log Insight</h1>
            <p className="text-xs text-gray-400">{reconfigMode ? 'Reconfigure' : 'Setup Wizard'}</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Step Indicator */}
          <div className="flex items-center gap-2">
            {steps.map((s, idx) => (
              <React.Fragment key={s.num}>
                <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${
                  step === s.num
                    ? 'bg-blue-500/10 border-blue-500/30 text-blue-400'
                    : step > s.num
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-gray-800/50 border-gray-700 text-gray-400'
                }`}>
                  <span className="text-xs font-medium">{s.num}</span>
                  <span className="text-xs hidden sm:inline">{s.label}</span>
                </div>
                {idx < steps.length - 1 && (
                  <div className="w-6 h-px bg-gray-700" />
                )}
              </React.Fragment>
            ))}
          </div>

          {/* Cancel button in reconfigure mode */}
          {reconfigMode && onCancel && (
            <button
              onClick={onCancel}
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-gray-300 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 transition-colors"
            >
              Cancel
            </button>
          )}
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 overflow-auto">
        <div className="max-w-6xl mx-auto py-8 px-6">
          {(loading || !settingsLoaded) ? (
            <div className="text-center py-12 text-gray-400 text-sm">Loading current configuration...</div>
          ) : (
            <>
              {/* Step 1: UniFi Connection */}
              {step === 1 && (
                <UniFiConnectionForm
                  onSuccess={handleUniFiSuccess}
                  onSkip={handleSkip}
                  envApiKey={envApiKey}
                  envHost={envHost}
                  savedHost={savedHost}
                  savedApiKey={savedApiKey}
                />
              )}

              {/* Step 2: WAN Configuration (API path) */}
              {step === 2 && wizardPath === 'unifi_api' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-xl font-semibold text-gray-200 mb-2">WAN Configuration</h2>
                    <p className="text-sm text-gray-300">
                      These WAN interfaces were auto-detected from your UniFi Controller.
                      Verify the physical interface names are correct.
                    </p>
                  </div>

                  <div className="px-3 py-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400">
                    Auto-detected from UniFi Controller
                  </div>

                  <div className="space-y-3">
                    {(apiNetConfig?.wan_interfaces || []).map((w) => {
                      const isActive = w.active || !!w.wan_ip
                      const wanIdx = wanInterfaces.indexOf(w.physical_interface)
                      return (
                        <div key={w.physical_interface} className="p-4 rounded-lg border border-gray-700">
                          <div className="flex items-center gap-3 mb-3">
                            <input
                              type="checkbox"
                              readOnly
                              checked={isActive}
                              disabled={!isActive}
                              className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-blue-500 pointer-events-none"
                            />
                            <span className="text-sm font-semibold text-gray-200">{w.name.replace(/\s*\(WAN\d*\)\s*$/i, '')}</span>
                            {interfaceLabels[w.physical_interface] && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30 shrink-0">
                                {interfaceLabels[w.physical_interface]}
                              </span>
                            )}
                            {w.wan_ip && (
                              <span className="text-xs font-mono text-gray-400">{w.wan_ip}</span>
                            )}
                            {!isActive && (
                              <span className="text-xs text-yellow-400/80">(inactive)</span>
                            )}
                          </div>
                          <div className="flex items-center gap-4 ml-7 text-xs text-gray-400">
                            <span>Type: {w.type || 'unknown'}</span>
                            {isActive && (
                              <>
                                <span>|</span>
                                <div className="flex items-center gap-2">
                                  <label className="text-gray-400">Interface:</label>
                                  <input
                                    type="text"
                                    value={wanIdx >= 0 ? wanInterfaces[wanIdx] : w.physical_interface}
                                    onChange={e => handleApiWanInterfaceChange(wanIdx, e.target.value)}
                                    className="w-24 px-2 py-1 rounded bg-gray-900 border border-gray-600 font-mono text-xs text-gray-200 focus:border-blue-500 focus:outline-none"
                                  />
                                  <span className="text-gray-500">(auto-detected)</span>
                                </div>
                              </>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>

                  {(!apiNetConfig?.wan_interfaces?.length) && (
                    <div className="text-center py-8 text-gray-400 text-sm">
                      No WAN interfaces detected from your controller.
                    </div>
                  )}

                  {(apiNetConfig?.wan_interfaces || []).some(w => !w.active && !w.wan_ip) && (
                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                      <p className="text-sm text-yellow-400">
                        Inactive WAN interfaces are excluded from labeling. If you activate
                        them later, re-run the setup wizard via Settings &rarr; Reconfigure
                        to label them correctly.
                      </p>
                    </div>
                  )}

                  <div className="flex justify-between pt-2">
                    <button
                      onClick={handleBack}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 transition-all"
                    >
                      Back
                    </button>
                    <button
                      onClick={() => setStep(3)}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-blue-500 hover:bg-blue-600 text-white transition-all"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}

              {/* Step 2: WAN Detection (log detection path) */}
              {step === 2 && wizardPath === 'log_detection' && (
                <WizardStepWAN
                  selected={wanInterfaces}
                  onSelect={setWanInterfaces}
                  interfaceLabels={interfaceLabels}
                  onUpdateLabels={setInterfaceLabels}
                  onNext={() => setStep(3)}
                  onBack={handleBack}
                  reconfigMode={reconfigMode}
                />
              )}

              {/* Step 3: Network Labels (API path) */}
              {step === 3 && wizardPath === 'unifi_api' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-xl font-semibold text-gray-200 mb-2">Network Labels</h2>
                    <p className="text-sm text-gray-300">
                      These networks were auto-detected from your UniFi Controller.
                      Labels are editable &mdash; these names appear in the UI.
                    </p>
                  </div>

                  <div className="px-3 py-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400">
                    Auto-detected from UniFi Controller &mdash; labels are editable
                  </div>

                  <div className="overflow-hidden rounded-lg border border-gray-700">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-xs text-gray-400">
                          <th className="px-4 py-2 text-left font-medium">Interface</th>
                          <th className="px-4 py-2 text-left font-medium">Sample IP</th>
                          <th className="px-4 py-2 text-left font-medium">Label</th>
                        </tr>
                      </thead>
                      <tbody>
                        {/* Active WAN interfaces */}
                        {(apiNetConfig?.wan_interfaces || []).filter(w => w.wan_ip).map((w, activeIdx) => {
                          const iface = w.physical_interface
                          return (
                            <tr key={iface} className="border-t border-gray-800">
                              <td className="px-4 py-2.5">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-gray-300">{iface}</span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                                    WAN
                                  </span>
                                </div>
                              </td>
                              <td className="px-4 py-2.5 font-mono text-xs text-gray-400">{w.wan_ip}</td>
                              <td className="px-4 py-2.5">
                                <input
                                  type="text"
                                  maxLength={20}
                                  value={interfaceLabels[iface] || ''}
                                  onChange={e => handleApiNetworkLabelChange(iface, e.target.value)}
                                  placeholder={(apiNetConfig?.wan_interfaces || []).filter(x => x.wan_ip).length === 1 ? 'e.g., WAN' : `e.g., WAN ${activeIdx + 1}`}
                                  className="w-32 px-2 py-1 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                                />
                              </td>
                            </tr>
                          )
                        })}
                        {/* LAN / VLAN networks */}
                        {(apiNetConfig?.networks || []).map(n => (
                          <tr key={n.interface} className="border-t border-gray-800">
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-gray-300">{n.interface}</span>
                                {n.vlan != null && (
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30">
                                    VLAN {n.vlan}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-xs text-gray-400">
                              {n.ip_subnet?.split('/')[0] || '\u2014'}
                            </td>
                            <td className="px-4 py-2.5">
                              <input
                                type="text"
                                maxLength={20}
                                value={interfaceLabels[n.interface] || ''}
                                onChange={e => handleApiNetworkLabelChange(n.interface, e.target.value)}
                                className="w-32 px-2 py-1 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 focus:border-blue-500 focus:outline-none"
                              />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {(!apiNetConfig?.networks?.length) && (
                    <div className="text-center py-8 text-gray-400 text-sm">
                      No networks detected from your controller.
                    </div>
                  )}

                  <div className="flex justify-between pt-2">
                    <button
                      onClick={handleBack}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 transition-all"
                    >
                      Back
                    </button>
                    <button
                      onClick={() => setStep(4)}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-blue-500 hover:bg-blue-600 text-white transition-all"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}

              {/* Step 3: Network Labels (log detection path) */}
              {step === 3 && wizardPath === 'log_detection' && (
                <div>
                  <WizardStepLabels
                    wanInterfaces={wanInterfaces}
                    labels={interfaceLabels}
                    onUpdate={setInterfaceLabels}
                    onNext={handleFinish}
                    onBack={handleBack}
                    nextLabel={saving ? 'Saving...' : 'Finish'}
                    disabled={saving}
                  />
                  {saveError && (
                    <div className="mt-4 px-3 py-2 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">
                      Failed to save: {saveError}
                    </div>
                  )}
                </div>
              )}

              {/* Step 4: Firewall Rules (API path only) */}
              {step === 4 && wizardPath === 'unifi_api' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-lg font-semibold text-gray-200 mb-1">Firewall Rules Syslog</h2>
                    <p className="text-sm text-gray-400">
                      Enable syslog on firewall rules so they appear in your log dashboard.
                      Rules without syslog enabled will not generate log entries.
                    </p>
                  </div>

                  <div className="flex justify-between">
                    <button
                      onClick={handleBack}
                      disabled={saving}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 transition-all"
                    >
                      Back
                    </button>
                    <button
                      onClick={handleFinish}
                      disabled={saving}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-blue-500 hover:bg-blue-600 text-white disabled:opacity-50 transition-all"
                    >
                      {saving ? 'Saving...' : 'Finish'}
                    </button>
                  </div>

                  <div className="rounded-lg border border-gray-700 p-4">
                    <FirewallRules />
                  </div>

                  {saveError && (
                    <div className="px-3 py-2 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">
                      Failed to save: {saveError}
                    </div>
                  )}

                  <div className="flex justify-between">
                    <button
                      onClick={handleBack}
                      disabled={saving}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 transition-all"
                    >
                      Back
                    </button>
                    <button
                      onClick={handleFinish}
                      disabled={saving}
                      className="px-6 py-2.5 rounded-lg font-medium text-sm bg-blue-500 hover:bg-blue-600 text-white disabled:opacity-50 transition-all"
                    >
                      {saving ? 'Saving...' : 'Finish'}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  )
}

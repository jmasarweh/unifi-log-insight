import React, { useState, useEffect } from 'react'
import WizardStepWAN from './WizardStepWAN'
import WizardStepLabels from './WizardStepLabels'
import WizardStepSummary from './WizardStepSummary'
import { fetchConfig } from '../api'

export default function SetupWizard({ onComplete, reconfigMode, onCancel }) {
  const [step, setStep] = useState(1)
  const [wanInterfaces, setWanInterfaces] = useState([])
  const [interfaceLabels, setInterfaceLabels] = useState({})
  const [loading, setLoading] = useState(!!reconfigMode)

  // Pre-populate with current config in reconfigure mode
  useEffect(() => {
    if (!reconfigMode) return
    fetchConfig()
      .then(cfg => {
        setWanInterfaces(cfg.wan_interfaces || [])
        setInterfaceLabels(cfg.interface_labels || {})
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [reconfigMode])

  const steps = [
    { num: 1, label: 'WAN Detection' },
    { num: 2, label: 'Network Labels' },
    { num: 3, label: 'Summary' },
  ]

  const handleNext = () => setStep(s => Math.min(s + 1, 3))
  const handleBack = () => setStep(s => Math.max(s - 1, 1))

  return (
    <div className="h-screen flex flex-col bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-900/50 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
            <span className="text-blue-400 font-bold">U</span>
          </div>
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
                  <span className="text-xs">{s.label}</span>
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
        <div className="max-w-4xl mx-auto py-8 px-6">
          {loading ? (
            <div className="text-center py-12 text-gray-400 text-sm">Loading current configuration...</div>
          ) : (
            <>
              {step === 1 && (
                <WizardStepWAN
                  selected={wanInterfaces}
                  onSelect={setWanInterfaces}
                  interfaceLabels={interfaceLabels}
                  onUpdateLabels={setInterfaceLabels}
                  onNext={handleNext}
                  reconfigMode={reconfigMode}
                />
              )}
              {step === 2 && (
                <WizardStepLabels
                  wanInterfaces={wanInterfaces}
                  labels={interfaceLabels}
                  onUpdate={setInterfaceLabels}
                  onNext={handleNext}
                  onBack={handleBack}
                />
              )}
              {step === 3 && (
                <WizardStepSummary
                  wanInterfaces={wanInterfaces}
                  interfaceLabels={interfaceLabels}
                  onComplete={onComplete}
                  onBack={handleBack}
                />
              )}
            </>
          )}
        </div>
      </main>
    </div>
  )
}

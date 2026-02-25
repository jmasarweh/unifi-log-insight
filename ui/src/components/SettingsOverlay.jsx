import { useState, useEffect } from 'react'
import { fetchConfig, fetchUniFiSettings, fetchUniFiNetworkConfig } from '../api'
import SettingsWanNetworks from './SettingsWanNetworks'
import SettingsFirewall from './SettingsFirewall'
import SettingsDataBackups from './SettingsDataBackups'
import SettingsUserInterface from './SettingsUserInterface'
import SettingsMCP from './SettingsMCP'
import SetupWizard from './SetupWizard'

function getVlanId(iface) {
  if (iface === 'br0') return 1
  const match = iface.match(/^br(\d+)$/)
  return match ? parseInt(match[1]) : null
}

const BASE_SECTIONS = [
  {
    id: 'wan-networks',
    label: 'WAN & Networks',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM4.332 8.027a6.012 6.012 0 011.912-2.706C6.512 5.73 6.974 6 7.5 6A1.5 1.5 0 019 7.5V8a2 2 0 004 0 2 2 0 011.523-1.943A5.977 5.977 0 0116 10c0 .34-.028.675-.083 1H15a2 2 0 00-2 2v2.197A5.973 5.973 0 0110 16v-2a2 2 0 00-2-2 2 2 0 01-2-2 2 2 0 00-1.668-1.973z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'firewall',
    label: 'Firewall',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'data-backups',
    label: 'Data & Backups',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
        <path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z" />
        <path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z" />
      </svg>
    ),
  },
  {
    id: 'user-interface',
    label: 'User Interface',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path d="M5 4a1 1 0 00-2 0v7.268a2 2 0 000 3.464V16a1 1 0 102 0v-1.268a2 2 0 000-3.464V4zM11 4a1 1 0 10-2 0v1.268a2 2 0 000 3.464V16a1 1 0 102 0V8.732a2 2 0 000-3.464V4zM17 4a1 1 0 10-2 0v7.268a2 2 0 000 3.464V16a1 1 0 102 0v-1.268a2 2 0 000-3.464V4z" />
      </svg>
    ),
  },
  {
    id: 'mcp',
    label: <span className="flex items-center gap-1.5">MCP <span className="text-[10px] px-1 py-0 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">Beta</span></span>,
    icon: (
      <img src="/mcp-logo.png" alt="MCP" className="mcp-logo" />
    ),
  },
]

export default function SettingsOverlay({ onClose, startInReconfig, unlabeledVpn = [], onVpnSaved: onVpnSavedApp }) {
  const [config, setConfig] = useState(null)
  const [unifiSettings, setUnifiSettings] = useState(null)
  const [netConfig, setNetConfig] = useState(null)
  const [activeSection, setActiveSection] = useState('wan-networks')
  const [reconfigMode, setReconfigMode] = useState(!!startInReconfig)
  const [wizardPath, setWizardPath] = useState(null)

  useEffect(() => {
    fetchConfig().then(setConfig).catch(() => {})
    fetchUniFiSettings().then(data => {
      setUnifiSettings(data)
      if (data?.enabled) {
        fetchUniFiNetworkConfig().then(setNetConfig).catch(() => {})
      }
    }).catch(() => {})
  }, [])

  const sections = BASE_SECTIONS

  const savedWanInterfaces = config?.wan_interfaces || []
  const labels = config?.interface_labels || {}
  const unifiEnabled = unifiSettings?.enabled

  // Build WAN cards from ALL live WAN data (includes inactive WANs like WAN2)
  // Fall back to saved config if live data isn't available
  const liveWans = netConfig?.wan_interfaces || []
  const allWanPhysicals = new Set(savedWanInterfaces)
  for (const w of liveWans) allWanPhysicals.add(w.physical_interface)

  const wanCards = liveWans.length > 0
    ? liveWans.map(w => ({
        iface: w.physical_interface,
        name: w.name,
        wanIp: w.wan_ip || null,
        active: w.active,
        type: w.type || null,
      }))
    : savedWanInterfaces.map(iface => ({
        iface,
        name: labels[iface] || iface,
        wanIp: (config?.wan_ip_by_iface || {})[iface] || null,
        active: null,
        type: null,
      }))

  // Network cards: only bridge interfaces (br*) belong in network segments
  const networkCards = Object.entries(labels)
    .filter(([iface]) => iface.startsWith('br'))
    .map(([iface, label]) => {
      const live = netConfig?.networks?.find(n => n.interface === iface)
      return {
        iface,
        label,
        vlanId: live?.vlan ?? getVlanId(iface),
        subnet: live?.ip_subnet || null,
      }
    })

  const handleRestartWizard = () => {
    setReconfigMode(true)
    setWizardPath(null)
    setActiveSection('wan-networks')
  }

  const reloadAll = () => {
    fetchConfig().then(setConfig).catch(() => {})
    fetchUniFiSettings().then(data => {
      setUnifiSettings(data)
      if (data?.enabled) fetchUniFiNetworkConfig().then(setNetConfig).catch(() => {})
    }).catch(() => {})
  }

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950 shrink-0">
        <div className="flex items-center gap-3">
          <svg viewBox="0 0 24 24" className="w-7 h-7 text-blue-400" fill="none" stroke="currentColor">
            <circle cx="12" cy="12" r="10.5" strokeWidth="1.5" strokeOpacity="0.4" />
            <path d="M8.5 7.5v5.5a3.5 3.5 0 0 0 7 0V7.5" strokeWidth="2.2" strokeLinecap="round" />
          </svg>
          <div>
            <h1 className="text-lg font-semibold text-gray-200">UniFi Log Insight</h1>
            {reconfigMode ? (
              <p className="text-xs text-gray-400">
                Settings
                <span className="text-gray-600 mx-1">&rsaquo;</span>
                WAN &amp; Networks
                <span className="text-gray-600 mx-1">&rsaquo;</span>
                <span className="text-gray-300">Reconfigure</span>
                {wizardPath === 'unifi_api' && (
                  <><span className="text-gray-600 mx-1">&rsaquo;</span><span className="text-gray-300">UniFi API</span></>
                )}
                {wizardPath === 'log_detection' && (
                  <><span className="text-gray-600 mx-1">&rsaquo;</span><span className="text-gray-300">Log Detection</span></>
                )}
              </p>
            ) : (
              <p className="text-xs text-gray-400">Settings</p>
            )}
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      </header>

      {/* Sidebar + Content */}
      <main className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <nav className="w-52 shrink-0 border-r border-gray-800 bg-gray-950 py-4 overflow-y-auto">
          {sections.map(section => (
            <button
              key={section.id}
              onClick={() => {
                if (reconfigMode) { setReconfigMode(false); setWizardPath(null) }
                setActiveSection(section.id)
              }}
              className={`w-full flex items-center gap-3 px-5 py-2.5 text-sm transition-colors ${
                activeSection === section.id
                  ? 'bg-gray-800/60 text-white border-r-2 border-blue-500'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/30'
              }`}
            >
              {section.icon}
              {section.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1 overflow-y-auto py-8 px-6">
          <div className="max-w-6xl mx-auto">
            {reconfigMode ? (
              <SetupWizard
                embedded
                reconfigMode
                onComplete={() => {
                  setReconfigMode(false)
                  setWizardPath(null)
                  reloadAll()
                }}
                onCancel={() => { setReconfigMode(false); setWizardPath(null) }}
                onPathChange={setWizardPath}
              />
            ) : (
              <>
                {activeSection === 'wan-networks' && (
                  <SettingsWanNetworks
                    unifiEnabled={unifiEnabled}
                    unifiSettings={unifiSettings}
                    wanCards={wanCards}
                    networkCards={networkCards}
                    onRestartWizard={handleRestartWizard}
                    vpnNetworks={config?.vpn_networks || {}}
                    interfaceLabels={config?.interface_labels || {}}
                    onVpnSaved={() => { fetchConfig().then(cfg => { setConfig(cfg); onVpnSavedApp?.(cfg) }).catch(() => {}) }}
                    unlabeledVpn={unlabeledVpn}
                  />
                )}
                {activeSection === 'firewall' && (
                  <SettingsFirewall
                    unifiEnabled={unifiEnabled}
                    supportsFirewall={unifiSettings?.supports_firewall !== false}
                    onRestartWizard={handleRestartWizard}
                  />
                )}
                {activeSection === 'data-backups' && (
                  <SettingsDataBackups />
                )}
                {activeSection === 'user-interface' && (
                  <SettingsUserInterface />
                )}
                {activeSection === 'mcp' && (
                  <SettingsMCP />
                )}
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}

import { useState, useEffect } from 'react'
import { fetchUiSettings, updateUiSettings } from '../api'

const COUNTRY_OPTIONS = [
  { value: 'flag_name', label: 'Flag + Country Code' },
  { value: 'flag_only', label: 'Flag Only' },
  { value: 'name_only', label: 'Country Code Only' },
]

const SUBLINE_OPTIONS = [
  { value: 'none', label: 'Disabled' },
  { value: 'asn_or_abuse', label: 'ASN (fallback: AbuseIPDB hostname)' },
]

const THEME_OPTIONS = [
  { value: 'dark', label: 'Dark' },
  { value: 'light', label: 'Light' },
]

export default function SettingsUserInterface() {
  const [settings, setSettings] = useState(null)
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [status, setStatus] = useState(null)

  useEffect(() => {
    fetchUiSettings().then(setSettings).catch(() => {})
  }, [])

  const update = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }))
    setDirty(true)
    setStatus(null)
  }

  const handleSave = async () => {
    setSaving(true)
    setStatus(null)
    try {
      await updateUiSettings(settings)
      if (settings.ui_theme) {
        localStorage.setItem('ui_theme', settings.ui_theme)
        document.documentElement.setAttribute('data-theme', settings.ui_theme)
      }
      setDirty(false)
      setStatus('saved')
    } catch {
      setStatus('error')
    } finally {
      setSaving(false)
    }
  }

  if (!settings) return <div className="text-gray-500 text-sm">Loading...</div>

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">User Interface</h2>
        <p className="text-xs text-gray-400 mb-4">Customize how data is displayed in the log view.</p>
      </div>

      {/* Country Display */}
      <section>
        <h3 className="text-sm font-semibold text-gray-300 mb-1">Country Display</h3>
        <p className="text-xs text-gray-500 mb-3">Control how countries appear in Source/Destination columns.</p>
        <div className="space-y-2">
          {COUNTRY_OPTIONS.map(opt => (
            <label key={opt.value} className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="country_display"
                value={opt.value}
                checked={settings.ui_country_display === opt.value}
                onChange={() => update('ui_country_display', opt.value)}
                className="text-teal-500 focus:ring-0 focus:ring-offset-0 bg-gray-800 border-gray-600"
              />
              <span className="text-xs text-gray-300">{opt.label}</span>
            </label>
          ))}
        </div>
      </section>

      {/* IP Subline */}
      <section>
        <h3 className="text-sm font-semibold text-gray-300 mb-1">IP Address Subline</h3>
        <p className="text-xs text-gray-500 mb-3">Show ASN or AbuseIPDB hostname under IP addresses. When enabled, the standalone ASN column is hidden.</p>
        <div className="space-y-2">
          {SUBLINE_OPTIONS.map(opt => (
            <label key={opt.value} className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="ip_subline"
                value={opt.value}
                checked={settings.ui_ip_subline === opt.value}
                onChange={() => update('ui_ip_subline', opt.value)}
                className="text-teal-500 focus:ring-0 focus:ring-offset-0 bg-gray-800 border-gray-600"
              />
              <span className="text-xs text-gray-300">{opt.label}</span>
            </label>
          ))}
        </div>
      </section>

      {/* Theme */}
      <section>
        <h3 className="text-sm font-semibold text-gray-300 mb-1">Theme</h3>
        <p className="text-xs text-gray-500 mb-3">Switch between dark and light mode.</p>
        <div className="space-y-2">
          {THEME_OPTIONS.map(opt => (
            <label key={opt.value} className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="theme"
                value={opt.value}
                checked={settings.ui_theme === opt.value}
                onChange={() => update('ui_theme', opt.value)}
                className="text-teal-500 focus:ring-0 focus:ring-offset-0 bg-gray-800 border-gray-600"
              />
              <span className="text-xs text-gray-300">{opt.label}</span>
            </label>
          ))}
        </div>
      </section>

      {/* Save */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          disabled={!dirty || saving}
          className="px-3 py-1.5 rounded text-xs font-medium bg-teal-600 hover:bg-teal-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
        {status === 'saved' && <span className="text-xs text-emerald-400">Settings saved</span>}
        {status === 'error' && <span className="text-xs text-red-400">Failed to save</span>}
      </div>
    </div>
  )
}

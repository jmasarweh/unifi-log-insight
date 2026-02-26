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
    fetchUiSettings().then(setSettings).catch(err => {
      console.error('Failed to load UI settings:', err)
      setSettings({ ui_country_display: 'flag_name', ui_ip_subline: 'none', ui_theme: 'dark' })
    })
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
    <div className="space-y-8">
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">User Interface</h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          {/* Country Display */}
          <div className="p-5">
            <p className="text-sm text-gray-200 font-medium">Country Display</p>
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
                    className="ui-radio"
                  />
                  <span className="text-xs text-gray-300">{opt.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="border-t border-gray-800" />

          {/* IP Subline */}
          <div className="p-5">
            <p className="text-sm text-gray-200 font-medium">IP Address Subline</p>
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
                    className="ui-radio"
                  />
                  <span className="text-xs text-gray-300">{opt.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="border-t border-gray-800" />

          {/* Theme */}
          <div className="p-5">
            <p className="text-sm text-gray-200 font-medium">Theme</p>
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
                    className="ui-radio"
                  />
                  <span className="text-xs text-gray-300">{opt.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="border-t border-gray-800" />

          <div className="px-5 py-3 flex items-center justify-between">
            <div>
              {status === 'saved' && <span className="text-xs text-emerald-400">Settings saved</span>}
              {status === 'error' && <span className="text-xs text-red-400">Failed to save</span>}
            </div>
            <button
              onClick={handleSave}
              disabled={!dirty || saving}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                dirty
                  ? 'bg-teal-600 hover:bg-teal-500 text-white'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

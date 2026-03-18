import { useEffect, useRef, useState } from 'react'
import { fetchAuthStatus, fetchAuthMe, authChangePassword, authSetup, updateSessionTtl } from '../api'

const INPUT_CLS = 'w-full px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-teal-500'

export default function SettingsSecurity({ onAuthEnabled }) {
  const [authStatus, setAuthStatus] = useState(null)
  const [me, setMe] = useState(null)
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState(null)

  // Change password
  const [showPwChange, setShowPwChange] = useState(false)
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [pwSaving, setPwSaving] = useState(false)

  // Enable auth (first-user setup)
  const [setupUser, setSetupUser] = useState('admin')
  const [setupPw, setSetupPw] = useState('')
  const [setupConfirm, setSetupConfirm] = useState('')
  const [setupSaving, setSetupSaving] = useState(false)

  // Session duration
  const [sessionTtl, setSessionTtl] = useState(168)
  const [ttlSaving, setTtlSaving] = useState(false)

  const flashTimer = useRef(null)

  useEffect(() => { reload() }, [])

  useEffect(() => {
    return () => clearTimeout(flashTimer.current)
  }, [])

  async function reload() {
    setLoading(true)
    try {
      const [status, meResp] = await Promise.allSettled([
        fetchAuthStatus(),
        fetchAuthMe(),
      ])
      if (status.status === 'fulfilled') {
        setAuthStatus(status.value)
        if (status.value.session_ttl_hours) setSessionTtl(status.value.session_ttl_hours)
      }
      if (meResp.status === 'fulfilled') setMe(meResp.value)
    } finally {
      setLoading(false)
    }
  }

  function flash(text, type = 'info') {
    setMessage({ text, type })
    clearTimeout(flashTimer.current)
    flashTimer.current = setTimeout(() => setMessage(null), 4000)
  }

  async function handleChangePassword(e) {
    e.preventDefault()
    if (newPw !== confirmPw) { flash('Passwords do not match', 'error'); return }
    if (newPw.length < 8) { flash('Password must be at least 8 characters', 'error'); return }
    setPwSaving(true)
    try {
      await authChangePassword(currentPw, newPw)
      flash('Password changed successfully', 'success')
      setShowPwChange(false)
      setCurrentPw(''); setNewPw(''); setConfirmPw('')
    } catch (err) {
      flash(err.message || 'Failed to change password', 'error')
    } finally {
      setPwSaving(false)
    }
  }

  async function handleEnableAuth(e) {
    e.preventDefault()
    if (setupPw !== setupConfirm) { flash('Passwords do not match', 'error'); return }
    if (setupPw.length < 8) { flash('Password must be at least 8 characters', 'error'); return }
    if (!setupUser.trim()) { flash('Username is required', 'error'); return }
    setSetupSaving(true)
    try {
      await authSetup(setupUser.trim(), setupPw)
      flash('Authentication enabled — admin account created', 'success')
      setSetupUser(''); setSetupPw(''); setSetupConfirm('')
      onAuthEnabled?.()
      reload()
    } catch (err) {
      flash(err.message || 'Setup failed', 'error')
    } finally {
      setSetupSaving(false)
    }
  }

  async function handleSaveSessionTtl() {
    setTtlSaving(true)
    try {
      await updateSessionTtl(sessionTtl)
      flash('Session duration updated', 'success')
    } catch (err) {
      flash(err.message || 'Failed to update session duration', 'error')
    } finally {
      setTtlSaving(false)
    }
  }

  if (loading) return (
    <div className="space-y-8 animate-pulse">
      <div>
        <div className="h-5 w-40 bg-gray-800 rounded mb-3" />
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5 space-y-3">
          <div className="h-4 w-56 bg-gray-800 rounded" />
          <div className="h-4 w-36 bg-gray-800 rounded" />
        </div>
      </div>
    </div>
  )

  const authEnabled = authStatus?.auth_enabled_effective

  return (
    <div className="space-y-8">
      {message && (
        <div className={`px-4 py-2 rounded text-sm ${
          message.type === 'error' ? 'bg-red-900/40 text-red-300 border border-red-700/50' :
          message.type === 'success' ? 'bg-green-900/40 text-green-300 border border-green-700/50' :
          'bg-blue-900/40 text-blue-300 border border-blue-700/50'
        }`}>
          {message.text}
        </div>
      )}

      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Authentication</h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          {/* Status */}
          <div className="p-5">
            <div className="flex items-center gap-3">
              <span className={`w-2 h-2 rounded-full ${authEnabled ? 'bg-green-500' : 'bg-gray-500'}`} />
              <span className="text-sm text-gray-300">
                {authEnabled ? 'Authentication enabled' : 'Authentication disabled (open access)'}
              </span>
            </div>
          </div>

          {!authEnabled && !authStatus?.has_users && (
            <>
              <div className="border-t border-gray-800" />
              <div className="p-5">
                {authStatus?.is_https ? (
                  <form onSubmit={handleEnableAuth} className="space-y-3 max-w-sm">
                    <p className="text-sm text-gray-500 mb-3">Create an admin account to enable authentication and protect your instance.</p>
                    <input
                      type="text"
                      placeholder="Username"
                      value={setupUser}
                      onChange={e => setSetupUser(e.target.value)}
                      disabled={setupSaving}
                      autoComplete="username"
                      className={`${INPUT_CLS} disabled:opacity-50`}
                    />
                    <input
                      type="password"
                      placeholder="Password (min 8 characters)"
                      value={setupPw}
                      onChange={e => setSetupPw(e.target.value)}
                      disabled={setupSaving}
                      autoComplete="new-password"
                      className={`${INPUT_CLS} disabled:opacity-50`}
                    />
                    <input
                      type="password"
                      placeholder="Confirm password"
                      value={setupConfirm}
                      onChange={e => setSetupConfirm(e.target.value)}
                      disabled={setupSaving}
                      autoComplete="new-password"
                      className={`${INPUT_CLS} disabled:opacity-50`}
                    />
                    <button
                      type="submit"
                      disabled={setupSaving || !setupUser.trim() || setupPw.length < 8 || setupPw !== setupConfirm}
                      className="px-4 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      {setupSaving ? 'Creating account...' : 'Enable Authentication'}
                    </button>
                  </form>
                ) : (
                  <div className="p-3 rounded bg-amber-500/10 border border-amber-500/30 text-sm text-amber-400">
                    Enabling authentication requires HTTPS. Please access the app through a reverse proxy with TLS enabled.
                  </div>
                )}
              </div>
            </>
          )}

          {authEnabled && me && (
            <>
              <div className="border-t border-gray-800" />
              <div className="p-5 space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-gray-500">Signed in as:</span>
                  <span className="text-gray-200 font-medium">{me.username}</span>
                  <span className="px-1.5 py-0.5 text-xs rounded bg-gray-800 text-gray-400">{me.role || 'user'}</span>
                </div>
                <button
                  onClick={() => setShowPwChange(!showPwChange)}
                  className="text-sm text-teal-500 hover:text-teal-400 transition-colors"
                >
                  Change password
                </button>

                {showPwChange && (
                  <form onSubmit={handleChangePassword} className="mt-3 space-y-3 max-w-sm">
                    <input
                      type="password"
                      placeholder="Current password"
                      value={currentPw}
                      onChange={e => setCurrentPw(e.target.value)}
                      required
                      className={INPUT_CLS}
                    />
                    <input
                      type="password"
                      placeholder="New password (min 8 characters)"
                      value={newPw}
                      onChange={e => setNewPw(e.target.value)}
                      required
                      minLength={8}
                      className={INPUT_CLS}
                    />
                    <input
                      type="password"
                      placeholder="Confirm new password"
                      value={confirmPw}
                      onChange={e => setConfirmPw(e.target.value)}
                      required
                      className={INPUT_CLS}
                    />
                    <div className="flex gap-2">
                      <button
                        type="submit"
                        disabled={pwSaving}
                        className="px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 transition-colors"
                      >
                        {pwSaving ? 'Saving...' : 'Update Password'}
                      </button>
                      <button
                        type="button"
                        onClick={() => { setShowPwChange(false); setCurrentPw(''); setNewPw(''); setConfirmPw('') }}
                        className="px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                )}
              </div>
            </>
          )}
        </div>
      </section>

      {authEnabled && (
        <section>
          <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Session Duration</h2>
          <div className="rounded-lg border border-gray-700 bg-gray-950 p-5">
            <div className="flex items-center gap-3 max-w-sm">
              <select
                value={sessionTtl}
                onChange={e => setSessionTtl(Number(e.target.value))}
                className="px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 focus:outline-none focus:border-teal-500"
              >
                <option value={1}>1 hour</option>
                <option value={4}>4 hours</option>
                <option value={8}>8 hours</option>
                <option value={24}>1 day</option>
                <option value={72}>3 days</option>
                <option value={168}>7 days</option>
                <option value={720}>30 days</option>
              </select>
              <button
                onClick={handleSaveSessionTtl}
                disabled={ttlSaving || sessionTtl === authStatus?.session_ttl_hours}
                className="px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {ttlSaving ? 'Saving...' : 'Save'}
              </button>
            </div>
            <p className="mt-2 text-sm text-gray-500">How long sessions remain valid before requiring re-login. Changes apply to new sessions only.</p>
          </div>
        </section>
      )}
    </div>
  )
}

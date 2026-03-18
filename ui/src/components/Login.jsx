import { useState } from 'react'
import { authLogin } from '../api'

const INPUT_CLS = 'w-full px-3 py-2 rounded bg-gray-900 border border-gray-700 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-teal-500'

export default function Login({ onSuccess, isHttps }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!username.trim() || !password) return
    setError('')
    setLoading(true)
    try {
      await authLogin(username.trim(), password)
      onSuccess()
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center justify-center h-dvh bg-gray-950">
      <div className="w-full max-w-sm mx-4">
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 shadow-2xl">
          <div className="flex items-center justify-center mb-6">
            <svg viewBox="0 0 100 116" className="w-8 h-9" fill="none">
              <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68 Z" fill="#14b8a6" fillOpacity="0.12"/>
              <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round" fill="none"/>
              <path d="M 28 34 A 18 18 0 0 1 44 22" stroke="#14b8a6" strokeWidth="4.8" strokeLinecap="round" fill="none" opacity="0.7"/>
              <line x1="28" y1="75" x2="72" y2="75" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
              <line x1="36" y1="84" x2="64" y2="84" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
              <text x="50" y="110" textAnchor="middle" fontFamily="-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif" fontWeight="800" fontSize="19" letterSpacing="0.16em" fill="#0d9488">PLUS</text>
            </svg>
          </div>
          <h2 className="text-lg font-semibold text-gray-200 text-center mb-1">Sign In</h2>
          <p className="text-xs text-gray-500 text-center mb-5">Insights Plus</p>

          {isHttps === false && (
            <div className="mb-4 p-3 rounded bg-amber-500/10 border border-amber-500/30 text-sm text-amber-400">
              Authentication requires HTTPS. Please access the app through a reverse proxy with TLS enabled.
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div className="space-y-3">
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="Username"
                disabled={!isHttps || loading}
                autoComplete="username"
                className={`${INPUT_CLS} disabled:opacity-50`}
              />
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Password"
                disabled={!isHttps || loading}
                autoComplete="current-password"
                className={`${INPUT_CLS} disabled:opacity-50`}
              />
            </div>

            {error && (
              <p className="mt-3 text-xs text-red-400">{error}</p>
            )}

            <button
              type="submit"
              disabled={!isHttps || loading || !username.trim() || !password}
              className="mt-4 w-full px-4 py-2 rounded text-sm font-medium bg-teal-600 hover:bg-teal-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}

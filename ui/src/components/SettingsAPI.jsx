import { useEffect, useRef, useState } from 'react'
import useApiTokens from '../hooks/useApiTokens'
import TokenCreatedModal from './TokenCreatedModal'
import TokenList from './TokenList'

const INPUT_CLS = 'px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 focus:outline-none focus:border-teal-500'

// Scopes the browser extension needs — locked when client_type is 'extension'
const EXTENSION_REQUIRED_SCOPES = new Set(['health.read', 'settings.read', 'threats.read', 'stats.read'])

const API_SCOPES = [
  { id: 'logs.read', description: 'Read logs', clients: ['api', 'extension', 'mcp'] },
  { id: 'stats.read', description: 'Read statistics', clients: ['api', 'extension', 'mcp'] },
  { id: 'flows.read', description: 'Read flows', clients: ['api', 'extension', 'mcp'] },
  { id: 'threats.read', description: 'Read threats', clients: ['api', 'extension', 'mcp'] },
  { id: 'dashboard.read', description: 'Read dashboard', clients: ['api', 'extension', 'mcp'] },
  { id: 'health.read', description: 'Health check', clients: ['api', 'extension', 'mcp'] },
  { id: 'firewall.read', description: 'Read firewall', clients: ['api', 'extension', 'mcp'] },
  { id: 'firewall.write', description: 'Write firewall', clients: ['api'] },
  { id: 'firewall.syslog', description: 'Firewall syslog', clients: ['api'] },
  { id: 'unifi.read', description: 'Read UniFi data', clients: ['api', 'extension', 'mcp'] },
  { id: 'system.read', description: 'Read system info', clients: ['api', 'extension', 'mcp'] },
  { id: 'settings.read', description: 'Read settings', clients: ['api', 'extension', 'mcp'] },
  { id: 'settings.write', description: 'Write settings', clients: ['api'] },
  { id: 'mcp.admin', description: 'MCP admin', clients: ['api', 'mcp'] },
]

export default function SettingsAPI() {
  const { tokens, loading, reload, create, revoke } = useApiTokens()
  const [message, setMessage] = useState(null)
  const flashTimer = useRef(null)

  // Create token
  const [showCreateToken, setShowCreateToken] = useState(false)
  const [tokenName, setTokenName] = useState('')
  const [tokenScopes, setTokenScopes] = useState(new Set(['logs.read', 'stats.read']))
  const [tokenClientType, setTokenClientType] = useState('api')
  const [creating, setCreating] = useState(false)
  const [createdToken, setCreatedToken] = useState(null)
  const [showTokenModal, setShowTokenModal] = useState(false)

  const visibleScopes = API_SCOPES.filter(s => s.clients.includes(tokenClientType))

  useEffect(() => { reload() }, [reload])

  useEffect(() => {
    return () => clearTimeout(flashTimer.current)
  }, [])

  function flash(text, type = 'info') {
    setMessage({ text, type })
    clearTimeout(flashTimer.current)
    flashTimer.current = setTimeout(() => setMessage(null), 4000)
  }

  async function handleCreateToken(e) {
    e.preventDefault()
    if (!tokenName.trim()) { flash('Token name is required', 'error'); return }
    if (tokenScopes.size === 0) { flash('Select at least one scope', 'error'); return }
    setCreating(true)
    try {
      const resp = await create({
        name: tokenName.trim(),
        scopes: [...tokenScopes],
        client_type: tokenClientType,
      })
      setCreatedToken(resp.token)
      setShowTokenModal(true)
      setTokenName('')
      setTokenScopes(new Set(['logs.read', 'stats.read']))
    } catch (err) {
      flash(err.message || 'Failed to create token', 'error')
    } finally {
      setCreating(false)
    }
  }

  async function handleRevoke(id, name) {
    if (!confirm(`Revoke token "${name}"? This cannot be undone.`)) return
    try {
      await revoke(id)
      flash('Token revoked', 'success')
    } catch (err) {
      flash(err.message || 'Failed to revoke token', 'error')
    }
  }

  function toggleScope(scope) {
    setTokenScopes(prev => {
      const next = new Set(prev)
      next.has(scope) ? next.delete(scope) : next.add(scope)
      return next
    })
  }

  if (loading) return (
    <div className="space-y-8 animate-pulse">
      <div>
        <div className="h-5 w-32 bg-gray-800 rounded mb-3" />
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5 space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-4 bg-gray-800 rounded" style={{ width: `${70 - i * 15}%` }} />
          ))}
        </div>
      </div>
    </div>
  )

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
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-base font-semibold text-gray-300 uppercase tracking-wider">API Tokens</h2>
          <button
            onClick={() => { setShowCreateToken(!showCreateToken); setCreatedToken(null) }}
            className="px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded transition-colors"
          >
            Create Token
          </button>
        </div>


        {showCreateToken && (
          <form onSubmit={handleCreateToken} className="mb-4 rounded-lg border border-gray-700 bg-gray-950 p-5 space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-200 mb-1">Token Name</label>
              <input
                type="text"
                value={tokenName}
                onChange={e => setTokenName(e.target.value)}
                placeholder="e.g. Grafana integration"
                className={`w-full max-w-sm ${INPUT_CLS}`}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-200 mb-1">Client Type</label>
              <select
                value={tokenClientType}
                onChange={e => {
                  const type = e.target.value
                  setTokenClientType(type)
                  const allowed = new Set(API_SCOPES.filter(s => s.clients.includes(type)).map(s => s.id))
                  if (type === 'extension') {
                    setTokenScopes(new Set(EXTENSION_REQUIRED_SCOPES))
                  } else {
                    setTokenScopes(prev => new Set([...prev].filter(id => allowed.has(id))))
                  }
                }}
                className={INPUT_CLS}
              >
                <option value="api">API</option>
                <option value="extension">Extension</option>
                <option value="mcp">MCP</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-200 mb-2">Scopes</label>
              <div className="grid grid-cols-2 gap-2">
                {visibleScopes.map(s => {
                  const locked = tokenClientType === 'extension' && EXTENSION_REQUIRED_SCOPES.has(s.id)
                  return (
                    <label key={s.id} className={`flex items-start gap-2 text-sm ${locked ? 'text-gray-500 cursor-not-allowed' : 'text-gray-300'}`}>
                      <input
                        type="checkbox"
                        checked={tokenScopes.has(s.id)}
                        onChange={() => !locked && toggleScope(s.id)}
                        disabled={locked}
                        className="mt-0.5 ui-checkbox"
                      />
                      <span>
                        <span className={`${locked ? 'text-gray-400' : 'text-gray-200'} font-medium`}>{s.description}{locked ? ' (required)' : ''}</span>
                        <span className="block text-xs text-gray-500 font-mono">{s.id}</span>
                      </span>
                    </label>
                  )
                })}
              </div>
            </div>
            <div className="flex gap-2 pt-1">
              <button
                type="submit"
                disabled={creating}
                className="px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 transition-colors"
              >
                {creating ? 'Creating...' : 'Create'}
              </button>
              <button
                type="button"
                onClick={() => setShowCreateToken(false)}
                className="px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5">
            <p className="text-sm font-medium text-gray-200 mb-3">Active tokens</p>
            <TokenList tokens={tokens} onRevoke={handleRevoke} />
          </div>
        </div>
      </section>

      <section>
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5">
          <h3 className="text-sm font-medium text-gray-200 mb-2">Usage</h3>
          <p className="text-sm text-gray-400 mb-3">
            Pass your token as a Bearer token in the <span className="font-mono">Authorization</span> header:
          </p>
          <code className="block px-3 py-2 bg-gray-900 border border-gray-700 rounded text-sm text-gray-300 font-mono whitespace-pre-wrap">curl -H "Authorization: Bearer YOUR_TOKEN" https://your-host/api/logs</code>
        </div>
      </section>

      <section>
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5">
          <h3 className="text-sm font-medium text-gray-200 mb-2">Browser Extension</h3>
          <p className="text-sm text-gray-400">
            Create a token with <span className="font-mono">extension</span> client type and the scopes your extension needs.
            Paste the token into the extension popup under "API Token".
          </p>
        </div>
      </section>

      {showTokenModal && (
        <TokenCreatedModal
          token={createdToken}
          title="API Token Created"
          onClose={() => { setShowTokenModal(false); setCreatedToken(null) }}
        />
      )}
    </div>
  )
}

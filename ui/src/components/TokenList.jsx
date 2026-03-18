/**
 * Shared active-token list used by SettingsAPI and SettingsMCP.
 */
// PropTypes not used in this project. Date values come from own API (Python
// isoformat) — defensive validation against own server is unnecessary.
export default function TokenList({ tokens = [], onRevoke, formatPrefix, revokingId }) {
  return (
    <div className="space-y-2">
      {tokens.length === 0 && (
        <p className="text-sm text-gray-600">No tokens yet.</p>
      )}
      {tokens.map(t => (
        <div
          key={t.id}
          className="flex items-center justify-between gap-3 px-3 py-2 rounded border border-gray-800 bg-gray-900/60"
        >
          <div className="min-w-0">
            <p className="text-base text-gray-200 font-medium truncate">{t.name}</p>
            {/* IIFE keeps prefix/scopes computation local to where it's rendered */}
            <p className="text-xs text-gray-500 font-mono truncate">
              {(() => {
                const prefix = formatPrefix ? formatPrefix(t) : (t.token_prefix ? `${t.token_prefix}…` : t.client_type)
                const scopes = t.scopes?.length ? t.scopes.join(', ') : 'no scopes'
                return `${prefix} · ${scopes}`
              })()}
            </p>
            <p className="text-xs text-gray-600">
              Created {t.created_at ? new Date(t.created_at).toLocaleString() : 'unknown'}
              {t.last_used_at && ` · Last used ${new Date(t.last_used_at).toLocaleString()}`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className={`text-xs uppercase font-semibold px-2 py-0.5 rounded ${
              t.disabled ? 'bg-gray-700 text-gray-300' : 'bg-green-500/10 text-green-300'
            }`}>
              {t.disabled ? 'Disabled' : 'Active'}
            </span>
            {!t.disabled && onRevoke && (
              <button
                onClick={() => onRevoke(t.id, t.name)}
                disabled={revokingId === t.id}
                aria-label={`Revoke ${t.name || t.id}`}
                className="px-2 py-1 text-sm font-semibold rounded bg-teal-600 hover:bg-teal-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {revokingId === t.id ? 'Revoking...' : 'Revoke'}
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

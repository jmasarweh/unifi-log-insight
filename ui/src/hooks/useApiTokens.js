import { useState, useCallback } from 'react'
import { fetchApiTokens, createApiToken, revokeApiToken } from '../api'

/**
 * Shared hook for token CRUD operations.
 * @param {string} [clientType] - Optional client_type filter for fetchApiTokens.
 */
export default function useApiTokens(clientType) {
  const [tokens, setTokens] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const reload = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const resp = await fetchApiTokens(clientType)
      setTokens(resp.tokens || [])
    } catch (err) {
      setError(err.message || 'Failed to load tokens')
    } finally {
      setLoading(false)
    }
  }, [clientType])

  const create = useCallback(async (payload) => {
    const resp = await createApiToken(payload)
    await reload()
    return resp
  }, [reload])

  const revoke = useCallback(async (id) => {
    await revokeApiToken(id)
    await reload()
  }, [reload])

  return { tokens, loading, error, reload, create, revoke }
}

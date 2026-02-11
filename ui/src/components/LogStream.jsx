import React, { useState, useEffect, useCallback, useRef } from 'react'
import { fetchLogs, getExportUrl } from '../api'
import FilterBar from './FilterBar'
import LogTable from './LogTable'
import Pagination from './Pagination'

const DEFAULT_FILTERS = {
  time_range: '24h',
  log_type: null,
  rule_action: null,
  direction: null,
  ip: null,
  rule_name: null,
  search: null,
  service: null,
  page: 1,
  per_page: 50,
  sort: 'timestamp',
  order: 'desc',
}

const STORAGE_KEY = 'unifi-log-insight:log-types'

export default function LogStream() {
  const [filters, setFilters] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (saved) return { ...DEFAULT_FILTERS, log_type: saved }
    } catch (e) { /* private browsing */ }
    return DEFAULT_FILTERS
  })
  const [data, setData] = useState({ data: [], total: 0, page: 1, pages: 0 })
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const [pendingCount, setPendingCount] = useState(0)
  const intervalRef = useRef(null)
  const pendingRef = useRef(null)

  // Persist log_type toggles to localStorage
  useEffect(() => {
    try {
      if (filters.log_type) {
        localStorage.setItem(STORAGE_KEY, filters.log_type)
      } else {
        localStorage.removeItem(STORAGE_KEY)
      }
    } catch (e) { /* private browsing */ }
  }, [filters.log_type])

  // Effective auto-refresh: paused when a row is expanded
  const isRefreshing = autoRefresh && expandedId === null

  // When a row is expanded, silently check for new logs count
  useEffect(() => {
    if (pendingRef.current) clearInterval(pendingRef.current)
    if (autoRefresh && expandedId !== null && filters.page === 1) {
      pendingRef.current = setInterval(async () => {
        try {
          const qs = new URLSearchParams()
          for (const [k, v] of Object.entries(filters)) {
            if (v !== null && v !== undefined && v !== '') qs.set(k, v)
          }
          qs.set('per_page', '1')
          const resp = await fetch(`/api/logs?${qs}`)
          const result = await resp.json()
          const diff = result.total - data.total
          if (diff > 0) setPendingCount(diff)
        } catch {}
      }, 5000)
    }
    return () => { if (pendingRef.current) clearInterval(pendingRef.current) }
  }, [autoRefresh, expandedId, filters, data.total])

  // Auto-resume: when row is collapsed, refresh immediately
  const handleToggleExpand = (id) => {
    if (expandedId === id) {
      setExpandedId(null)
      setPendingCount(0)
      // Refresh immediately on collapse
      load(filters)
    } else {
      setExpandedId(id)
      setPendingCount(0)
    }
  }

  const load = useCallback(async (f) => {
    try {
      setLoading(true)
      const result = await fetchLogs(f || filters)
      setData(result)
      setLastUpdate(new Date())
    } catch (err) {
      console.error('Failed to fetch logs:', err)
    } finally {
      setLoading(false)
    }
  }, [filters])

  // Load on filter change
  useEffect(() => {
    load(filters)
  }, [filters])

  // Auto-refresh every 5s when on page 1 and no row expanded
  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current)
    if (isRefreshing && filters.page === 1) {
      intervalRef.current = setInterval(() => load(filters), 5000)
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [isRefreshing, filters, load])

  const handleFilterChange = (newFilters) => {
    setExpandedId(null)
    setPendingCount(0)
    setFilters({ ...newFilters, page: 1 })
  }

  const handlePageChange = (page) => {
    setExpandedId(null)
    setPendingCount(0)
    setFilters(f => ({ ...f, page }))
  }

  return (
    <div className="flex flex-col h-full">
      {/* Filters */}
      <div className="px-4 py-3 border-b border-gray-800 bg-gray-900/30">
        <FilterBar filters={filters} onChange={handleFilterChange} />
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-gray-800/50 bg-gray-900/20">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 text-[11px] transition-colors ${
              isRefreshing ? 'text-emerald-400' : autoRefresh && expandedId !== null ? 'text-amber-400' : 'text-gray-500'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${isRefreshing ? 'bg-emerald-400 animate-pulse' : autoRefresh && expandedId !== null ? 'bg-amber-400' : 'bg-gray-600'}`} />
            {isRefreshing ? 'Live' : autoRefresh && expandedId !== null ? 'Paused' : 'Paused'}
          </button>
          {pendingCount > 0 && (
            <button
              onClick={() => { setExpandedId(null); setPendingCount(0); load(filters) }}
              className="text-[11px] text-amber-400 hover:text-amber-300 transition-colors"
            >
              {pendingCount} new log{pendingCount !== 1 ? 's' : ''} ↻
            </button>
          )}
          {lastUpdate && (
            <span className="text-[10px] text-gray-600">
              Updated {lastUpdate.toLocaleTimeString('en-GB')}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => load(filters)}
            className="text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
          >
            ↻ Refresh
          </button>
          <a
            href={getExportUrl(filters)}
            className="text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
          >
            ↓ Export CSV
          </a>
        </div>
      </div>

      {/* Log table */}
      <div className="flex-1 overflow-auto">
        <LogTable logs={data.data} loading={loading} expandedId={expandedId} onToggleExpand={handleToggleExpand} />
      </div>

      {/* Pagination */}
      <Pagination
        page={data.page}
        pages={data.pages}
        total={data.total}
        perPage={filters.per_page}
        onChange={handlePageChange}
      />
    </div>
  )
}

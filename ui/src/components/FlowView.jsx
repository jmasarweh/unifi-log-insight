import { useState, useCallback, lazy, Suspense } from 'react'
import useTimeRange from '../hooks/useTimeRange'
import { ACTION_STYLES, DIRECTION_ICONS, DIRECTION_COLORS } from '../utils'
import SankeyChart from './SankeyChart'
import TopIPPairs from './TopIPPairs'
import HostSlidePanel from './HostSlidePanel'

const ZoneMatrix = lazy(() => import('./ZoneMatrix'))

const ACTIONS = ['allow', 'block']
const DIRECTIONS = ['inbound', 'outbound', 'inter_vlan', 'nat', 'local', 'vpn']
const SUB_TABS = [
  { key: 'sankey', label: 'Flow Graph' },
  { key: 'zone-matrix', label: 'Zone Matrix' },
]

export default function FlowView({ maxFilterDays }) {
  const [timeRange, setTimeRange, visibleRanges] = useTimeRange(maxFilterDays)
  const [activeActions, setActiveActions] = useState(ACTIONS)
  const [activeDirections, setActiveDirections] = useState(DIRECTIONS)
  const [refreshKey, setRefreshKey] = useState(0)

  // Sub-tab state
  const [activePanel, setActivePanel] = useState('sankey')

  // Cross-filter state
  const [sankeyFilter, setSankeyFilter] = useState(null)
  const [zoneFilter, setZoneFilter] = useState(null)

  // Host detail expansion state — { ip, rowIndex } or null
  const [expandedRow, setExpandedRow] = useState(null)
  const [hostSearchInput, setHostSearchInput] = useState('')

  const toggleAction = (action) => {
    setActiveActions(prev => {
      const updated = prev.includes(action)
        ? prev.filter(a => a !== action)
        : [...prev, action]
      return updated.length === 0 ? [...ACTIONS] : updated
    })
  }

  const toggleDirection = (dir) => {
    setActiveDirections(prev => {
      const updated = prev.includes(dir)
        ? prev.filter(d => d !== dir)
        : [...prev, dir]
      return updated.length === 0 ? [...DIRECTIONS] : updated
    })
  }

  const filters = {
    time_range: timeRange,
    rule_action: activeActions.length === ACTIONS.length ? null : activeActions.join(','),
    direction: activeDirections.length === DIRECTIONS.length ? null : activeDirections.join(','),
  }

  const refresh = useCallback(() => setRefreshKey(k => k + 1), [])

  // Sankey node click — toggle filter, clear zone filter (mutual exclusivity)
  const handleSankeyNodeClick = useCallback(({ type, value }) => {
    setSankeyFilter(prev => {
      if (prev && prev.type === type && prev.value === value) return null
      return { type, value }
    })
    setZoneFilter(null)
  }, [])

  // Zone cell click — toggle filter, clear sankey filter (mutual exclusivity)
  const handleZoneCellClick = useCallback(({ interface_in, interface_out, in_label, out_label }) => {
    setZoneFilter(prev => {
      if (prev && prev.interface_in === interface_in && prev.interface_out === interface_out) return null
      return { interface_in, interface_out, in_label, out_label }
    })
    setSankeyFilter(null)
  }, [])

  // IP click — toggle host detail expansion (from TopIPPairs row IPs)
  const handleIpClick = useCallback((ip, rowIndex) => {
    setExpandedRow(prev =>
      prev && prev.ip === ip && prev.rowIndex === rowIndex ? null : { ip, rowIndex }
    )
    setHostSearchInput(ip)
  }, [])

  // Sankey node click also expands host detail if IP type
  const handleSankeyNodeClickWithHost = useCallback(({ type, value }) => {
    handleSankeyNodeClick({ type, value })
    if (type === 'src_ip' || type === 'dst_ip') {
      setExpandedRow(prev => prev && prev.ip === value ? null : { ip: value, rowIndex: -1 })
      setHostSearchInput(value)
    }
  }, [handleSankeyNodeClick])

  const handleHostSearch = (e) => {
    if (e.key === 'Enter' && hostSearchInput.trim()) {
      setExpandedRow({ ip: hostSearchInput.trim(), rowIndex: -1 })
    }
  }

  return (
    <div className="flex flex-col h-full overflow-hidden p-4 space-y-4">
      {/* Filters — matches FilterBar styling */}
      <div className="flex items-center gap-4 flex-wrap">
        {/* Action toggles */}
        <div className="flex items-center gap-1.5">
          {ACTIONS.map(action => (
            <button
              key={action}
              onClick={() => toggleAction(action)}
              className={`px-2 py-1 rounded text-xs font-medium uppercase border transition-all ${
                activeActions.includes(action)
                  ? ACTION_STYLES[action]
                  : 'border-transparent text-gray-500 hover:text-gray-400'
              }`}
            >
              {action}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        {/* Direction toggles */}
        <div className="flex items-center gap-1">
          {DIRECTIONS.map(dir => (
            <button
              key={dir}
              onClick={() => toggleDirection(dir)}
              className={`px-2 py-1 rounded text-xs font-medium uppercase transition-all ${
                activeDirections.includes(dir)
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-500 hover:text-gray-400'
              }`}
            >
              <span className={activeDirections.includes(dir) ? DIRECTION_COLORS[dir] : ''}>{DIRECTION_ICONS[dir]}</span> {dir === 'inter_vlan' ? 'vlan' : dir}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        {/* Time range */}
        <div className="flex items-center gap-1">
          {visibleRanges.map(tr => (
            <button
              key={tr}
              onClick={() => setTimeRange(tr)}
              className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                timeRange === tr
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-400 hover:text-gray-300'
              }`}
            >
              {tr}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        {/* IP Search */}
        <div className="flex items-center gap-1">
          <input
            type="text"
            placeholder="Search IP..."
            value={hostSearchInput}
            onChange={e => setHostSearchInput(e.target.value)}
            onKeyDown={handleHostSearch}
            className="w-36 bg-gray-800/50 text-gray-300 text-xs rounded px-2 py-1 border border-gray-700 placeholder-gray-600 focus:outline-none focus:border-gray-500"
          />
          {expandedRow && (
            <button
              onClick={() => { setExpandedRow(null); setHostSearchInput('') }}
              className="text-gray-500 hover:text-gray-300 text-xs px-1"
              title="Clear host search"
            >&times;</button>
          )}
        </div>

        <button
          onClick={refresh}
          className="ml-auto px-2.5 py-1 rounded text-xs font-medium text-gray-400 hover:text-gray-200 transition-colors"
          title="Refresh data"
        >
          ↻ Refresh
        </button>
      </div>

      {/* Sub-tabs */}
      <div className="flex items-center gap-1">
        {SUB_TABS.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActivePanel(tab.key)}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-all ${
              activePanel === tab.key
                ? 'bg-gray-700 text-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main content — side by side: chart 65%, IP pairs 35% */}
      <div className="flex gap-4 min-h-0 flex-1">
        {/* Left: active panel (60%) */}
        <div className="w-[60%] min-w-0 overflow-hidden">
          {activePanel === 'sankey' && (
            <SankeyChart
              filters={filters}
              refreshKey={refreshKey}
              onNodeClick={handleSankeyNodeClickWithHost}
              activeFilter={sankeyFilter}
              hostIp={expandedRow?.ip}
            />
          )}
          {activePanel === 'zone-matrix' && (
            <Suspense fallback={<div className="border border-gray-800 rounded-lg p-4 h-64 flex items-center justify-center text-xs text-gray-500">Loading...</div>}>
              <ZoneMatrix
                filters={filters}
                refreshKey={refreshKey}
                onCellClick={handleZoneCellClick}
                activeCell={zoneFilter}
              />
            </Suspense>
          )}
        </div>

        {/* Right: Top IP Pairs (40%) + slide-out host panel */}
        <div className="w-[40%] min-w-0 overflow-hidden flex flex-col relative">
          <TopIPPairs
            filters={filters}
            refreshKey={refreshKey}
            sankeyFilter={sankeyFilter}
            onClearSankeyFilter={() => setSankeyFilter(null)}
            zoneFilter={zoneFilter}
            onClearZoneFilter={() => setZoneFilter(null)}
            onIpClick={handleIpClick}
          />
          {expandedRow && (
            <HostSlidePanel
              ip={expandedRow.ip}
              filters={filters}
              onClose={() => { setExpandedRow(null); setHostSearchInput('') }}
              onPeerClick={(ip) => { setExpandedRow({ ip, rowIndex: -1 }); setHostSearchInput(ip) }}
            />
          )}
        </div>
      </div>
    </div>
  )
}

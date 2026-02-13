import { useState, useEffect } from 'react'
import { fetchStats } from '../api'
import { formatNumber, FlagIcon, decodeThreatCategories } from '../utils'

const TIME_RANGES = ['1h', '6h', '24h', '7d', '30d', '60d']

export function DashboardSkeleton() {
  return (
    <div className="p-4 space-y-4 overflow-auto max-h-full animate-pulse">
      {/* Time range selector */}
      <div className="flex gap-1">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-7 w-10 bg-gray-800 rounded" />
        ))}
      </div>
      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="bg-gray-900/50 border border-gray-800 rounded-lg p-4 space-y-2">
            <div className="h-2.5 w-16 bg-gray-800 rounded" />
            <div className="h-6 w-12 bg-gray-800 rounded" />
          </div>
        ))}
      </div>
      {/* Direction breakdown */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4 h-16" />
      {/* Chart */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4 h-40" />
      {/* Section header */}
      <div className="h-3 w-24 bg-gray-800 rounded mt-2" />
      {/* Panel grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="bg-gray-900/50 border border-gray-800 rounded-lg p-4 h-48" />
        ))}
      </div>
      {/* Section header */}
      <div className="h-3 w-24 bg-gray-800 rounded mt-2" />
      {/* Allowed panel grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-gray-900/50 border border-gray-800 rounded-lg p-4 h-48" />
        ))}
      </div>
    </div>
  )
}

function StatCard({ label, value, color = 'text-white', sub }) {
  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
      <div className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-2xl font-semibold ${color}`}>{formatNumber(value)}</div>
      {sub && <div className="text-[10px] text-gray-400 mt-1">{sub}</div>}
    </div>
  )
}

function MiniBar({ data, maxVal, color = 'bg-blue-500' }) {
  if (!maxVal) return null
  const pct = (data / maxVal) * 100
  return (
    <div className="w-full bg-gray-800 rounded-full h-1.5">
      <div className={`${color} h-1.5 rounded-full transition-all`} style={{ width: `${pct}%` }} />
    </div>
  )
}

function LogsPerHourChart({ data }) {
  if (!data || data.length === 0) {
    return <div className="text-gray-400 text-xs text-center py-8">No data yet</div>
  }

  const maxCount = Math.max(...data.map(d => d.count))
  const chartHeight = 120

  return (
    <div className="flex items-end gap-px h-32 px-1">
      {data.map((d, i) => {
        const height = maxCount > 0 ? (d.count / maxCount) * chartHeight : 0
        const hour = new Date(d.hour).getHours()
        return (
          <div key={i} className="flex-1 flex flex-col items-center gap-1" title={`${hour}:00 — ${formatNumber(d.count)} logs`}>
            <div
              className="w-full bg-blue-500/60 hover:bg-blue-500 rounded-t transition-colors min-h-[2px]"
              style={{ height: `${height}px` }}
            />
            <span className={`text-[9px] ${
              i % Math.max(1, Math.floor(data.length / 8)) === 0
                ? 'text-gray-400'
                : 'invisible'
            }`}>{hour}h</span>
          </div>
        )
      })}
    </div>
  )
}

function formatTimeAgo(isoStr) {
  if (!isoStr) return null
  const diff = Date.now() - new Date(isoStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function TopList({ title, items, renderItem }) {
  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
      <div className="text-[10px] text-gray-400 uppercase tracking-wider mb-3">{title}</div>
      {items.length === 0 ? (
        <div className="text-gray-400 text-xs py-4 text-center">No data</div>
      ) : (
        <div className="space-y-2">
          {items.map((item, i) => renderItem(item, i))}
        </div>
      )}
    </div>
  )
}

export default function Dashboard() {
  const [timeRange, setTimeRange] = useState('24h')
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    setLoading(true)
    fetchStats(timeRange)
      .then(data => { if (mounted) setStats(data) })
      .catch(err => console.error('Failed to fetch stats:', err))
      .finally(() => { if (mounted) setLoading(false) })
    return () => { mounted = false }
  }, [timeRange])

  // Auto-refresh every 30s
  useEffect(() => {
    const interval = setInterval(() => {
      fetchStats(timeRange)
        .then(setStats)
        .catch(() => {})
    }, 30000)
    return () => clearInterval(interval)
  }, [timeRange])

  if (loading && !stats) {
    return <DashboardSkeleton />
  }

  if (!stats) return null

  const maxBlocked = stats.top_blocked_ips.length > 0
    ? Math.max(...stats.top_blocked_ips.map(i => i.count))
    : 0
  const maxBlockedInternal = (stats.top_blocked_internal_ips || []).length > 0
    ? Math.max(...stats.top_blocked_internal_ips.map(i => i.count))
    : 0
  const maxAllowedDest = (stats.top_allowed_destinations || []).length > 0
    ? Math.max(...stats.top_allowed_destinations.map(i => i.count))
    : 0
  const maxActiveInternal = (stats.top_active_internal_ips || []).length > 0
    ? Math.max(...stats.top_active_internal_ips.map(i => i.count))
    : 0

  return (
    <div className="p-4 space-y-4 overflow-auto max-h-full">
      {/* Time range selector */}
      <div className="flex items-center gap-1">
        {TIME_RANGES.map(tr => (
          <button
            key={tr}
            onClick={() => setTimeRange(tr)}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
              timeRange === tr ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            {tr}
          </button>
        ))}
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Total Logs" value={stats.total} />
        <StatCard
          label="Blocked"
          value={stats.blocked}
          color={stats.blocked > 0 ? 'text-red-400' : 'text-gray-300'}
        />
        <StatCard
          label="Threats (>50%)"
          value={stats.threats}
          color={stats.threats > 0 ? 'text-orange-400' : 'text-gray-300'}
        />
        <StatCard
          label="Allowed"
          value={stats.allowed || 0}
          color={(stats.allowed || 0) > 0 ? 'text-green-400' : 'text-gray-300'}
        />
        <StatCard
          label="Log Types"
          value={Object.keys(stats.by_type).length}
          sub={Object.entries(stats.by_type).map(([t, c]) => `${t}: ${formatNumber(c)}`).join(' · ')}
        />
      </div>

      {/* Direction breakdown */}
      {Object.keys(stats.by_direction).length > 0 && (
        <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
          <div className="text-[10px] text-gray-400 uppercase tracking-wider mb-3">Traffic Direction</div>
          <div className="flex items-center gap-4">
            {Object.entries(stats.by_direction).map(([dir, count]) => {
              const colors = {
                inbound: 'text-red-400',
                outbound: 'text-blue-400',
                inter_vlan: 'text-gray-300',
                nat: 'text-yellow-400',
              }
              return (
                <div key={dir} className="text-center">
                  <div className={`text-lg font-semibold ${colors[dir] || 'text-gray-300'}`}>
                    {formatNumber(count)}
                  </div>
                  <div className="text-[10px] text-gray-400">{dir}</div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Logs per hour chart */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
        <div className="text-[10px] text-gray-400 uppercase tracking-wider mb-3">Logs Per Hour</div>
        <LogsPerHourChart data={stats.logs_per_hour} />
      </div>

      {/* Blocked Traffic */}
      <div className="text-[10px] text-gray-400 uppercase tracking-wider mt-2">Blocked Traffic</div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <TopList
          title="Top Threat IPs"
          items={stats.top_threat_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">
                  {item.ip}
                  {item.country && <span className="ml-1.5">{<FlagIcon code={item.country} />}</span>}
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-gray-400 text-[10px]">{formatNumber(item.count)}×</span>
                  <span className={`font-medium ${
                    item.threat_score >= 75 ? 'text-red-400' : item.threat_score >= 50 ? 'text-orange-400' : 'text-yellow-400'
                  }`}>
                    {item.threat_score}%
                  </span>
                </div>
              </div>
              {(item.asn || item.city) && (
                <div className="text-[10px] text-gray-400 truncate">
                  {[item.asn, item.city].filter(Boolean).join(' · ')}
                </div>
              )}
              {item.rdns && (
                <div className="text-[10px] text-gray-400 truncate">{item.rdns}</div>
              )}
              <div className="flex items-center justify-between">
                {decodeThreatCategories(item.threat_categories) ? (
                  <div className="text-[10px] text-purple-400/70 truncate">
                    {decodeThreatCategories(item.threat_categories)}
                  </div>
                ) : <div />}
                {item.last_seen && (
                  <div className="text-[10px] text-gray-400 shrink-0">{formatTimeAgo(item.last_seen)}</div>
                )}
              </div>
            </div>
          )}
        />

        <TopList
          title="Top Blocked External IPs"
          items={stats.top_blocked_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">
                  {item.ip}
                  {item.country && <span className="ml-1.5">{<FlagIcon code={item.country} />}</span>}
                </span>
                <span className="text-gray-400">{formatNumber(item.count)}</span>
              </div>
              {item.asn && <div className="text-[10px] text-gray-400">{item.asn}</div>}
              <MiniBar data={item.count} maxVal={maxBlocked} color="bg-red-500/60" />
            </div>
          )}
        />

        <TopList
          title="Top Blocked Internal IPs"
          items={stats.top_blocked_internal_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">{item.ip}</span>
                <span className="text-gray-400">{formatNumber(item.count)}</span>
              </div>
              <MiniBar data={item.count} maxVal={maxBlockedInternal} color="bg-orange-500/60" />
            </div>
          )}
        />

        <TopList
          title="Top Blocked Countries"
          items={stats.top_blocked_countries || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300">
                {<FlagIcon code={item.country} />} {item.country}
              </span>
              <span className="text-gray-400">{formatNumber(item.count)}</span>
            </div>
          )}
        />

        <TopList
          title="Top Blocked Services"
          items={stats.top_blocked_services || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300 truncate mr-2">{item.service_name}</span>
              <span className="text-gray-400 shrink-0">{formatNumber(item.count)}</span>
            </div>
          )}
        />

        <TopList
          title="Top DNS Queries"
          items={stats.top_dns || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300 truncate mr-2">{item.dns_query}</span>
              <span className="text-gray-400 shrink-0">{formatNumber(item.count)}</span>
            </div>
          )}
        />
      </div>

      {/* Allowed Traffic */}
      <div className="text-[10px] text-gray-400 uppercase tracking-wider mt-2">Allowed Traffic</div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <TopList
          title="Top Allowed Destinations"
          items={stats.top_allowed_destinations || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">
                  {item.ip}
                  {item.country && <span className="ml-1.5">{<FlagIcon code={item.country} />}</span>}
                </span>
                <span className="text-gray-400">{formatNumber(item.count)}</span>
              </div>
              {item.asn && <div className="text-[10px] text-gray-400">{item.asn}</div>}
              <MiniBar data={item.count} maxVal={maxAllowedDest} color="bg-green-500/60" />
            </div>
          )}
        />

        <TopList
          title="Top Allowed Countries"
          items={stats.top_allowed_countries || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300">
                {<FlagIcon code={item.country} />} {item.country}
              </span>
              <span className="text-gray-400">{formatNumber(item.count)}</span>
            </div>
          )}
        />

        <TopList
          title="Top Allowed Services"
          items={stats.top_allowed_services || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300 truncate mr-2">{item.service_name}</span>
              <span className="text-gray-400 shrink-0">{formatNumber(item.count)}</span>
            </div>
          )}
        />

        <TopList
          title="Top Active Internal IPs"
          items={stats.top_active_internal_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">{item.ip}</span>
                <span className="text-gray-400">{formatNumber(item.count)}</span>
              </div>
              <MiniBar data={item.count} maxVal={maxActiveInternal} color="bg-emerald-500/60" />
            </div>
          )}
        />
      </div>
    </div>
  )
}

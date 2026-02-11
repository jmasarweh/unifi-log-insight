import React from 'react'
import {
  formatTime, getFlag, isPrivateIP, getInterfaceName,
  LOG_TYPE_STYLES, ACTION_STYLES,
  DIRECTION_ICONS, DIRECTION_COLORS, decodeThreatCategories,
} from '../utils'
import LogDetail from './LogDetail'

function ThreatBadge({ score, categories }) {
  if (score === null || score === undefined) return <span className="text-gray-700">—</span>

  let dotColor = 'bg-emerald-400'
  if (score >= 75) { dotColor = 'bg-red-400' }
  else if (score >= 50) { dotColor = 'bg-orange-400' }
  else if (score >= 25) { dotColor = 'bg-yellow-400' }
  else if (score > 0) { dotColor = 'bg-blue-400' }

  const catText = decodeThreatCategories(categories)

  return (
    <span className="inline-flex items-center gap-1" title={catText || `Threat score: ${score}%`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      <span className="text-gray-400">{score}</span>
    </span>
  )
}

function IPCell({ ip, port }) {
  if (!ip) return <span className="text-gray-700">—</span>

  return (
    <span className="inline-flex items-baseline gap-0.5 min-w-0">
      <span className="text-gray-300 truncate">{ip}</span>
      {port && <span className="text-gray-600">:{port}</span>}
    </span>
  )
}

function NetworkPath({ ifaceIn, ifaceOut }) {
  const nameIn = getInterfaceName(ifaceIn)
  const nameOut = getInterfaceName(ifaceOut)

  if (!ifaceIn && !ifaceOut) return <span className="text-gray-700">—</span>

  const colorMap = {
    'Main': 'text-blue-400',
    'IoT': 'text-amber-400',
    'Hotspot': 'text-purple-400',
    'WAN': 'text-red-400',
  }

  const colorIn = colorMap[nameIn] || 'text-gray-400'
  const colorOut = colorMap[nameOut] || 'text-gray-400'

  if (!ifaceOut) {
    return <span className={colorIn}>{nameIn}</span>
  }

  return (
    <span className="inline-flex items-center gap-1">
      <span className={colorIn}>{nameIn}</span>
      <span className="text-gray-600">→</span>
      <span className={colorOut}>{nameOut}</span>
    </span>
  )
}

function formatRuleDesc(desc) {
  if (!desc) return null
  // Add space after ] if missing: "[WAN_LOCAL]Block" → "[WAN_LOCAL] Block"
  return desc.replace(/\](?!\s)/, '] ')
}

function LogRow({ log, isExpanded, detailedLog, onToggle }) {
  const actionStyle = ACTION_STYLES[log.rule_action || log.dhcp_event || log.wifi_event] || ''
  const typeStyle = LOG_TYPE_STYLES[log.log_type] || LOG_TYPE_STYLES.system
  const dirIcon = DIRECTION_ICONS[log.direction] || ''
  const dirColor = DIRECTION_COLORS[log.direction] || 'text-gray-600'

  const infoText = log.log_type === 'firewall'
    ? (formatRuleDesc(log.rule_desc) || log.rule_name || '—')
    : (log.dns_query || log.hostname || log.wifi_event || '—')

  const infoTitle = log.log_type === 'firewall'
    ? (formatRuleDesc(log.rule_desc) || log.rule_name || '')
    : infoText

  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-b border-gray-800/50 transition-colors hover:bg-gray-800/30 ${
          log.rule_action === 'block' ? 'bg-red-950/10' : ''
        } ${log.threat_score >= 50 ? 'bg-orange-950/10' : ''}`}
      >
        {/* Time */}
        <td className="px-3 py-1.5 text-[13px] text-gray-500 whitespace-nowrap font-light">
          {formatTime(log.timestamp)}
        </td>

        {/* Type */}
        <td className="px-2 py-1.5">
          <span className={`inline-block px-1.5 py-0.5 rounded text-[12px] font-medium border ${typeStyle}`}>
            {log.log_type}
          </span>
        </td>

        {/* Action */}
        <td className="px-2 py-1.5">
          {(log.rule_action || log.dhcp_event || log.wifi_event) ? (
            <span className={`inline-block px-1.5 py-0.5 rounded text-[12px] font-medium border ${actionStyle}`}>
              {log.rule_action || log.dhcp_event || log.wifi_event}
            </span>
          ) : (
            <span className="text-gray-700 text-[12px]">—</span>
          )}
        </td>

        {/* Source */}
        <td className="px-2 py-1.5 text-[13px] max-w-[180px] truncate">
          <IPCell ip={log.src_ip} port={log.src_port} />
        </td>

        {/* Direction */}
        <td className={`px-1 py-1.5 text-center text-sm ${dirColor}`} title={log.direction}>
          {dirIcon}
        </td>

        {/* Destination */}
        <td className="px-2 py-1.5 text-[13px] max-w-[180px] truncate">
          <IPCell ip={log.dst_ip} port={log.dst_port} />
        </td>

        {/* Country */}
        <td className="px-2 py-1.5 text-[13px] whitespace-nowrap" title={log.geo_country}>
          {log.geo_country ? (
            <span>{getFlag(log.geo_country)} <span className="text-gray-500">{log.geo_country}</span></span>
          ) : (
            <span className="text-gray-700">—</span>
          )}
        </td>

        {/* ASN */}
        <td className="px-2 py-1.5 text-[12px] text-gray-500 max-w-[150px] truncate" title={log.asn_name || ''}>
          {log.asn_name || '—'}
        </td>

        {/* Network Path */}
        <td className="px-2 py-1.5 text-[12px] whitespace-nowrap">
          <NetworkPath ifaceIn={log.interface_in} ifaceOut={log.interface_out} />
        </td>

        {/* Protocol */}
        <td className="px-2 py-1.5 text-[13px] text-gray-500">
          {log.protocol || '—'}
        </td>

        {/* Service */}
        <td className="px-2 py-1.5 text-[12px] text-gray-500">
          {log.service_name || '—'}
        </td>

        {/* Rule / Info */}
        <td className="px-2 py-1.5 text-[12px] text-gray-500 max-w-[180px] truncate" title={infoTitle}>
          {infoText}
        </td>

        {/* AbuseIPDB */}
        <td className="px-2 py-1.5 text-[13px] text-center">
          <ThreatBadge score={log.threat_score} categories={log.threat_categories} />
        </td>

        {/* Threat Categories */}
        <td className="px-2 py-1.5 text-[11px] text-orange-400/70 max-w-[180px] truncate" title={decodeThreatCategories(log.threat_categories) || ''}>
          {decodeThreatCategories(log.threat_categories) || <span className="text-gray-700">—</span>}
        </td>
      </tr>

      {isExpanded && (
        <tr>
          <td colSpan={14}>
            <LogDetail log={detailedLog || log} />
          </td>
        </tr>
      )}
    </>
  )
}

export default function LogTable({ logs, loading, expandedId, detailedLog, onToggleExpand }) {

  const columns = [
    { key: 'timestamp', label: 'Time', className: 'w-20' },
    { key: 'log_type', label: 'Type', className: 'w-20' },
    { key: 'action', label: 'Action', className: 'w-20' },
    { key: 'src', label: 'Source', className: 'w-40' },
    { key: 'dir', label: '', className: 'w-6' },
    { key: 'dst', label: 'Destination', className: 'w-40' },
    { key: 'country', label: 'Country', className: 'w-16' },
    { key: 'asn', label: 'ASN', className: 'w-36' },
    { key: 'network', label: 'Network', className: 'w-28' },
    { key: 'proto', label: 'Proto', className: 'w-12' },
    { key: 'service', label: 'Service', className: 'w-48' },
    { key: 'rule', label: 'Rule / Info', className: 'w-48' },
    { key: 'threat', label: 'AbuseIPDB', className: 'w-20' },
    { key: 'categories', label: 'Categories', className: 'w-40' },
  ]

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-gray-800">
            {columns.map(col => (
              <th
                key={col.key}
                className={`px-2 py-2 text-[12px] text-gray-500 font-medium uppercase tracking-wider ${col.className}`}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr>
              <td colSpan={13} className="text-center py-12 text-gray-600 text-sm">
                Loading...
              </td>
            </tr>
          ) : logs.length === 0 ? (
            <tr>
              <td colSpan={13} className="text-center py-12 text-gray-600 text-sm">
                No logs match current filters
              </td>
            </tr>
          ) : (
            logs.map(log => (
              <LogRow
                key={log.id}
                log={log}
                isExpanded={expandedId === log.id}
                detailedLog={expandedId === log.id ? detailedLog : null}
                onToggle={() => onToggleExpand(log.id)}
              />
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

import React from 'react'
import {
  formatTime, FlagIcon, getInterfaceName, formatServiceName, resolveIpSublines,
  LOG_TYPE_STYLES, ACTION_STYLES,
  DIRECTION_ICONS, DIRECTION_COLORS, decodeThreatCategories,
} from '../utils'
import LogDetail from './LogDetail'
import IPCell from './IPCell'

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
      <span className="text-gray-300">{score}</span>
    </span>
  )
}

function NetworkPath({ ifaceIn, ifaceOut }) {
  if (!ifaceIn && !ifaceOut) return <span className="text-gray-700">—</span>

  if (!ifaceOut) {
    return <span className="text-gray-200">{getInterfaceName(ifaceIn)}</span>
  }

  return (
    <span className="inline-flex items-center gap-1">
      <span className={ifaceIn ? 'text-gray-200' : 'text-gray-400 italic'}>{ifaceIn ? getInterfaceName(ifaceIn) : 'Gateway'}</span>
      <span className="text-gray-500">→</span>
      <span className="text-gray-200">{getInterfaceName(ifaceOut)}</span>
    </span>
  )
}

function formatRuleDesc(desc) {
  if (!desc) return null
  // Add space after ] if missing: "[WAN_LOCAL]Block" → "[WAN_LOCAL] Block"
  return desc.replace(/\](?!\s)/, '] ')
}

function LogRow({ log, isExpanded, detailedLog, onToggle, hiddenColumns, colCount, uiSettings }) {
  const actionStyle = ACTION_STYLES[log.rule_action || log.dhcp_event || log.wifi_event] || ''
  const typeStyle = LOG_TYPE_STYLES[log.log_type] || LOG_TYPE_STYLES.system
  const dirIcon = DIRECTION_ICONS[log.direction] || ''
  const dirColor = DIRECTION_COLORS[log.direction] || 'text-gray-500'

  const infoText = log.log_type === 'firewall'
    ? (formatRuleDesc(log.rule_desc) || log.rule_name || '—')
    : (log.dns_query || log.hostname || log.wifi_event || '—')

  const infoTitle = log.log_type === 'firewall'
    ? (formatRuleDesc(log.rule_desc) || log.rule_name || '')
    : infoText

  const show = (key) => !hiddenColumns.has(key)
  const countryDisplay = uiSettings?.ui_country_display || 'flag_name'
  const ipSubline = uiSettings?.ui_ip_subline === 'asn_or_abuse'
  const { srcSubline, dstSubline } = ipSubline ? resolveIpSublines(log) : { srcSubline: null, dstSubline: null }

  const highlightBlock = uiSettings?.ui_block_highlight !== 'off'
    && log.rule_action === 'block'
    && (log.threat_score ?? 0) >= (uiSettings?.ui_block_highlight_threshold ?? 0)

  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer transition-colors hover:bg-gray-800/30 ${
          isExpanded ? 'expanded-row' : 'border-b border-gray-800/50'
        } ${highlightBlock ? 'bg-red-950/10' : ''}`}
      >
        {/* Time */}
        <td className="px-3 py-1.5 text-[13px] text-gray-400 whitespace-nowrap font-light">
          {formatTime(log.timestamp)}
        </td>

        {/* Type */}
        <td className="px-2 py-1.5">
          <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${typeStyle}`}>
            {log.log_type}
          </span>
        </td>

        {/* Action */}
        <td className="px-2 py-1.5">
          {(log.rule_action || log.dhcp_event || log.wifi_event) ? (
            <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${actionStyle}`}>
              {log.rule_action || log.dhcp_event || log.wifi_event}
            </span>
          ) : (
            <span className="text-gray-700 text-[12px]">—</span>
          )}
        </td>

        {/* Source */}
        <td className="px-2 py-1.5 text-[13px] whitespace-nowrap sm:max-w-[180px] sm:truncate">
          <IPCell ip={log.src_ip} port={log.src_port} deviceName={log.src_device_name} vlan={log.src_device_vlan} networkLabel={log.src_device_network} subline={srcSubline} />
        </td>

        {/* Direction */}
        <td className={`px-1 py-1.5 text-center text-sm ${dirColor}`} title={log.direction}>
          {dirIcon}
        </td>

        {/* Destination */}
        <td className="px-2 py-1.5 text-[13px] whitespace-nowrap sm:max-w-[180px] sm:truncate">
          <IPCell ip={log.dst_ip} port={log.dst_port} deviceName={log.dst_device_name} vlan={log.dst_device_vlan} networkLabel={log.dst_device_network} subline={dstSubline} />
        </td>

        {/* Country */}
        {show('country') && (
          <td className="px-2 py-1.5 text-[13px] whitespace-nowrap text-center" title={log.geo_country}>
            {log.geo_country ? (
              <span className="inline-flex items-center justify-center gap-1">
                {countryDisplay !== 'name_only' && <FlagIcon code={log.geo_country} />}
                {countryDisplay !== 'flag_only' && (
                  <span className="text-gray-400">{log.geo_country}</span>
                )}
              </span>
            ) : (
              <span className="text-gray-700">—</span>
            )}
          </td>
        )}

        {/* ASN */}
        {show('asn') && (
          <td className="px-2 py-1.5 text-[12px] text-gray-400 whitespace-nowrap sm:max-w-[150px] sm:truncate" title={log.asn_name || ''}>
            {log.asn_name || '—'}
          </td>
        )}

        {/* Network Path */}
        <td className="px-2 py-1.5 text-[12px] whitespace-nowrap">
          <NetworkPath ifaceIn={log.interface_in} ifaceOut={log.interface_out} />
        </td>

        {/* Protocol */}
        {show('proto') && (
          <td className="px-2 py-1.5 text-[13px] text-gray-400 uppercase">
            {log.protocol || '—'}
          </td>
        )}

        {/* Service */}
        <td className="px-2 py-1.5 text-[12px] text-gray-400">
          {formatServiceName(log.service_name)}
        </td>

        {/* Rule / Info */}
        {show('rule') && (
          <td className="px-2 py-1.5 text-[12px] text-gray-400 whitespace-nowrap sm:max-w-[180px] sm:truncate" title={infoTitle}>
            {infoText}
          </td>
        )}

        {/* AbuseIPDB */}
        {show('threat') && (
          <td className="px-2 py-1.5 text-[13px] text-center">
            <ThreatBadge score={log.threat_score} categories={log.threat_categories} />
          </td>
        )}

        {/* Threat Categories */}
        {show('categories') && (
          <td className="px-2 py-1.5 text-[11px] text-purple-400/70 whitespace-nowrap sm:max-w-[180px] sm:truncate" title={decodeThreatCategories(log.threat_categories) || ''}>
            {decodeThreatCategories(log.threat_categories) || <span className="text-gray-700">—</span>}
          </td>
        )}
      </tr>

      {isExpanded && (
        <tr className="expanded-detail">
          <td colSpan={colCount}>
            <LogDetail log={detailedLog || log} hiddenColumns={hiddenColumns} />
          </td>
        </tr>
      )}
    </>
  )
}

export default function LogTable({ logs, loading, expandedId, detailedLog, onToggleExpand, hiddenColumns = new Set(), uiSettings }) {

  // Auto-hide ASN column when IP subline is enabled
  const effectiveHidden = uiSettings?.ui_ip_subline === 'asn_or_abuse'
    ? new Set([...hiddenColumns, 'asn'])
    : hiddenColumns

  const allColumns = [
    { key: 'timestamp', label: 'Time', className: 'w-20' },
    { key: 'log_type', label: 'Type', className: 'w-20' },
    { key: 'action', label: 'Action', className: 'w-20' },
    { key: 'src', label: 'Source', className: 'w-40' },
    { key: 'dir', label: '', className: 'w-6' },
    { key: 'dst', label: 'Destination', className: 'w-40' },
    { key: 'country', label: 'Country', className: 'w-16 text-center' },
    { key: 'asn', label: 'ASN', className: 'w-36' },
    { key: 'network', label: 'Network', className: 'w-28' },
    { key: 'proto', label: 'Proto', className: 'w-12' },
    { key: 'service', label: 'Service', className: 'w-28' },
    { key: 'rule', label: 'Rule / Info', className: 'w-48' },
    { key: 'threat', label: 'AbuseIPDB', className: 'w-20' },
    { key: 'categories', label: 'Categories', className: 'w-40' },
  ]

  const visibleColumns = allColumns.filter(col => !effectiveHidden.has(col.key))
  const colCount = visibleColumns.length

  return (
    <div>
      <table className="w-full text-left">
        <thead className="sticky top-0 z-10">
          <tr className="bg-gray-950">
            {visibleColumns.map(col => (
              <th
                key={col.key}
                className={`px-2 py-2 text-[12px] text-gray-400 font-medium uppercase tracking-wider ${col.className}`}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr>
              <td colSpan={colCount} className="text-center py-12 text-gray-500 text-sm">
                Loading...
              </td>
            </tr>
          ) : logs.length === 0 ? (
            <tr>
              <td colSpan={colCount} className="text-center py-12 text-gray-500 text-sm">
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
                hiddenColumns={effectiveHidden}
                colCount={colCount}
                uiSettings={uiSettings}
              />
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

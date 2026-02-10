import React from 'react'
import { getFlag, getInterfaceName, decodeThreatCategories } from '../utils'

function parseRuleName(ruleName) {
  if (!ruleName) return null
  // Format: CHAIN-ACTION_CODE-PRIORITY e.g. "WAN_LOCAL-D-2147483647"
  const m = ruleName.match(/^(.+?)-(A|D|R)-(\d+)$/)
  if (!m) return null
  const actionMap = { 'A': 'Allow', 'D': 'Drop', 'R': 'Redirect' }
  return {
    chain: m[1],
    action: actionMap[m[2]] || m[2],
    priority: m[3],
  }
}

export default function LogDetail({ log }) {
  if (!log) return null

  const sections = []

  // rDNS (prominent)
  if (log.rdns) {
    sections.push(
      <div key="rdns" className="col-span-full">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">Reverse DNS</span>
        <div className="text-gray-200 text-sm mt-0.5">{log.rdns}</div>
      </div>
    )
  }

  // GeoIP
  if (log.geo_country) {
    const geo = [
      getFlag(log.geo_country),
      log.geo_country,
      log.geo_city,
    ].filter(Boolean).join(' · ')

    sections.push(
      <div key="geo">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">GeoIP</span>
        <div className="text-gray-300 text-sm mt-0.5">{geo}</div>
        {log.geo_lat && (
          <div className="text-gray-600 text-[12px] mt-0.5">
            {log.geo_lat.toFixed(4)}, {log.geo_lon.toFixed(4)}
          </div>
        )}
      </div>
    )
  }

  // ASN
  if (log.asn_name) {
    sections.push(
      <div key="asn">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">ASN</span>
        <div className="text-gray-300 text-sm mt-0.5">
          {log.asn_name}
          {log.asn_number && <span className="text-gray-600 ml-1.5">AS{log.asn_number}</span>}
        </div>
      </div>
    )
  }

  // Firewall details
  if (log.log_type === 'firewall') {
    // Parsed rule breakdown
    const parsed = parseRuleName(log.rule_name)
    if (parsed) {
      sections.push(
        <div key="rule_parsed">
          <span className="text-gray-500 text-[12px] uppercase tracking-wider">Rule Details</span>
          <div className="text-gray-300 text-sm mt-0.5">
            <span className="text-gray-400">Chain:</span> {parsed.chain}
            <span className="text-gray-600 mx-2">·</span>
            <span className="text-gray-400">Action:</span> {parsed.action}
            <span className="text-gray-600 mx-2">·</span>
            <span className="text-gray-400">Priority:</span> {parsed.priority}
          </div>
        </div>
      )
    }

    // Rule description
    if (log.rule_desc) {
      const desc = log.rule_desc.replace(/\](?!\s)/, '] ')
      sections.push(
        <div key="rule_desc">
          <span className="text-gray-500 text-[12px] uppercase tracking-wider">Rule Description</span>
          <div className="text-gray-300 text-sm mt-0.5">{desc}</div>
        </div>
      )
    }

    const netDetails = [
      log.interface_in && `IN: ${getInterfaceName(log.interface_in)}`,
      log.interface_out && `OUT: ${getInterfaceName(log.interface_out)}`,
      log.mac_address && `MAC: ${log.mac_address}`,
    ].filter(Boolean)
    if (netDetails.length) {
      sections.push(
        <div key="net">
          <span className="text-gray-500 text-[12px] uppercase tracking-wider">Network</span>
          <div className="text-gray-300 text-sm mt-0.5">{netDetails.join(' · ')}</div>
        </div>
      )
    }
  }

  // DHCP details
  if (log.log_type === 'dhcp') {
    const dhcpDetails = [
      log.hostname && `Host: ${log.hostname}`,
      log.mac_address && `MAC: ${log.mac_address}`,
    ].filter(Boolean)
    if (dhcpDetails.length) {
      sections.push(
        <div key="dhcp">
          <span className="text-gray-500 text-[12px] uppercase tracking-wider">DHCP</span>
          <div className="text-gray-300 text-sm mt-0.5">{dhcpDetails.join(' · ')}</div>
        </div>
      )
    }
  }

  // WiFi details
  if (log.log_type === 'wifi') {
    const wifiDetails = [
      log.wifi_event && `Event: ${log.wifi_event}`,
      log.mac_address && `MAC: ${log.mac_address}`,
    ].filter(Boolean)
    if (wifiDetails.length) {
      sections.push(
        <div key="wifi">
          <span className="text-gray-500 text-[12px] uppercase tracking-wider">WiFi</span>
          <div className="text-gray-300 text-sm mt-0.5">{wifiDetails.join(' · ')}</div>
        </div>
      )
    }
  }

  // AbuseIPDB Detail Fields
  const abuseDetails = []

  if (log.threat_score !== null && log.threat_score !== undefined) {
    const score = log.threat_score
    let color = 'text-emerald-400'
    let label = 'Clean'
    if (score >= 75) { color = 'text-red-400'; label = 'Critical' }
    else if (score >= 50) { color = 'text-orange-400'; label = 'High' }
    else if (score >= 25) { color = 'text-yellow-400'; label = 'Medium' }
    else if (score > 0) { color = 'text-blue-400'; label = 'Low' }

    abuseDetails.push(
      <div key="abuse_score">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">AbuseIPDB Score</span>
        <div className={`text-sm mt-0.5 ${color} font-medium`}>
          {score}% · {label}
        </div>
        {decodeThreatCategories(log.threat_categories) && (
          <div className="text-[11px] text-orange-400/70 mt-0.5">
            {decodeThreatCategories(log.threat_categories)}
          </div>
        )}
      </div>
    )
  }

  if (log.abuse_usage_type) {
    abuseDetails.push(
      <div key="abuse_usage">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">AbuseIPDB Usage Type</span>
        <div className="text-gray-300 text-sm mt-0.5">{log.abuse_usage_type}</div>
      </div>
    )
  }

  if (log.abuse_hostnames) {
    abuseDetails.push(
      <div key="abuse_hosts">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">AbuseIPDB Host Names</span>
        <div className="text-gray-300 text-sm mt-0.5">{log.abuse_hostnames}</div>
      </div>
    )
  }

  if (log.abuse_total_reports != null && log.abuse_total_reports > 0) {
    abuseDetails.push(
      <div key="abuse_reports">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">AbuseIPDB Reports #</span>
        <div className="text-gray-300 text-sm mt-0.5">{log.abuse_total_reports.toLocaleString()}</div>
      </div>
    )
  }

  if (log.abuse_last_reported) {
    const d = new Date(log.abuse_last_reported)
    const formatted = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
    abuseDetails.push(
      <div key="abuse_last">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">AbuseIPDB Last Reported</span>
        <div className="text-gray-300 text-sm mt-0.5">{formatted}</div>
      </div>
    )
  }

  if (log.abuse_is_whitelisted) {
    abuseDetails.push(
      <div key="abuse_wl">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">AbuseIPDB Whitelisted</span>
        <div className="text-emerald-400 text-sm mt-0.5">✓</div>
      </div>
    )
  }

  if (log.abuse_is_tor) {
    abuseDetails.push(
      <div key="abuse_tor">
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">AbuseIPDB Tor</span>
        <div className="text-orange-400 text-sm mt-0.5">✓</div>
      </div>
    )
  }

  return (
    <div className="bg-gray-900/50 border-t border-gray-800 px-4 py-3">
      {sections.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
          {sections}
        </div>
      )}
      {abuseDetails.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3 pt-2 border-t border-gray-800/50">
          {abuseDetails}
        </div>
      )}
      {/* Raw log */}
      <div>
        <span className="text-gray-500 text-[12px] uppercase tracking-wider">Raw Log</span>
        <pre className="text-[12px] text-gray-100 mt-1 whitespace-pre-wrap break-all leading-relaxed bg-gray-950 rounded p-2 border border-gray-800">
          {log.raw_log}
        </pre>
      </div>
    </div>
  )
}

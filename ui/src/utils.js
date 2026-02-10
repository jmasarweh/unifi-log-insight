// Country flag emoji from ISO code
const FLAGS = {
  US: '🇺🇸', GB: '🇬🇧', IE: '🇮🇪', DE: '🇩🇪', CN: '🇨🇳', RU: '🇷🇺',
  NL: '🇳🇱', BR: '🇧🇷', FR: '🇫🇷', JP: '🇯🇵', KR: '🇰🇷', IN: '🇮🇳',
  AU: '🇦🇺', CA: '🇨🇦', SG: '🇸🇬', HK: '🇭🇰', SE: '🇸🇪', IT: '🇮🇹',
  ES: '🇪🇸', PL: '🇵🇱', RO: '🇷🇴', UA: '🇺🇦', TW: '🇹🇼', VN: '🇻🇳',
  TH: '🇹🇭', ID: '🇮🇩', PH: '🇵🇭', AR: '🇦🇷', MX: '🇲🇽', CL: '🇨🇱',
  ZA: '🇿🇦', EG: '🇪🇬', NG: '🇳🇬', KE: '🇰🇪', SA: '🇸🇦', AE: '🇦🇪',
  TR: '🇹🇷', IR: '🇮🇷', PK: '🇵🇰', BD: '🇧🇩', FI: '🇫🇮', NO: '🇳🇴',
  DK: '🇩🇰', CH: '🇨🇭', AT: '🇦🇹', BE: '🇧🇪', PT: '🇵🇹', GR: '🇬🇷',
  CZ: '🇨🇿', HU: '🇭🇺', BG: '🇧🇬', JO: '🇯🇴', LB: '🇱🇧', IL: '🇮🇱',
}

export function getFlag(code) {
  if (!code) return ''
  return FLAGS[code.toUpperCase()] || '🏳️'
}

export function formatTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function formatDateTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) + ' ' +
    d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function formatNumber(n) {
  if (n === null || n === undefined) return '—'
  return n.toLocaleString()
}

export function isPrivateIP(ip) {
  if (!ip) return true
  return ip.startsWith('10.') || ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') || ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') || ip.startsWith('172.19.') ||
    ip.startsWith('172.2') || ip.startsWith('172.3') ||
    ip.startsWith('127.') || ip.startsWith('169.254.')
}

export const LOG_TYPE_STYLES = {
  firewall: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  dns: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  dhcp: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  wifi: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  ids: 'bg-red-500/15 text-red-400 border-red-500/30',
  system: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

export const ACTION_STYLES = {
  block: 'bg-red-500/20 text-red-400 border-red-500/40',
  allow: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  redirect: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  DHCPACK: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  DHCPDISCOVER: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  DHCPREQUEST: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  DHCPOFFER: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  associated: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  disassociated: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

export const DIRECTION_ICONS = {
  inbound: '↓',
  outbound: '↑',
  inter_vlan: '↔',
  nat: '⤴',
  local: '⟳',
}

export const INTERFACE_NAMES = {
  'br0': 'Main',
  'br20': 'IoT',
  'br40': 'Hotspot',
  'ppp0': 'WAN',
}

export function getInterfaceName(iface) {
  if (!iface) return '—'
  return INTERFACE_NAMES[iface] || iface
}

export const DIRECTION_COLORS = {
  inbound: 'text-red-400',
  outbound: 'text-blue-400',
  inter_vlan: 'text-gray-400',
  nat: 'text-yellow-400',
  local: 'text-gray-500',
}

// AbuseIPDB category code → human-readable label
const ABUSE_CATEGORIES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
}

export function decodeThreatCategories(cats) {
  if (!cats || cats.length === 0) return null
  return cats.map(c => {
    if (c === 'blacklist') return 'Blacklist'
    return ABUSE_CATEGORIES[parseInt(c)] || `Cat ${c}`
  }).join(', ')
}

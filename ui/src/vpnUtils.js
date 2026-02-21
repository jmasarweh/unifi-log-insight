/**
 * Shared VPN constants and utility functions.
 *
 * Single source of truth for VPN interface detection, type mapping,
 * badge choices, and mismatch warnings. Used by Settings, Wizard (API path),
 * and Wizard (Log Detection path).
 */

// Interface prefixes that identify VPN tunnels
export const VPN_PREFIXES = ['wgsrv', 'wgclt', 'wgsts', 'tlprt', 'vti', 'tun', 'vtun', 'l2tp']

// Prefix → type abbreviation
export const VPN_PREFIX_BADGES = {
  wgsrv: 'WGD SRV',
  wgclt: 'WGD CLT',
  wgsts: 'S MAGIC',
  tlprt: 'TELEPORT',
  vti: 'S2S IPSEC',
  tun: 'OVPN TUN',
  vtun: 'OVPN VTN',
  l2tp: 'L2TP SRV',
}

// Type abbreviation → human-readable full name (for UI dropdowns)
export const BADGE_LABELS = {
  'WGD SRV':   'WireGuard Server',
  'WGD CLT':   'WireGuard Client',
  'OVPN SRV':  'OpenVPN Server',
  'OVPN CLT':  'OpenVPN Client',
  'OVPN TUN':  'OpenVPN / Tunnel 1',
  'OVPN VTN':  'OpenVPN / Tunnel 2',
  'L2TP SRV':  'L2TP Server',
  'TELEPORT':  'Teleport',
  'S MAGIC':   'Site Magic',
  'S2S IPSEC': 'Site-to-Site IPsec',
}

// Ordered list of VPN type choices for dropdowns
export const BADGE_CHOICES = [
  'WGD SRV', 'WGD CLT', 'OVPN SRV', 'OVPN CLT', 'OVPN TUN', 'OVPN VTN', 'L2TP SRV', 'TELEPORT', 'S MAGIC', 'S2S IPSEC',
]

// Interface prefix → human-readable description (shown under interface name)
export const VPN_PREFIX_DESCRIPTIONS = {
  wgsrv: 'WireGuard Server',
  wgclt: 'WireGuard Client',
  wgsts: 'Site Magic',
  tlprt: 'Teleport',
  vti:   'Site-to-Site IPsec',
  tun:   'OpenVPN / Tunnel 1',
  vtun:  'OpenVPN / Tunnel 2',
  l2tp:  'L2TP Server',
}

// Type abbreviation → interface prefix (reverse of VPN_PREFIX_BADGES)
export const BADGE_TO_PREFIX = {
  'WGD SRV': 'wgsrv', 'WGD CLT': 'wgclt', 'OVPN TUN': 'tun',
  'OVPN VTN': 'vtun', 'L2TP SRV': 'l2tp', 'TELEPORT': 'tlprt',
  'S MAGIC': 'wgsts', 'S2S IPSEC': 'vti',
}

/** Generate a unique VPN interface name for a given badge type. */
export function generateVpnInterface(badgeType, existingInterfaces) {
  const prefix = BADGE_TO_PREFIX[badgeType]
  if (!prefix) return null
  const existing = existingInterfaces || []
  for (let i = 0; i < 100; i++) {
    const name = `${prefix}${i}`
    if (!existing.includes(name)) return name
  }
  return `${prefix}0`
}

// Server/client mismatch detection rules
const SERVER_CLIENT_CONFLICTS = {
  wgsrv: { expected: 'WGD SRV', conflict: 'WGD CLT', desc: 'WireGuard Server' },
  wgclt: { expected: 'WGD CLT', conflict: 'WGD SRV', desc: 'WireGuard Client' },
}

/** Check if an interface name belongs to a VPN tunnel. */
export function isVpnInterface(iface) {
  return VPN_PREFIXES.some(p => iface.startsWith(p))
}

/**
 * Return the BADGE_CHOICES value for a known VPN prefix.
 * e.g. wgsrv1 → "WGD SRV", tlprt0 → "TELEPORT", tun0 → "OVPN TUN"
 */
export function suggestVpnType(iface) {
  for (const [prefix, badge] of Object.entries(VPN_PREFIX_BADGES)) {
    if (iface.startsWith(prefix)) return badge
  }
  return ''
}

/** Return human-readable description for a VPN interface prefix. */
export function getIfaceDescription(iface) {
  for (const [prefix, desc] of Object.entries(VPN_PREFIX_DESCRIPTIONS)) {
    if (iface.startsWith(prefix)) return desc
  }
  return null
}

/**
 * Detect server/client mismatch: e.g. wgsrv interface assigned WGD CLT type.
 * Returns warning string or null.
 */
export function getMismatchWarning(iface, vpnType) {
  if (!vpnType) return null
  for (const [prefix, rule] of Object.entries(SERVER_CLIENT_CONFLICTS)) {
    if (iface.startsWith(prefix) && vpnType === rule.conflict) {
      return `This is a ${rule.desc} interface`
    }
  }
  return null
}

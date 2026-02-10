"""
UniFi Log Insight - Syslog Parsers

Parses UDR syslog messages into structured data.
Log types: firewall, dns, dhcp, wifi
"""

import re
import ipaddress
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── WAN IP auto-detection ────────────────────────────────────────────────────
_wan_ip = None


def get_wan_ip() -> str:
    return _wan_ip


def _is_broadcast_or_multicast(ip: str) -> bool:
    """Check if IP is broadcast (255.255.255.255) or multicast (224.0.0.0/4)."""
    if not ip:
        return False
    if ip == '255.255.255.255':
        return True
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False

# ── Syslog header ──────────────────────────────────────────────────────────────
# Matches: "Feb  8 16:43:49 UDR-UK ..."
SYSLOG_HEADER = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<body>.+)$'
)

# ── Firewall (iptables/netfilter) ──────────────────────────────────────────────
FW_RULE     = re.compile(r'\[([^\]]+)\]')
FW_DESC     = re.compile(r'DESCR="([^"]*)"')
FW_IN       = re.compile(r'IN=(\S*)')
FW_OUT      = re.compile(r'OUT=(\S*)')
FW_SRC      = re.compile(r'SRC=([0-9.]+)')
FW_DST      = re.compile(r'DST=([0-9.]+)')
FW_PROTO    = re.compile(r'PROTO=([A-Z]+)')
FW_SPT      = re.compile(r'SPT=(\d+)')
FW_DPT      = re.compile(r'DPT=(\d+)')
FW_MAC      = re.compile(r'MAC=([0-9a-f:]+)')

# ── DNS (dnsmasq) ─────────────────────────────────────────────────────────────
DNS_QUERY   = re.compile(r'query\[([A-Z]+)\]\s+(\S+)\s+from\s+([0-9.]+)')
DNS_REPLY   = re.compile(r'reply\s+(\S+)\s+is\s+(.+)')
DNS_FORWARD = re.compile(r'forwarded\s+(\S+)\s+to\s+([0-9.]+)')
DNS_CACHED  = re.compile(r'cached\s+(\S+)\s+is\s+(.+)')

# ── DHCP (dnsmasq-dhcp) ───────────────────────────────────────────────────────
DHCP_ACK     = re.compile(r'DHCPACK\((\S+)\)\s+([0-9.]+)\s+([0-9a-f:]+)\s*(\S*)')
DHCP_DISC    = re.compile(r'DHCPDISCOVER\((\S+)\)\s+([0-9a-f:]+)')
DHCP_OFFER   = re.compile(r'DHCPOFFER\((\S+)\)\s+([0-9.]+)\s+([0-9a-f:]+)')
DHCP_REQ     = re.compile(r'DHCPREQUEST\((\S+)\)\s+([0-9.]+)\s+([0-9a-f:]+)')

# ── WiFi (stamgr / hostapd) ───────────────────────────────────────────────────
WIFI_EVENT  = re.compile(r'(\w+):\s+STA\s+([0-9a-f:]+)')
WIFI_ASSOC  = re.compile(r'STA\s+([0-9a-f:]+)\s+.*?(associated|disassociated|deauthenticated|authenticated)')

# ── Interface → network mapping ───────────────────────────────────────────────
INTERFACE_MAP = {
    'br0':  'Main',      # VLAN 1  - 10.10.10.0/24
    'br20': 'IoT',       # VLAN 20 - 10.10.20.0/24
    'br40': 'Hotspot',   # VLAN 40 - 10.10.40.0/28
    'ppp0': 'WAN',
}

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def parse_syslog_timestamp(month: str, day: str, time_str: str) -> datetime:
    """Parse syslog timestamp. Syslog doesn't include year, so we use current year."""
    now = datetime.now(timezone.utc)
    month_num = MONTHS.get(month, 1)
    h, m, s = time_str.split(':')
    ts = now.replace(month=month_num, day=int(day), hour=int(h), minute=int(m), second=int(s), microsecond=0)
    # Handle year rollover (Dec logs in January)
    if ts > now:
        ts = ts.replace(year=ts.year - 1)
    return ts


def derive_direction(iface_in: str, iface_out: str, rule_name: str, src_ip: str = None, dst_ip: str = None) -> str:
    """Derive traffic direction from interfaces, rule name, and IPs."""
    global _wan_ip

    if not iface_in and not iface_out:
        return None

    # Auto-learn WAN IP from WAN_LOCAL rules (IN=ppp0, public DST)
    if iface_in == 'ppp0' and 'WAN_LOCAL' in (rule_name or '') and dst_ip:
        try:
            ip = ipaddress.ip_address(dst_ip)
            if ip.is_global and not ip.is_multicast and str(ip) != _wan_ip:
                _wan_ip = str(ip)
                logger.info("Auto-detected WAN IP: %s", _wan_ip)
        except ValueError:
            pass

    # Broadcast/multicast → local (not real inbound/outbound traffic)
    if _is_broadcast_or_multicast(dst_ip):
        return 'local'

    # Traffic from/to the router's own WAN IP
    if _wan_ip and src_ip == _wan_ip:
        return 'local'

    # NAT rules (explicit DNAT/PREROUTING)
    if 'DNAT' in (rule_name or '') or 'PREROUTING' in (rule_name or ''):
        return 'nat'

    is_wan_in = iface_in == 'ppp0'

    # No OUT interface = traffic destined to the router itself
    if not iface_out:
        return 'inbound' if is_wan_in else 'local'

    is_wan_out = iface_out == 'ppp0'

    if is_wan_in and not is_wan_out:
        return 'inbound'
    if not is_wan_in and is_wan_out:
        return 'outbound'
    if not is_wan_in and not is_wan_out and iface_in != iface_out:
        return 'inter_vlan'

    return 'local'


def derive_action(rule_name: str) -> str:
    """Derive firewall action from rule name convention.
    
    UniFi rule naming: -A- = allow, -B- = block/drop, -R- = reject
    """
    if not rule_name:
        return None
    if 'DNAT' in rule_name or 'PREROUTING' in rule_name:
        return 'redirect'
    if '-A-' in rule_name:
        return 'allow'
    if '-B-' in rule_name or '-D-' in rule_name:
        return 'block'
    if '-R-' in rule_name:
        return 'block'
    return 'allow'  # Default for custom rules without convention


def extract_mac(mac_raw: str) -> str:
    """Extract the source MAC from the iptables MAC field.
    
    Format: dest_mac:src_mac:ethertype (6:6:2 bytes)
    We want bytes 7-12 (the source MAC).
    """
    if not mac_raw:
        return None
    parts = mac_raw.split(':')
    if len(parts) >= 12:
        return ':'.join(parts[6:12])
    return mac_raw


def parse_firewall(body: str) -> dict:
    """Parse a firewall (iptables/netfilter) log line."""
    result = {'log_type': 'firewall'}

    m = FW_RULE.search(body)
    result['rule_name'] = m.group(1) if m else None

    m = FW_DESC.search(body)
    result['rule_desc'] = m.group(1) if m else None

    m = FW_IN.search(body)
    result['interface_in'] = m.group(1) if m and m.group(1) else None

    m = FW_OUT.search(body)
    result['interface_out'] = m.group(1) if m and m.group(1) else None

    m = FW_SRC.search(body)
    result['src_ip'] = m.group(1) if m else None

    m = FW_DST.search(body)
    result['dst_ip'] = m.group(1) if m else None

    m = FW_PROTO.search(body)
    result['protocol'] = m.group(1) if m else None

    m = FW_SPT.search(body)
    result['src_port'] = int(m.group(1)) if m else None

    m = FW_DPT.search(body)
    result['dst_port'] = int(m.group(1)) if m else None

    m = FW_MAC.search(body)
    result['mac_address'] = extract_mac(m.group(1)) if m else None

    result['rule_action'] = derive_action(result['rule_name'])
    result['direction'] = derive_direction(
        result['interface_in'], result['interface_out'], result['rule_name'],
        result.get('src_ip'), result.get('dst_ip')
    )

    return result


def parse_dns(body: str) -> dict:
    """Parse a DNS (dnsmasq) log line."""
    result = {'log_type': 'dns'}

    m = DNS_QUERY.search(body)
    if m:
        result['dns_type'] = m.group(1)
        result['dns_query'] = m.group(2)
        result['src_ip'] = m.group(3)
        return result

    m = DNS_REPLY.search(body)
    if m:
        result['dns_query'] = m.group(1)
        result['dns_answer'] = m.group(2)
        return result

    m = DNS_FORWARD.search(body)
    if m:
        result['dns_query'] = m.group(1)
        result['dst_ip'] = m.group(2)
        return result

    m = DNS_CACHED.search(body)
    if m:
        result['dns_query'] = m.group(1)
        result['dns_answer'] = m.group(2)
        return result

    return result


def parse_dhcp(body: str) -> dict:
    """Parse a DHCP (dnsmasq-dhcp) log line."""
    result = {'log_type': 'dhcp'}

    m = DHCP_ACK.search(body)
    if m:
        result['interface_in'] = m.group(1)
        result['src_ip'] = m.group(2)
        result['mac_address'] = m.group(3)
        result['hostname'] = m.group(4) if m.group(4) else None
        result['dhcp_event'] = 'DHCPACK'
        return result

    m = DHCP_REQ.search(body)
    if m:
        result['interface_in'] = m.group(1)
        result['src_ip'] = m.group(2)
        result['mac_address'] = m.group(3)
        result['dhcp_event'] = 'DHCPREQUEST'
        return result

    m = DHCP_OFFER.search(body)
    if m:
        result['interface_in'] = m.group(1)
        result['src_ip'] = m.group(2)
        result['mac_address'] = m.group(3)
        result['dhcp_event'] = 'DHCPOFFER'
        return result

    m = DHCP_DISC.search(body)
    if m:
        result['interface_in'] = m.group(1)
        result['mac_address'] = m.group(2)
        result['dhcp_event'] = 'DHCPDISCOVER'
        return result

    return result


def parse_wifi(body: str) -> dict:
    """Parse a WiFi (stamgr/hostapd/stahtd) log line."""
    result = {'log_type': 'wifi'}

    # stahtd STA tracker JSON events
    if 'stahtd' in body and '{' in body:
        json_start = body.index('{')
        try:
            import json
            data = json.loads(body[json_start:])
            result['mac_address'] = data.get('mac')
            result['wifi_event'] = data.get('event_type', data.get('message_type', 'stahtd'))
            return result
        except (json.JSONDecodeError, ValueError):
            result['wifi_event'] = 'stahtd'
            return result

    m = WIFI_ASSOC.search(body)
    if m:
        result['mac_address'] = m.group(1)
        result['wifi_event'] = m.group(2)
        return result

    m = WIFI_EVENT.search(body)
    if m:
        result['wifi_event'] = m.group(1)
        result['mac_address'] = m.group(2)
        return result

    return result


def parse_system(body: str) -> dict:
    """Parse a system log line. Stores raw log only."""
    return {'log_type': 'system'}


def detect_log_type(body: str) -> str:
    """Detect log type from the syslog message body."""
    # Firewall: contains iptables-style fields
    if 'SRC=' in body and 'DST=' in body and 'PROTO=' in body:
        return 'firewall'
    if body.startswith('[') and 'DESCR=' in body:
        return 'firewall'

    # DHCP: dnsmasq-dhcp messages
    if 'dnsmasq-dhcp' in body or 'DHCPACK' in body or 'DHCPDISCOVER' in body or 'DHCPREQUEST' in body or 'DHCPOFFER' in body:
        return 'dhcp'

    # DNS: dnsmasq query/reply/forwarded/cached
    if 'dnsmasq' in body and ('query[' in body or 'reply ' in body or 'forwarded ' in body or 'cached ' in body):
        return 'dns'

    # WiFi: stamgr, hostapd, or stahtd (STA tracker)
    if 'stamgr' in body or 'hostapd' in body or 'stahtd' in body:
        return 'wifi'
    if 'STA ' in body and ('associated' in body or 'authenticated' in body):
        return 'wifi'

    # System: earlyoom, systemd, ubios-udapi, other UDR internals
    return 'system'


def parse_log(raw_log: str) -> dict | None:
    """Parse a raw syslog line into a structured dict.
    
    Returns None if the log can't be parsed (header doesn't match).
    """
    original_raw = raw_log

    m = SYSLOG_HEADER.match(raw_log)
    if not m:
        # Strip RFC3164 priority prefix (e.g. <13>, <14>) and retry
        stripped = re.sub(r'^<\d+>', '', raw_log)
        m = SYSLOG_HEADER.match(stripped)
        if not m:
            return None
        raw_log = stripped

    timestamp = parse_syslog_timestamp(m.group('month'), m.group('day'), m.group('time'))
    body = m.group('body')

    log_type = detect_log_type(body)

    if log_type == 'firewall':
        parsed = parse_firewall(body)
    elif log_type == 'dns':
        parsed = parse_dns(body)
    elif log_type == 'dhcp':
        parsed = parse_dhcp(body)
    elif log_type == 'wifi':
        parsed = parse_wifi(body)
    elif log_type == 'system':
        parsed = parse_system(body)
    else:
        parsed = {'log_type': 'unknown'}

    parsed['timestamp'] = timestamp
    parsed['raw_log'] = original_raw

    return parsed

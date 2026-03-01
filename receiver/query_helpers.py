"""
Query building helpers shared by log and export endpoints.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def _parse_negation(value: str) -> tuple[bool, str]:
    """Check if a filter value is negated (prefixed with '!').
    Returns (is_negated, clean_value).
    """
    if value.startswith('!'):
        return True, value[1:]
    return False, value


def _parse_port(value: str) -> tuple[bool, int | None]:
    """Parse a port filter value, supporting '!' prefix for negation.
    Returns (is_negated, port_int_or_None).
    """
    negated, clean = _parse_negation(value)
    try:
        port = int(clean)
        if 1 <= port <= 65535:
            return negated, port
        logger.debug("Port value out of range (1-65535): %r", value)
    except (ValueError, TypeError):
        logger.debug("Non-numeric port value: %r", value)
    return negated, None


def parse_time_range(time_range: str) -> Optional[datetime]:
    """Convert time range string to a datetime cutoff."""
    now = datetime.now(timezone.utc)
    mapping = {
        '1h': timedelta(hours=1),
        '6h': timedelta(hours=6),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
        '60d': timedelta(days=60),
        '90d': timedelta(days=90),
        '180d': timedelta(days=180),
        '365d': timedelta(days=365),
    }
    delta = mapping.get(time_range)
    return now - delta if delta else None


def build_log_query(
    log_type: Optional[str],
    time_range: Optional[str],
    time_from: Optional[str],
    time_to: Optional[str],
    src_ip: Optional[str],
    dst_ip: Optional[str],
    ip: Optional[str],
    direction: Optional[str],
    rule_action: Optional[str],
    rule_name: Optional[str],
    country: Optional[str],
    threat_min: Optional[int],
    search: Optional[str],
    service: Optional[str],
    interface: Optional[str],
    vpn_only: bool = False,
    asn: Optional[str] = None,
    dst_port: Optional[str] = None,
    src_port: Optional[str] = None,
    protocol: Optional[str] = None,
) -> tuple[str, list]:
    """Build WHERE clause and params from filters."""
    conditions = []
    params = []

    if log_type:
        types = [t.strip() for t in log_type.split(',')]
        placeholders = ','.join(['%s'] * len(types))
        conditions.append(f"log_type IN ({placeholders})")
        params.extend(types)

    if time_range:
        cutoff = parse_time_range(time_range)
        if cutoff:
            conditions.append("timestamp >= %s")
            params.append(cutoff)

    if time_from:
        conditions.append("timestamp >= %s")
        params.append(time_from)

    if time_to:
        conditions.append("timestamp <= %s")
        params.append(time_to)

    if src_ip:
        negated, val = _parse_negation(src_ip)
        op = "NOT LIKE" if negated else "LIKE"
        conditions.append(f"src_ip::text {op} %s ESCAPE '\\'")
        params.append(f"%{_escape_like(val)}%")

    if dst_ip:
        negated, val = _parse_negation(dst_ip)
        op = "NOT LIKE" if negated else "LIKE"
        conditions.append(f"dst_ip::text {op} %s ESCAPE '\\'")
        params.append(f"%{_escape_like(val)}%")

    if ip:
        negated, val = _parse_negation(ip)
        escaped_ip = _escape_like(val)
        if negated:
            conditions.append("(src_ip::text NOT LIKE %s ESCAPE '\\' AND dst_ip::text NOT LIKE %s ESCAPE '\\')")
        else:
            conditions.append("(src_ip::text LIKE %s ESCAPE '\\' OR dst_ip::text LIKE %s ESCAPE '\\')")
        params.extend([f"%{escaped_ip}%", f"%{escaped_ip}%"])

    if direction:
        directions = [d.strip() for d in direction.split(',')]
        # When VPN filter is active, always include 'vpn' direction so
        # VPN↔LAN traffic isn't excluded by the direction filter.
        if vpn_only and 'vpn' not in directions:
            directions.append('vpn')
        placeholders = ','.join(['%s'] * len(directions))
        conditions.append(f"direction IN ({placeholders})")
        params.extend(directions)

    if rule_action:
        negated, val = _parse_negation(rule_action)
        actions = [a.strip() for a in val.split(',')]
        placeholders = ','.join(['%s'] * len(actions))
        keyword = "NOT IN" if negated else "IN"
        conditions.append(f"rule_action {keyword} ({placeholders})")
        params.extend(actions)

    if rule_name:
        negated, val = _parse_negation(rule_name)
        escaped = _escape_like(val)
        if negated:
            conditions.append("(rule_name NOT ILIKE %s ESCAPE '\\' OR rule_name IS NULL) AND (rule_desc NOT ILIKE %s ESCAPE '\\' OR rule_desc IS NULL)")
        else:
            conditions.append("(rule_name ILIKE %s ESCAPE '\\' OR rule_desc ILIKE %s ESCAPE '\\')")
        params.extend([f"%{escaped}%", f"%{escaped}%"])

    if country:
        negated, val = _parse_negation(country)
        countries = [c.strip().upper() for c in val.split(',')]
        placeholders = ','.join(['%s'] * len(countries))
        keyword = "NOT IN" if negated else "IN"
        condition = f"geo_country {keyword} ({placeholders})"
        if negated:
            condition = f"({condition} OR geo_country IS NULL)"
        conditions.append(condition)
        params.extend(countries)

    if threat_min is not None:
        conditions.append("threat_score >= %s")
        params.append(threat_min)

    if search:
        negated, val = _parse_negation(search)
        op = "NOT ILIKE" if negated else "ILIKE"
        escaped = _escape_like(val)
        conditions.append(f"raw_log {op} %s ESCAPE '\\'")
        params.append(f"%{escaped}%")

    if service:
        negated, val = _parse_negation(service)
        services = [s.strip() for s in val.split(',')]
        placeholders = ','.join(['%s'] * len(services))
        keyword = "NOT IN" if negated else "IN"
        condition = f"service_name {keyword} ({placeholders})"
        if negated:
            condition = f"({condition} OR service_name IS NULL)"
        conditions.append(condition)
        params.extend(services)

    if interface:
        ifaces = [i.strip() for i in interface.split(',')]
        placeholders = ','.join(['%s'] * len(ifaces))
        conditions.append(f"(interface_in IN ({placeholders}) OR interface_out IN ({placeholders}))")
        params.extend(ifaces)
        params.extend(ifaces)  # Twice: once for interface_in, once for interface_out

    if asn:
        negated, val = _parse_negation(asn)
        escaped_asn = _escape_like(val)
        op = "NOT ILIKE" if negated else "ILIKE"
        conditions.append(f"asn_name {op} %s ESCAPE '\\'")
        params.append(f"%{escaped_asn}%")

    if dst_port:
        negated, port_val = _parse_port(dst_port)
        if port_val is not None:
            if negated:
                conditions.append("(dst_port != %s OR dst_port IS NULL)")
            else:
                conditions.append("dst_port = %s")
            params.append(port_val)

    if src_port:
        negated, port_val = _parse_port(src_port)
        if port_val is not None:
            if negated:
                conditions.append("(src_port != %s OR src_port IS NULL)")
            else:
                conditions.append("src_port = %s")
            params.append(port_val)

    if protocol:
        negated, val = _parse_negation(protocol)
        protocols = [p.strip().upper() for p in val.split(',')]
        placeholders = ','.join(['%s'] * len(protocols))
        keyword = "NOT IN" if negated else "IN"
        condition = f"protocol {keyword} ({placeholders})"
        if negated:
            condition = f"({condition} OR protocol IS NULL)"
        conditions.append(condition)
        params.extend(protocols)

    if vpn_only:
        from parsers import VPN_INTERFACE_PREFIXES
        vpn_parts = []
        for pfx in VPN_INTERFACE_PREFIXES:
            vpn_parts.append("interface_in LIKE %s")
            vpn_parts.append("interface_out LIKE %s")
            params.extend([f"{pfx}%", f"{pfx}%"])
        conditions.append(f"({' OR '.join(vpn_parts)})")

    where = " AND ".join(conditions) if conditions else "1=1"
    return where, params


def _escape_like(value: str) -> str:
    """Escape LIKE wildcard characters in user input."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

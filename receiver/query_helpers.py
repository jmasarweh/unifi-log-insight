"""
Query building helpers shared by log and export endpoints.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional


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
        conditions.append("src_ip::text LIKE %s ESCAPE '\\'")
        params.append(f"%{_escape_like(src_ip)}%")

    if dst_ip:
        conditions.append("dst_ip::text LIKE %s ESCAPE '\\'")
        params.append(f"%{_escape_like(dst_ip)}%")

    if ip:
        escaped_ip = _escape_like(ip)
        conditions.append("(src_ip::text LIKE %s ESCAPE '\\' OR dst_ip::text LIKE %s ESCAPE '\\')")
        params.extend([f"%{escaped_ip}%", f"%{escaped_ip}%"])

    if direction:
        directions = [d.strip() for d in direction.split(',')]
        placeholders = ','.join(['%s'] * len(directions))
        conditions.append(f"direction IN ({placeholders})")
        params.extend(directions)

    if rule_action:
        actions = [a.strip() for a in rule_action.split(',')]
        placeholders = ','.join(['%s'] * len(actions))
        conditions.append(f"rule_action IN ({placeholders})")
        params.extend(actions)

    if rule_name:
        conditions.append("rule_name LIKE %s")
        params.append(f"%{rule_name}%")

    if country:
        countries = [c.strip().upper() for c in country.split(',')]
        placeholders = ','.join(['%s'] * len(countries))
        conditions.append(f"geo_country IN ({placeholders})")
        params.extend(countries)

    if threat_min is not None:
        conditions.append("threat_score >= %s")
        params.append(threat_min)

    if search:
        conditions.append("raw_log ILIKE %s")
        params.append(f"%{search}%")

    if service:
        services = [s.strip() for s in service.split(',')]
        placeholders = ','.join(['%s'] * len(services))
        conditions.append(f"service_name IN ({placeholders})")
        params.extend(services)

    if interface:
        ifaces = [i.strip() for i in interface.split(',')]
        placeholders = ','.join(['%s'] * len(ifaces))
        conditions.append(f"(interface_in IN ({placeholders}) OR interface_out IN ({placeholders}))")
        params.extend(ifaces)
        params.extend(ifaces)  # Twice: once for interface_in, once for interface_out

    where = " AND ".join(conditions) if conditions else "1=1"
    return where, params


def _escape_like(value: str) -> str:
    """Escape LIKE wildcard characters in user input."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

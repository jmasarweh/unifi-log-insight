"""
UniFi Log Insight - REST API

FastAPI application serving log data to the frontend.

Endpoints:
- GET /api/logs        — paginated, filterable log list
- GET /api/logs/{id}   — single log detail
- GET /api/stats       — dashboard summaries
- GET /api/export      — CSV export with current filters
- GET /api/health      — health check
"""

import os
import csv
import io
import json
import logging
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

from db import Database, get_config, set_config, count_logs
from enrichment import AbuseIPDBEnricher, is_public_ip
from services import get_service_description

_log_level_name = os.environ.get('LOG_LEVEL', 'INFO').upper()
if _log_level_name not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
    _log_level_name = 'INFO'

logging.basicConfig(
    level=getattr(logging, _log_level_name),
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('api')

def _read_version():
    for path in ('/app/VERSION', 'VERSION'):
        try:
            with open(path) as f:
                return f.read().strip()
        except FileNotFoundError:
            continue
    return 'unknown'

APP_VERSION = _read_version()

# ── Database ──────────────────────────────────────────────────────────────────

conn_params = {
    'host': '127.0.0.1',
    'port': 5432,
    'dbname': 'unifi_logs',
    'user': 'unifi',
    'password': os.environ.get('POSTGRES_PASSWORD', 'changeme'),
}

db_pool = pool.ThreadedConnectionPool(2, 10, **conn_params)


def get_conn():
    return db_pool.getconn()


def put_conn(conn):
    db_pool.putconn(conn)


# ── AbuseIPDB Enricher (for manual enrich endpoint) ──────────────────────────

enricher_db = Database(conn_params, min_conn=1, max_conn=3)
enricher_db.connect()
abuseipdb = AbuseIPDBEnricher(db=enricher_db)


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="UniFi Log Insight API", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Uvicorn access log filter ────────────────────────────────────────────────

class _QuietAccessFilter(logging.Filter):
    """Suppress high-frequency polling endpoints from uvicorn access logs.

    /api/health (polled every 15s) and /api/logs (polled on page load)
    are only shown at DEBUG level. All other endpoints remain visible at INFO.
    """
    _QUIET_RE = re.compile(r'"GET /api/(health|logs)[\s?]')

    def filter(self, record):
        if self._QUIET_RE.search(record.getMessage()):
            return logging.getLogger().getEffectiveLevel() <= logging.DEBUG
        return True


@app.on_event("startup")
def _configure_access_logging():
    logging.getLogger("uvicorn.access").addFilter(_QuietAccessFilter())


# ── Helpers ───────────────────────────────────────────────────────────────────

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
        conditions.append("src_ip::text LIKE %s")
        params.append(f"%{src_ip}%")

    if dst_ip:
        conditions.append("dst_ip::text LIKE %s")
        params.append(f"%{dst_ip}%")

    if ip:
        conditions.append("(src_ip::text LIKE %s OR dst_ip::text LIKE %s)")
        params.extend([f"%{ip}%", f"%{ip}%"])

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


# ── Endpoints ─────────────────────────────────────────────────────────────────

# ── Setup Wizard & Config Endpoints ──────────────────────────────────────────

@app.get("/api/config")
def get_current_config():
    """Return current system configuration."""
    return {
        "wan_interfaces": get_config(enricher_db, "wan_interfaces", ["ppp0"]),
        "interface_labels": get_config(enricher_db, "interface_labels", {}),
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "config_version": get_config(enricher_db, "config_version", 1),
    }


@app.get("/api/setup/status")
def setup_status():
    """Check if setup wizard is complete."""
    return {
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "logs_count": count_logs(enricher_db, 'firewall'),
    }


@app.get("/api/setup/wan-candidates")
def wan_candidates():
    """Return non-bridge firewall interfaces with their associated WAN IP."""
    return {
        'candidates': enricher_db.get_wan_ip_candidates(),
    }


@app.get("/api/setup/network-segments")
def network_segments(wan_interfaces: str = None):
    """Discover ALL network interfaces with sample local IPs and suggested labels.

    wan_interfaces: comma-separated list from Step 1. Auto-labelled WAN/WAN1/WAN2.
    """
    wan_list = wan_interfaces.split(',') if wan_interfaces else []

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get ALL interfaces with sample local IPs (no exclusions)
            cur.execute("""
                WITH interface_ips AS (
                    SELECT interface_in as iface, src_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_in IS NOT NULL
                      AND (src_ip << '10.0.0.0/8'::inet
                           OR src_ip << '172.16.0.0/12'::inet
                           OR src_ip << '192.168.0.0/16'::inet
                           OR src_ip << 'fc00::/7'::inet
                           OR src_ip << 'fe80::/10'::inet)
                    UNION
                    SELECT interface_out as iface, dst_ip as src_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_out IS NOT NULL
                      AND (dst_ip << '10.0.0.0/8'::inet
                           OR dst_ip << '172.16.0.0/12'::inet
                           OR dst_ip << '192.168.0.0/16'::inet
                           OR dst_ip << 'fc00::/7'::inet
                           OR dst_ip << 'fe80::/10'::inet)
                )
                SELECT
                    iface,
                    ARRAY_AGG(DISTINCT host(src_ip) ORDER BY host(src_ip)) as sample_ips
                FROM interface_ips
                GROUP BY iface
                ORDER BY iface
                LIMIT 30
            """)
            interfaces = cur.fetchall()
    finally:
        put_conn(conn)

    # For WAN interfaces, fetch their public IP instead of a local IP
    wan_ips = enricher_db.get_wan_ips_by_interface(wan_list) if wan_list else {}

    # Generate suggested labels
    segments = []
    for row in interfaces:
        iface = row['iface']
        ips = row['sample_ips'] or []
        is_wan = iface in wan_list

        # WAN interfaces auto-labelled from Step 1
        if is_wan:
            if len(wan_list) == 1:
                suggested = 'WAN'
            else:
                suggested = f'WAN{wan_list.index(iface) + 1}'
            # Show WAN IP, not a random local IP
            display_ip = wan_ips.get(iface, '')
        elif iface == 'br0':
            suggested = 'Main LAN'
            display_ip = ips[0] if ips else ''
        elif iface.startswith('br'):
            num = iface[2:]
            suggested = f'VLAN {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        elif iface.startswith('vlan'):
            num = iface[4:]
            suggested = f'VLAN {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        elif iface.startswith('eth'):
            num = iface[3:]
            suggested = f'Ethernet {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        else:
            suggested = ''
            display_ip = ips[0] if ips else ''

        segments.append({
            'interface': iface,
            'sample_local_ip': display_ip,
            'suggested_label': suggested,
            'is_wan': is_wan,
        })

    return {'segments': segments}


@app.post("/api/setup/complete")
def complete_setup(body: dict):
    """Save wizard configuration and trigger receiver reload."""
    if not body.get('wan_interfaces'):
        raise HTTPException(status_code=400, detail="wan_interfaces required")

    # Read current WAN config before overwriting (for backfill comparison)
    current_wan = set(get_config(enricher_db, "wan_interfaces", ["ppp0"]))

    set_config(enricher_db, "wan_interfaces", body["wan_interfaces"])
    set_config(enricher_db, "interface_labels", body.get("interface_labels", {}))
    set_config(enricher_db, "setup_complete", True)
    set_config(enricher_db, "config_version", 1)

    # Trigger direction backfill if WAN interfaces actually changed
    new_wan = set(body["wan_interfaces"])
    if new_wan != current_wan:
        set_config(enricher_db, "direction_backfill_pending", True)

    # Signal receiver process to reload config
    try:
        subprocess.run(['pkill', '-SIGUSR2', '-f', '/app/main.py'],
                      check=False, timeout=2)
        with open('/tmp/config_update_requested', 'w') as f:
            f.write(str(time.time()))
        logger.info("Signaled receiver process to reload config")
    except Exception as e:
        logger.warning("Failed to signal receiver: %s", e)

    return {"success": True}


@app.get("/api/interfaces")
def list_interfaces():
    """Return all discovered interfaces with their labels."""
    labels = get_config(enricher_db, "interface_labels", {})

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT unnest(ARRAY[interface_in, interface_out]) as iface
                FROM logs
                WHERE log_type = 'firewall'
                  AND (interface_in IS NOT NULL OR interface_out IS NOT NULL)
            """)
            interfaces = [row[0] for row in cur.fetchall() if row[0]]
    finally:
        put_conn(conn)

    result = []
    for iface in sorted(interfaces):
        result.append({
            'name': iface,
            'label': labels.get(iface, iface)
        })

    return {'interfaces': result}


# ── Original Log Endpoints ────────────────────────────────────────────────────

@app.get("/api/logs")
def get_logs(
    log_type: Optional[str] = Query(None, description="Comma-separated: firewall,dns,dhcp,wifi,system"),
    time_range: Optional[str] = Query(None, description="1h,6h,24h,7d,30d,60d"),
    time_from: Optional[str] = Query(None, description="ISO datetime"),
    time_to: Optional[str] = Query(None, description="ISO datetime"),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    ip: Optional[str] = Query(None, description="Search both src and dst"),
    direction: Optional[str] = Query(None, description="Comma-separated: inbound,outbound,inter_vlan,nat"),
    rule_action: Optional[str] = Query(None, description="Comma-separated: allow,block,redirect"),
    rule_name: Optional[str] = Query(None),
    country: Optional[str] = Query(None, description="Comma-separated country codes"),
    threat_min: Optional[int] = Query(None, description="Minimum threat score"),
    search: Optional[str] = Query(None, description="Full-text search in raw_log"),
    service: Optional[str] = Query(None, description="Comma-separated service names"),
    interface: Optional[str] = Query(None, description="Comma-separated interface names"),
    sort: str = Query("timestamp", description="Sort field"),
    order: str = Query("desc", description="asc or desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search, service,
        interface,
    )

    # Whitelist sort columns
    allowed_sorts = {
        'timestamp', 'log_type', 'src_ip', 'dst_ip', 'protocol', 'service_name',
        'direction', 'rule_action', 'rule_name', 'geo_country',
        'threat_score', 'created_at',
    }
    sort_col = sort if sort in allowed_sorts else 'timestamp'
    sort_dir = 'ASC' if order.lower() == 'asc' else 'DESC'
    offset = (page - 1) * per_page

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Count total
            cur.execute(f"SELECT COUNT(*) as total FROM logs WHERE {where}", params)
            total = cur.fetchone()['total']

            # Fetch page
            cur.execute(
                f"SELECT * FROM logs WHERE {where} ORDER BY {sort_col} {sort_dir} "
                f"LIMIT %s OFFSET %s",
                params + [per_page, offset]
            )
            rows = cur.fetchall()

        # Serialize
        logs = []
        for row in rows:
            log = dict(row)
            # Convert types for JSON
            for key in ['timestamp', 'created_at', 'abuse_last_reported']:
                if log.get(key):
                    log[key] = log[key].isoformat()
            for key in ['src_ip', 'dst_ip', 'mac_address']:
                if log.get(key):
                    log[key] = str(log[key])
            if log.get('geo_lat'):
                log['geo_lat'] = float(log['geo_lat'])
            if log.get('geo_lon'):
                log['geo_lon'] = float(log['geo_lon'])
            logs.append(log)

        conn.commit()
        return {
            'data': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page if per_page else 0,
        }
    except Exception as e:
        conn.rollback()
        logger.error("Error fetching logs: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        put_conn(conn)


@app.get("/api/logs/{log_id}")
def get_log(log_id: int):
    wan_ips = get_config(enricher_db, 'wan_ips') or []
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Join ip_threats on both src and dst to fill abuse fields
            # for logs not yet patched by the backfill daemon.
            # Exclude WAN IPs from joins so we only pick up remote party's data.
            cur.execute("""
                SELECT l.*,
                    COALESCE(l.abuse_usage_type, t1.abuse_usage_type, t2.abuse_usage_type) as abuse_usage_type,
                    COALESCE(l.abuse_hostnames, t1.abuse_hostnames, t2.abuse_hostnames) as abuse_hostnames,
                    COALESCE(l.abuse_total_reports, t1.abuse_total_reports, t2.abuse_total_reports) as abuse_total_reports,
                    COALESCE(l.abuse_last_reported, t1.abuse_last_reported, t2.abuse_last_reported) as abuse_last_reported,
                    COALESCE(l.abuse_is_whitelisted, t1.abuse_is_whitelisted, t2.abuse_is_whitelisted) as abuse_is_whitelisted,
                    COALESCE(l.abuse_is_tor, t1.abuse_is_tor, t2.abuse_is_tor) as abuse_is_tor,
                    COALESCE(
                        CASE WHEN array_length(l.threat_categories, 1) > 0 THEN l.threat_categories END,
                        CASE WHEN array_length(t1.threat_categories, 1) > 0 THEN t1.threat_categories END,
                        CASE WHEN array_length(t2.threat_categories, 1) > 0 THEN t2.threat_categories END
                    ) as threat_categories
                FROM logs l
                LEFT JOIN ip_threats t1 ON t1.ip = l.src_ip
                    AND NOT (l.src_ip = ANY(%s::inet[]))
                LEFT JOIN ip_threats t2 ON t2.ip = l.dst_ip
                    AND NOT (l.dst_ip = ANY(%s::inet[]))
                WHERE l.id = %s
            """, [wan_ips, wan_ips, log_id])
            row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Log not found")

        log = dict(row)
        for key in ['timestamp', 'created_at', 'abuse_last_reported']:
            if log.get(key):
                log[key] = log[key].isoformat()
        for key in ['src_ip', 'dst_ip', 'mac_address']:
            if log.get(key):
                log[key] = str(log[key])
        if log.get('geo_lat'):
            log['geo_lat'] = float(log['geo_lat'])
        if log.get('geo_lon'):
            log['geo_lon'] = float(log['geo_lon'])

        # Enrich with IANA service description for expanded detail view
        desc = get_service_description(log.get('dst_port'), log.get('protocol'))
        if desc:
            log['service_description'] = desc

        conn.commit()
        return log
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        put_conn(conn)


@app.get("/api/stats")
def get_stats(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d"),
):
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    bucket_map = {'1h': 'hour', '6h': 'hour', '24h': 'hour', '7d': 'day', '30d': 'day', '60d': 'week'}
    bucket = bucket_map.get(time_range, 'hour')

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Total logs
            cur.execute("SELECT COUNT(*) as total FROM logs WHERE timestamp >= %s", [cutoff])
            total = cur.fetchone()['total']

            # By type
            cur.execute(
                "SELECT log_type, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s GROUP BY log_type ORDER BY count DESC",
                [cutoff]
            )
            by_type = {r['log_type']: r['count'] for r in cur.fetchall()}

            # Blocked count
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block'",
                [cutoff]
            )
            blocked = cur.fetchone()['count']

            # Threat count (score > 50)
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND threat_score > 50",
                [cutoff]
            )
            threats = cur.fetchone()['count']

            # Top blocked countries
            cur.execute(
                "SELECT geo_country as country, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND geo_country IS NOT NULL "
                "GROUP BY geo_country ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_blocked_countries = [dict(r) for r in cur.fetchall()]

            # Top blocked external IPs (public src_ip only, exclude WAN IPs)
            wan_ips = get_config(enricher_db, 'wan_ips') or []
            wan_ip = get_config(enricher_db, 'wan_ip')
            exclude_ips = ['0.0.0.0']
            if wan_ip:
                exclude_ips.append(wan_ip)
            for ip in wan_ips:
                if ip not in exclude_ips:
                    exclude_ips.append(ip)
            cur.execute(
                "SELECT host(src_ip) as ip, COUNT(*) as count, "
                "MAX(geo_country) as country, MAX(asn_name) as asn, "
                "MAX(threat_score) as threat_score "
                "FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND src_ip IS NOT NULL "
                "AND host(src_ip) != ALL(%s) "
                "AND NOT (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                "    OR src_ip << '192.168.0.0/16' OR src_ip << '127.0.0.0/8' "
                "    OR src_ip << 'fe80::/10' OR src_ip << 'fc00::/7') "
                "GROUP BY src_ip ORDER BY count DESC LIMIT 10",
                [cutoff, exclude_ips]
            )
            top_blocked_ips = [dict(r) for r in cur.fetchall()]

            # Top blocked internal IPs (private src_ip only — inter-VLAN / outbound blocks)
            cur.execute(
                "SELECT host(src_ip) as ip, COUNT(*) as count "
                "FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND src_ip IS NOT NULL "
                "AND (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                "    OR src_ip << '192.168.0.0/16') "
                "GROUP BY src_ip ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_blocked_internal_ips = [dict(r) for r in cur.fetchall()]

            # Top threat IPs (enriched — categories from ip_threats for reliability)
            cur.execute(
                "SELECT host(l.src_ip) as ip, COUNT(*) as count, "
                "MAX(l.geo_country) as country, MAX(l.asn_name) as asn, "
                "MAX(l.geo_city) as city, MAX(l.rdns) as rdns, "
                "MAX(l.threat_score) as threat_score, "
                "COALESCE(MAX(l.threat_categories), MAX(t.threat_categories)) as threat_categories, "
                "MAX(l.timestamp) as last_seen "
                "FROM logs l "
                "LEFT JOIN ip_threats t ON l.src_ip = t.ip "
                "WHERE l.timestamp >= %s AND l.threat_score > 50 AND l.src_ip IS NOT NULL "
                "AND host(l.src_ip) != ALL(%s) "
                "GROUP BY l.src_ip ORDER BY max(l.threat_score) DESC, count DESC LIMIT 10",
                [cutoff, exclude_ips]
            )
            top_threat_ips = []
            for r in cur.fetchall():
                row = dict(r)
                if row.get('last_seen'):
                    row['last_seen'] = row['last_seen'].isoformat()
                top_threat_ips.append(row)

            # Logs over time (adaptive bucketing)
            cur.execute(
                f"SELECT date_trunc('{bucket}', timestamp) as period, COUNT(*) as count "
                "FROM logs WHERE timestamp >= %s "
                "GROUP BY period ORDER BY period",
                [cutoff]
            )
            logs_over_time = [
                {'period': r['period'].isoformat(), 'count': r['count']}
                for r in cur.fetchall()
            ]

            # Traffic by action over time
            cur.execute(
                f"SELECT date_trunc('{bucket}', timestamp) as period, "
                "rule_action, COUNT(*) as count "
                "FROM logs WHERE timestamp >= %s AND log_type = 'firewall' "
                "AND rule_action IS NOT NULL "
                "GROUP BY period, rule_action ORDER BY period",
                [cutoff]
            )
            action_map = {}
            for r in cur.fetchall():
                p = r['period'].isoformat()
                if p not in action_map:
                    action_map[p] = {'period': p, 'allow': 0, 'block': 0, 'redirect': 0}
                action = r['rule_action']
                if action in ('allow', 'block', 'redirect'):
                    action_map[p][action] = r['count']
            traffic_by_action = sorted(action_map.values(), key=lambda x: x['period'])

            # Direction breakdown
            cur.execute(
                "SELECT direction, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND direction IS NOT NULL "
                "GROUP BY direction ORDER BY count DESC",
                [cutoff]
            )
            by_direction = {r['direction']: r['count'] for r in cur.fetchall()}

            # Top DNS queries
            cur.execute(
                "SELECT dns_query, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND log_type = 'dns' AND dns_query IS NOT NULL "
                "GROUP BY dns_query ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_dns = [dict(r) for r in cur.fetchall()]

            # Top blocked services
            cur.execute(
                "SELECT service_name, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND service_name IS NOT NULL "
                "GROUP BY service_name ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_blocked_services = [dict(r) for r in cur.fetchall()]

            # Allowed count
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND log_type = 'firewall' AND rule_action = 'allow'",
                [cutoff]
            )
            allowed = cur.fetchone()['count']

            # Top allowed destinations (external dst_ip, exclude WAN IPs)
            cur.execute(
                "SELECT host(dst_ip) as ip, COUNT(*) as count, "
                "MAX(geo_country) as country, MAX(asn_name) as asn "
                "FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'allow' AND dst_ip IS NOT NULL "
                "AND host(dst_ip) != ALL(%s) "
                "AND NOT (dst_ip << '10.0.0.0/8' OR dst_ip << '172.16.0.0/12' "
                "    OR dst_ip << '192.168.0.0/16' OR dst_ip << '127.0.0.0/8' "
                "    OR dst_ip << '169.254.0.0/16' OR dst_ip << '224.0.0.0/4' "
                "    OR dst_ip << 'fe80::/10' OR dst_ip << 'fc00::/7' "
                "    OR dst_ip << 'ff00::/8' OR dst_ip << '::1/128') "
                "GROUP BY dst_ip ORDER BY count DESC LIMIT 10",
                [cutoff, exclude_ips]
            )
            top_allowed_destinations = [dict(r) for r in cur.fetchall()]

            # Top allowed countries (outbound destinations)
            cur.execute(
                "SELECT geo_country as country, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'allow' "
                "AND geo_country IS NOT NULL AND direction = 'outbound' "
                "GROUP BY geo_country ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_allowed_countries = [dict(r) for r in cur.fetchall()]

            # Top allowed services
            cur.execute(
                "SELECT service_name, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'allow' AND service_name IS NOT NULL "
                "GROUP BY service_name ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_allowed_services = [dict(r) for r in cur.fetchall()]

            # Top active internal IPs (most allowed traffic by source, exclude gateway IPs)
            gateway_ips = get_config(enricher_db, 'gateway_ips') or []
            if gateway_ips:
                cur.execute(
                    "SELECT host(src_ip) as ip, COUNT(*) as count "
                    "FROM logs "
                    "WHERE timestamp >= %s AND rule_action = 'allow' AND src_ip IS NOT NULL "
                    "AND (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                    "    OR src_ip << '192.168.0.0/16') "
                    "AND host(src_ip) != ALL(%s) "
                    "GROUP BY src_ip ORDER BY count DESC LIMIT 10",
                    [cutoff, gateway_ips]
                )
            else:
                cur.execute(
                    "SELECT host(src_ip) as ip, COUNT(*) as count "
                    "FROM logs "
                    "WHERE timestamp >= %s AND rule_action = 'allow' AND src_ip IS NOT NULL "
                    "AND (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                    "    OR src_ip << '192.168.0.0/16') "
                    "GROUP BY src_ip ORDER BY count DESC LIMIT 10",
                    [cutoff]
                )
            top_active_internal_ips = [dict(r) for r in cur.fetchall()]

        conn.commit()
        return {
            'time_range': time_range,
            'total': total,
            'by_type': by_type,
            'blocked': blocked,
            'threats': threats,
            'allowed': allowed,
            'by_direction': by_direction,
            'top_blocked_countries': top_blocked_countries,
            'top_blocked_ips': top_blocked_ips,
            'top_blocked_internal_ips': top_blocked_internal_ips,
            'top_threat_ips': top_threat_ips,
            'top_blocked_services': top_blocked_services,
            'top_allowed_destinations': top_allowed_destinations,
            'top_allowed_countries': top_allowed_countries,
            'top_allowed_services': top_allowed_services,
            'top_active_internal_ips': top_active_internal_ips,
            'top_dns': top_dns,
            'logs_per_hour': logs_over_time,
            'logs_over_time': logs_over_time,
            'traffic_by_action': traffic_by_action,
        }
    except Exception as e:
        conn.rollback()
        logger.error("Error fetching stats: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        put_conn(conn)


@app.get("/api/export")
def export_csv(
    log_type: Optional[str] = Query(None),
    time_range: Optional[str] = Query(None),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    rule_action: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    threat_min: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
):
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search, service, interface,
    )

    export_columns = [
        'timestamp', 'log_type', 'direction', 'src_ip', 'src_port',
        'dst_ip', 'dst_port', 'protocol', 'service_name', 'rule_name', 'rule_desc',
        'rule_action', 'interface_in', 'interface_out', 'mac_address',
        'hostname', 'dns_query', 'dns_type', 'dns_answer',
        'geo_country', 'geo_city', 'asn_name', 'threat_score',
        'threat_categories', 'rdns',
        'abuse_usage_type', 'abuse_total_reports', 'abuse_last_reported',
        'abuse_is_tor',
    ]

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {', '.join(export_columns)} FROM logs "
                f"WHERE {where} ORDER BY timestamp DESC LIMIT %s",
                params + [limit]
            )
            rows = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(export_columns)
        for row in rows:
            writer.writerow([str(v) if v is not None else '' for v in row])

        output.seek(0)
        conn.commit()
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=unifi_logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        put_conn(conn)


@app.get("/api/services")
def get_services():
    """Return distinct service names for autocomplete filtering."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT service_name
                FROM logs
                WHERE service_name IS NOT NULL
                ORDER BY service_name
            """)
            services = [row[0] for row in cur.fetchall()]
        conn.commit()
        return {'services': services}
    except Exception as e:
        conn.rollback()
        logger.error("Error fetching services: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        put_conn(conn)


@app.get("/api/health")
def health():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM logs")
            total = cur.fetchone()[0]
            cur.execute("SELECT MAX(timestamp) FROM logs")
            latest = cur.fetchone()[0]
        conn.commit()

        # AbuseIPDB rate limit stats (written by receiver process)
        abuseipdb = None
        try:
            with open('/tmp/abuseipdb_stats.json', 'r') as f:
                abuseipdb = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # MaxMind database info
        maxmind_last_update = None
        mmdb_path = '/app/maxmind/GeoLite2-City.mmdb'
        try:
            if os.path.exists(mmdb_path):
                mtime = os.path.getmtime(mmdb_path)
                maxmind_last_update = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except Exception:
            pass

        # Calculate next MaxMind update (Wed=2, Sat=5 at 07:00 local)
        maxmind_next_update = None
        try:
            now = datetime.now().astimezone()
            target_time = now.replace(hour=7, minute=0, second=0, microsecond=0)
            # Find next Wed(2) or Sat(5)
            for days_ahead in range(1, 8):
                candidate = target_time + timedelta(days=days_ahead)
                if candidate.weekday() in (2, 5):  # Wed=2, Sat=5
                    maxmind_next_update = candidate.isoformat()
                    break
            # Edge case: today is Wed/Sat and it's before 07:00
            if now.weekday() in (2, 5) and now < target_time:
                maxmind_next_update = target_time.isoformat()
        except Exception:
            pass

        return {
            'status': 'ok',
            'version': APP_VERSION,
            'total_logs': total,
            'latest_log': latest.isoformat() if latest else None,
            'abuseipdb': abuseipdb,
            'maxmind_last_update': maxmind_last_update,
            'maxmind_next_update': maxmind_next_update,
        }
    except Exception as e:
        conn.rollback()
        return {'status': 'error', 'detail': str(e)}
    finally:
        put_conn(conn)


# ── AbuseIPDB Endpoints ──────────────────────────────────────────────────────

@app.get("/api/abuseipdb/status")
def abuseipdb_status():
    try:
        with open('/tmp/abuseipdb_stats.json') as f:
            stats = json.load(f)
            reset_at = stats.get('reset_at')
            remaining = stats.get('remaining', 0) or 0
            if reset_at is not None and remaining <= 0:
                try:
                    if time.time() > float(reset_at):
                        stats['quota_reset_pending'] = True
                except (ValueError, TypeError):
                    pass
            return stats
    except FileNotFoundError:
        return {"remaining": None, "limit": None}


@app.post("/api/enrich/{ip}")
def enrich_ip(ip: str):
    if not is_public_ip(ip):
        raise HTTPException(status_code=400, detail="Not a public IP")

    if not abuseipdb.enabled:
        raise HTTPException(status_code=400, detail="AbuseIPDB not configured")

    # Budget check: use shared stats file as source of truth
    try:
        with open('/tmp/abuseipdb_stats.json') as f:
            stats = json.load(f)
            remaining = stats.get('remaining', 0) or 0
            if remaining <= 0:
                # Check if quota has renewed since stats were written
                reset_at = stats.get('reset_at')
                quota_renewed = False
                if reset_at is not None:
                    try:
                        quota_renewed = time.time() > float(reset_at)
                    except (ValueError, TypeError):
                        pass
                if not quota_renewed:
                    raise HTTPException(status_code=429, detail="No API budget remaining — resets daily")
                logger.info("Manual enrich: quota reset detected (reset_at %s passed), allowing call", reset_at)
    except FileNotFoundError:
        pass  # No stats yet — allow call to bootstrap rate limit state

    # Clear from memory cache
    abuseipdb.cache.delete(ip)

    # Backdate ip_threats entry so lookup() treats it as expired
    try:
        with enricher_db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE ip_threats
                    SET looked_up_at = NOW() - INTERVAL '30 days'
                    WHERE ip = %s::inet
                """, [ip])
    except Exception:
        pass  # Entry may not exist yet, that's fine

    # Call lookup — hits the API, writes back to ip_threats + memory cache
    result = abuseipdb.lookup(ip)
    if not result or 'threat_score' not in result:
        raise HTTPException(status_code=502, detail="AbuseIPDB lookup failed")

    # Patch ALL log rows for this IP
    logs_patched = 0
    try:
        with enricher_db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE logs
                    SET threat_score = COALESCE(t.threat_score, logs.threat_score),
                        abuse_usage_type = t.abuse_usage_type,
                        abuse_hostnames = t.abuse_hostnames,
                        abuse_total_reports = t.abuse_total_reports,
                        abuse_last_reported = t.abuse_last_reported,
                        abuse_is_whitelisted = t.abuse_is_whitelisted,
                        abuse_is_tor = t.abuse_is_tor,
                        threat_categories = COALESCE(
                            CASE WHEN array_length(t.threat_categories, 1) > 0
                                 THEN t.threat_categories ELSE NULL END,
                            logs.threat_categories
                        )
                    FROM ip_threats t
                    WHERE (logs.src_ip = t.ip OR logs.dst_ip = t.ip)
                      AND t.ip = %s::inet
                      AND logs.log_type = 'firewall'
                      AND logs.rule_action = 'block'
                """, [ip])
                logs_patched = cur.rowcount
    except Exception as e:
        logger.error("Failed to patch logs for %s: %s", ip, e)

    return {
        'ip': ip,
        'threat_score': result.get('threat_score'),
        'threat_categories': result.get('threat_categories', []),
        'abuse_usage_type': result.get('abuse_usage_type'),
        'abuse_hostnames': result.get('abuse_hostnames'),
        'abuse_total_reports': result.get('abuse_total_reports'),
        'abuse_last_reported': result.get('abuse_last_reported'),
        'abuse_is_whitelisted': result.get('abuse_is_whitelisted'),
        'abuse_is_tor': result.get('abuse_is_tor'),
        'logs_patched': logs_patched,
        'remaining_budget': abuseipdb.remaining_budget,
    }


# ── Static file serving ───────────────────────────────────────────────────────

STATIC_DIR = '/app/static'

if os.path.exists(STATIC_DIR):
    # Mount static assets (JS, CSS, images)
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")

    # SPA catch-all: serve index.html for any non-API route
    _static_root = Path(STATIC_DIR).resolve()

    @app.get("/{path:path}")
    async def serve_spa(path: str):
        # URL-decode, resolve, and ensure the path stays inside STATIC_DIR
        decoded = unquote(path)
        resolved = (_static_root / decoded).resolve()
        if resolved != _static_root and not str(resolved).startswith(str(_static_root) + os.sep):
            return FileResponse(_static_root / "index.html")
        if decoded and resolved.is_file():
            return FileResponse(resolved)
        # Otherwise serve index.html for SPA routing
        return FileResponse(_static_root / "index.html")

    @app.get("/")
    async def serve_root():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    logger.info("Serving UI from %s", STATIC_DIR)
else:
    logger.warning("Static directory %s not found — UI not available", STATIC_DIR)

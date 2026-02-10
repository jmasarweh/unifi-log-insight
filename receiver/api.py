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
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

from parsers import get_wan_ip

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('api')

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


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="UniFi Log Insight API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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

    where = " AND ".join(conditions) if conditions else "1=1"
    return where, params


# ── Endpoints ─────────────────────────────────────────────────────────────────

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
    sort: str = Query("timestamp", description="Sort field"),
    order: str = Query("desc", description="asc or desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search,
    )

    # Whitelist sort columns
    allowed_sorts = {
        'timestamp', 'log_type', 'src_ip', 'dst_ip', 'protocol',
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
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Join ip_threats on both src and dst to fill abuse fields
            # for logs not yet patched by the backfill daemon
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
                LEFT JOIN ip_threats t2 ON t2.ip = l.dst_ip
                WHERE l.id = %s
            """, [log_id])
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

            # Top blocked IPs (exclude WAN IP and non-routable)
            wan_ip = get_wan_ip()
            exclude_ips = ['0.0.0.0']
            if wan_ip:
                exclude_ips.append(wan_ip)
            cur.execute(
                "SELECT host(src_ip) as ip, COUNT(*) as count, "
                "MAX(geo_country) as country, MAX(asn_name) as asn, "
                "MAX(threat_score) as threat_score "
                "FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND src_ip IS NOT NULL "
                "AND host(src_ip) != ALL(%s) "
                "GROUP BY src_ip ORDER BY count DESC LIMIT 10",
                [cutoff, exclude_ips]
            )
            top_blocked_ips = [dict(r) for r in cur.fetchall()]

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

            # Logs per hour (last 24h)
            cur.execute(
                "SELECT date_trunc('hour', timestamp) as hour, COUNT(*) as count "
                "FROM logs WHERE timestamp >= %s "
                "GROUP BY hour ORDER BY hour",
                [cutoff]
            )
            logs_per_hour = [
                {'hour': r['hour'].isoformat(), 'count': r['count']}
                for r in cur.fetchall()
            ]

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

        conn.commit()
        return {
            'time_range': time_range,
            'total': total,
            'by_type': by_type,
            'blocked': blocked,
            'threats': threats,
            'by_direction': by_direction,
            'top_blocked_countries': top_blocked_countries,
            'top_blocked_ips': top_blocked_ips,
            'top_threat_ips': top_threat_ips,
            'top_dns': top_dns,
            'logs_per_hour': logs_per_hour,
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
    limit: int = Query(10000, ge=1, le=100000),
):
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search,
    )

    export_columns = [
        'timestamp', 'log_type', 'direction', 'src_ip', 'src_port',
        'dst_ip', 'dst_port', 'protocol', 'rule_name', 'rule_desc',
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


# ── Static file serving ───────────────────────────────────────────────────────

STATIC_DIR = '/app/static'

if os.path.exists(STATIC_DIR):
    # Mount static assets (JS, CSS, images)
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")

    # SPA catch-all: serve index.html for any non-API route
    @app.get("/{path:path}")
    async def serve_spa(path: str):
        # If the path matches a file in static dir, serve it
        file_path = os.path.join(STATIC_DIR, path)
        if path and os.path.isfile(file_path):
            return FileResponse(file_path)
        # Otherwise serve index.html for SPA routing
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    @app.get("/")
    async def serve_root():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    logger.info("Serving UI from %s", STATIC_DIR)
else:
    logger.warning("Static directory %s not found — UI not available", STATIC_DIR)

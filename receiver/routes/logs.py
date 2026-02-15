"""Log CRUD, export, and service endpoints."""

import csv
import io
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from psycopg2.extras import RealDictCursor

from db import get_config
from deps import get_conn, put_conn, enricher_db
from query_helpers import build_log_query
from services import get_service_description

logger = logging.getLogger('api.logs')

router = APIRouter()


@router.get("/api/logs")
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
        logger.exception("Error fetching logs")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/logs/{log_id}")
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
        logger.exception("Error fetching log detail")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/export")
def export_csv_endpoint(
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
        logger.exception("Error exporting CSV")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/services")
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
        logger.exception("Error fetching services")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)

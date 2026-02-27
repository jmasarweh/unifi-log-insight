"""Log CRUD, export, and service endpoints."""

import csv
import io
import ipaddress
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from psycopg2.extras import RealDictCursor

from db import get_config, get_wan_ips_from_config
from deps import get_conn, put_conn, enricher_db
from parsers import VPN_PREFIX_DESCRIPTIONS
from query_helpers import build_log_query
from services import get_service_description


def _build_vpn_cidr_map(vpn_networks):
    """Pre-parse VPN CIDRs into (network_obj, gateway_ip, badge, type_name) tuples.

    The first usable IP in each CIDR is the VPN gateway (e.g. .1 in a /24).
    """
    result = []
    for iface, cfg in vpn_networks.items():
        cidr, badge = cfg.get('cidr', ''), cfg.get('badge', '')
        if cidr and badge:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                gw_ip = net.network_address + 1
                # Derive type name from interface prefix, not badge
                type_name = next(
                    (d for p, d in VPN_PREFIX_DESCRIPTIONS.items() if iface.startswith(p)),
                    badge
                )
                result.append((net, gw_ip, badge, type_name))
            except ValueError:
                pass
    return result


def _annotate_vpn_badges(logs, vpn_cidrs, exclude_ips=None):
    """Annotate logs with VPN gateway badges and device type names.

    Follows the same pattern as gateway/WAN annotation: only tags IPs that
    are explicitly within a configured VPN CIDR.

    Gateway IP (first in CIDR) → device_name='Gateway' + badge.
    Other IPs in pool → device_name=VPN type name (e.g. 'WireGuard Server'), no badge.
    """
    if not vpn_cidrs:
        return
    skip_ips = exclude_ips or set()

    for log in logs:
        for prefix in ('src', 'dst'):
            if log.get(f'{prefix}_device_vlan') is not None:
                continue
            if log.get(f'{prefix}_device_network'):
                continue

            name_key = f'{prefix}_device_name'
            ip_str = str(log.get(f'{prefix}_ip', '')).split('/')[0]
            if not ip_str or ip_str in skip_ips:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip_str)
                for net, gw_ip, badge, type_name in vpn_cidrs:
                    if ip_obj in net:
                        if ip_obj == gw_ip:
                            if not log.get(name_key):
                                log[name_key] = 'Gateway'
                            log[f'{prefix}_device_network'] = badge
                        else:
                            if not log.get(name_key):
                                log[name_key] = type_name
                        break
            except ValueError:
                pass

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
    vpn_only: bool = Query(False, description="Show only VPN traffic"),
    asn: Optional[str] = Query(None, description="ASN name search"),
    sort: str = Query("timestamp", description="Sort field"),
    order: str = Query("desc", description="asc or desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search, service,
        interface, vpn_only, asn=asn,
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

            # Fetch page, enriching with live device names from unifi_clients + unifi_devices
            cur.execute(
                f"""WITH page AS (
                        SELECT * FROM logs WHERE {where}
                        ORDER BY {sort_col} {sort_dir} LIMIT %s OFFSET %s
                    )
                    SELECT page.*,
                        COALESCE(page.src_device_name,
                            c1.device_name, c1.hostname, c1.oui,
                            d1.device_name, d1.model) AS src_device_name,
                        COALESCE(page.dst_device_name,
                            c2.device_name, c2.hostname, c2.oui,
                            d2.device_name, d2.model) AS dst_device_name
                    FROM page
                    LEFT JOIN unifi_clients c1 ON c1.mac = page.mac_address
                    -- No recency filter: log queries resolve names across all time
                    LEFT JOIN LATERAL (
                        SELECT device_name, hostname, oui
                        FROM unifi_clients WHERE ip = page.dst_ip
                        ORDER BY last_seen DESC NULLS LAST LIMIT 1
                    ) c2 ON true
                    LEFT JOIN unifi_devices d1 ON d1.mac = page.mac_address
                    LEFT JOIN LATERAL (
                        SELECT device_name, model
                        FROM unifi_devices WHERE ip = page.dst_ip
                        ORDER BY updated_at DESC NULLS LAST LIMIT 1
                    ) d2 ON true
                    ORDER BY page.{sort_col} {sort_dir}""",
                params + [per_page, offset]
            )
            rows = cur.fetchall()

        logs = [_serialize_log(row) for row in rows]
        _annotate_logs(logs)

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


# ── Shared helpers for detailed log queries ──────────────────────────────────

# Join ip_threats on both src and dst to fill abuse fields for logs not yet
# patched by the backfill daemon.  WAN IPs excluded via params.
_LOG_DETAIL_SQL = """
    SELECT l.*,
        COALESCE(l.abuse_usage_type,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_usage_type
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_usage_type
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_usage_type
                 ELSE t2.abuse_usage_type END) as abuse_usage_type,
        COALESCE(l.abuse_hostnames,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_hostnames
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_hostnames
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_hostnames
                 ELSE t2.abuse_hostnames END) as abuse_hostnames,
        COALESCE(l.abuse_total_reports,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_total_reports
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_total_reports
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_total_reports
                 ELSE t2.abuse_total_reports END) as abuse_total_reports,
        COALESCE(l.abuse_last_reported,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_last_reported
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_last_reported
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_last_reported
                 ELSE t2.abuse_last_reported END) as abuse_last_reported,
        COALESCE(l.abuse_is_whitelisted,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_is_whitelisted
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_is_whitelisted
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_is_whitelisted
                 ELSE t2.abuse_is_whitelisted END) as abuse_is_whitelisted,
        COALESCE(l.abuse_is_tor,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_is_tor
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_is_tor
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_is_tor
                 ELSE t2.abuse_is_tor END) as abuse_is_tor,
        COALESCE(
            CASE WHEN array_length(l.threat_categories, 1) > 0 THEN l.threat_categories END,
            CASE WHEN l.direction IN ('inbound', 'in') THEN
                     CASE WHEN array_length(t1.threat_categories, 1) > 0 THEN t1.threat_categories END
                 WHEN l.direction IN ('outbound', 'out') THEN
                     CASE WHEN array_length(t2.threat_categories, 1) > 0 THEN t2.threat_categories END
                 WHEN t1.ip IS NOT NULL THEN
                     CASE WHEN array_length(t1.threat_categories, 1) > 0 THEN t1.threat_categories END
                 ELSE
                     CASE WHEN array_length(t2.threat_categories, 1) > 0 THEN t2.threat_categories END
            END
        ) as threat_categories,
        COALESCE(l.src_device_name,
            c1.device_name, c1.hostname, c1.oui,
            d1.device_name, d1.model) as src_device_name,
        COALESCE(l.dst_device_name,
            c2.device_name, c2.hostname, c2.oui,
            d2.device_name, d2.model) as dst_device_name
    FROM logs l
    LEFT JOIN ip_threats t1 ON t1.ip = l.src_ip
        AND NOT (l.src_ip = ANY(%s::inet[]))
    LEFT JOIN ip_threats t2 ON t2.ip = l.dst_ip
        AND NOT (l.dst_ip = ANY(%s::inet[]))
    LEFT JOIN unifi_clients c1 ON c1.mac = l.mac_address
    LEFT JOIN LATERAL (
        SELECT device_name, hostname, oui
        FROM unifi_clients WHERE ip = l.dst_ip
        ORDER BY last_seen DESC NULLS LAST LIMIT 1
    ) c2 ON true
    LEFT JOIN unifi_devices d1 ON d1.mac = l.mac_address
    LEFT JOIN LATERAL (
        SELECT device_name, model
        FROM unifi_devices WHERE ip = l.dst_ip
        ORDER BY updated_at DESC NULLS LAST LIMIT 1
    ) d2 ON true
"""


def _serialize_log(row):
    """Convert a raw log DB row to API-friendly dict."""
    log = dict(row)
    for key in ('timestamp', 'created_at', 'abuse_last_reported'):
        if log.get(key):
            log[key] = log[key].isoformat()
    for key in ('src_ip', 'dst_ip', 'mac_address'):
        if log.get(key):
            log[key] = str(log[key])
    if log.get('geo_lat') is not None:
        log['geo_lat'] = float(log['geo_lat'])
    if log.get('geo_lon') is not None:
        log['geo_lon'] = float(log['geo_lon'])
    return log


def _annotate_logs(logs):
    """Annotate logs with gateway/VPN device names and service descriptions."""
    gateway_vlans = get_config(enricher_db, 'gateway_ip_vlans') or {}
    wan_ip_names = get_config(enricher_db, 'wan_ip_names') or {}
    vpn_networks = get_config(enricher_db, 'vpn_networks') or {}
    vpn_cidrs = _build_vpn_cidr_map(vpn_networks) if vpn_networks else []
    exclude_ips = (set(wan_ip_names.keys()) | set(gateway_vlans.keys())) if vpn_cidrs else set()

    for log in logs:
        for prefix in ('src', 'dst'):
            name_key = f'{prefix}_device_name'
            ip_str = str(log.get(f'{prefix}_ip', '')).split('/')[0]
            if ip_str in gateway_vlans:
                if not log.get(name_key):
                    log[name_key] = 'Gateway'
                log[f'{prefix}_device_vlan'] = gateway_vlans[ip_str].get('vlan')
            elif not log.get(name_key) and ip_str in wan_ip_names:
                log[name_key] = wan_ip_names[ip_str]

        desc = get_service_description(log.get('dst_port'), log.get('protocol'))
        if desc:
            log['service_description'] = desc

    if vpn_cidrs:
        _annotate_vpn_badges(logs, vpn_cidrs, exclude_ips)


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/api/logs/{log_id}")
def get_log(log_id: int):
    wan_ips = get_wan_ips_from_config(enricher_db)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                _LOG_DETAIL_SQL + " WHERE l.id = %s",
                [wan_ips, wan_ips, log_id]
            )
            row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Log not found")
        log = _serialize_log(row)
        _annotate_logs([log])
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


class LogBatchRequest(BaseModel):
    ids: list[int] = Field(..., min_length=1, max_length=50)


@router.post("/api/logs/batch")
def get_logs_batch(payload: LogBatchRequest):
    """Fetch multiple logs by ID (max 50). Used by threat map sidebar."""
    ids = payload.ids
    wan_ips = get_wan_ips_from_config(enricher_db)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                _LOG_DETAIL_SQL + " WHERE l.id = ANY(%s) ORDER BY l.timestamp DESC",
                [wan_ips, wan_ips, ids]
            )
            rows = cur.fetchall()
        logs = [_serialize_log(row) for row in rows]
        _annotate_logs(logs)
        conn.commit()
        return logs
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching log batch")
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
    vpn_only: bool = Query(False),
    asn: Optional[str] = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
):
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search, service, interface, vpn_only, asn=asn,
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

    # CSV header includes device name + VLAN + VPN network columns resolved via live JOIN
    csv_columns = export_columns + [
        'src_device_name', 'dst_device_name',
        'src_device_vlan', 'dst_device_vlan',
        'src_device_network', 'dst_device_network',
    ]

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""WITH filtered AS (
                        SELECT * FROM logs WHERE {where}
                        ORDER BY timestamp DESC LIMIT %s
                    )
                    SELECT {', '.join('f.' + c for c in export_columns)},
                        COALESCE(f.src_device_name,
                            c1.device_name, c1.hostname, c1.oui,
                            d1.device_name, d1.model) AS src_device_name,
                        COALESCE(f.dst_device_name,
                            c2.device_name, c2.hostname, c2.oui,
                            d2.device_name, d2.model) AS dst_device_name
                    FROM filtered f
                    LEFT JOIN unifi_clients c1 ON c1.mac = f.mac_address
                    LEFT JOIN LATERAL (
                        SELECT device_name, hostname, oui
                        FROM unifi_clients WHERE ip = f.dst_ip
                        ORDER BY last_seen DESC NULLS LAST LIMIT 1
                    ) c2 ON true
                    LEFT JOIN unifi_devices d1 ON d1.mac = f.mac_address
                    LEFT JOIN LATERAL (
                        SELECT device_name, model
                        FROM unifi_devices WHERE ip = f.dst_ip
                        ORDER BY updated_at DESC NULLS LAST LIMIT 1
                    ) d2 ON true
                    ORDER BY f.timestamp DESC""",
                params + [limit]
            )
            rows = cur.fetchall()

        # Annotate gateway/WAN IPs and VPN badges in CSV rows
        gateway_vlans = get_config(enricher_db, 'gateway_ip_vlans') or {}
        wan_ip_names = get_config(enricher_db, 'wan_ip_names') or {}
        vpn_networks = get_config(enricher_db, 'vpn_networks') or {}
        vpn_cidrs = _build_vpn_cidr_map(vpn_networks) if vpn_networks else []
        csv_exclude_ips = set(wan_ip_names.keys()) | set(gateway_vlans.keys())
        src_ip_idx = export_columns.index('src_ip')
        dst_ip_idx = export_columns.index('dst_ip')
        src_name_idx = len(export_columns)      # first appended column
        dst_name_idx = len(export_columns) + 1

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(csv_columns)
        for row in rows:
            # append vlan + network columns (4 total)
            row = list(row) + [None, None, None, None]
            src_vlan_idx = src_name_idx + 2
            dst_vlan_idx = src_name_idx + 3
            src_net_idx = src_name_idx + 4
            dst_net_idx = src_name_idx + 5
            for ip_idx, name_idx, vlan_idx, net_idx in [
                (src_ip_idx, src_name_idx, src_vlan_idx, src_net_idx),
                (dst_ip_idx, dst_name_idx, dst_vlan_idx, dst_net_idx),
            ]:
                ip_str = str(row[ip_idx] or '').split('/')[0]
                if not row[name_idx]:
                    if ip_str in gateway_vlans:
                        row[name_idx] = 'Gateway'
                        row[vlan_idx] = gateway_vlans[ip_str].get('vlan')
                    elif ip_str in wan_ip_names:
                        row[name_idx] = wan_ip_names[ip_str]
                # VPN annotation — same CIDR-based pattern as gateway/WAN
                if row[vlan_idx] is None and row[net_idx] is None and ip_str and ip_str not in csv_exclude_ips and vpn_cidrs:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        for net, gw_ip, badge, type_name in vpn_cidrs:
                            if ip_obj in net:
                                if ip_obj == gw_ip:
                                    if not row[name_idx]:
                                        row[name_idx] = 'Gateway'
                                    row[net_idx] = badge
                                else:
                                    if not row[name_idx]:
                                        row[name_idx] = type_name
                                break
                    except ValueError:
                        pass
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

"""Dashboard statistics endpoint."""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query, HTTPException
from psycopg2.extras import RealDictCursor

from db import get_config
from deps import get_conn, put_conn, enricher_db
from query_helpers import parse_time_range

logger = logging.getLogger('api.stats')

router = APIRouter()


@router.get("/api/stats")
def get_stats(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
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
            'logs_per_hour': logs_over_time,  # backward-compat alias for logs_over_time
            'logs_over_time': logs_over_time,
            'traffic_by_action': traffic_by_action,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching stats")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)

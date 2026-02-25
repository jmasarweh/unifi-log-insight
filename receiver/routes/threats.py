"""Threat intel query endpoints (ip_threats cache)."""

import ipaddress
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from psycopg2.extras import RealDictCursor

from deps import get_conn, put_conn

logger = logging.getLogger('api.threats')

router = APIRouter()


@router.get("/api/threats")
def list_threats(
    ip: Optional[str] = Query(None, description="Exact IP match"),
    min_score: int = Query(0, ge=0, le=100),
    max_score: Optional[int] = Query(None, ge=0, le=100),
    since: Optional[str] = Query(None, description="ISO datetime for looked_up_at lower bound"),
    limit: int = Query(100, ge=1, le=1000),
    sort: str = Query("threat_score", description="threat_score, looked_up_at, abuse_total_reports"),
    order: str = Query("desc", description="asc or desc"),
):
    allowed_sorts = {
        'threat_score': 'threat_score',
        'looked_up_at': 'looked_up_at',
        'abuse_total_reports': 'abuse_total_reports',
    }
    sort_col = allowed_sorts.get(sort, 'threat_score')
    sort_dir = 'ASC' if order.lower() == 'asc' else 'DESC'

    where = ["threat_score >= %s"]
    params = [min_score]

    if max_score is not None:
        where.append("threat_score <= %s")
        params.append(max_score)

    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
        where.append("ip = %s::inet")
        params.append(ip)

    if since:
        try:
            datetime.fromisoformat(since)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail=f"Invalid datetime for since: {since}")
        where.append("looked_up_at >= %s::timestamptz")
        params.append(since)

    where_sql = " AND ".join(where) if where else "TRUE"

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT COUNT(*) FROM ip_threats WHERE {where_sql}",
                params
            )
            total = cur.fetchone()['count']

            cur.execute(
                f"""SELECT host(ip) as ip, threat_score, threat_categories, looked_up_at,
                           abuse_usage_type, abuse_hostnames, abuse_total_reports,
                           abuse_last_reported, abuse_is_whitelisted, abuse_is_tor
                    FROM ip_threats
                    WHERE {where_sql}
                    ORDER BY {sort_col} {sort_dir}
                    LIMIT %s""",
                params + [limit]
            )
            rows = cur.fetchall()

        threats = []
        for row in rows:
            item = dict(row)
            if item.get('looked_up_at'):
                item['looked_up_at'] = item['looked_up_at'].isoformat()
            if item.get('abuse_last_reported'):
                item['abuse_last_reported'] = item['abuse_last_reported'].isoformat()
            threats.append(item)

        conn.commit()
        return {'threats': threats, 'total': total}
    except Exception as e:
        conn.rollback()
        logger.exception("Error querying ip_threats")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)

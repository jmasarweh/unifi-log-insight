"""Health check endpoint."""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from deps import get_conn, put_conn, APP_VERSION

logger = logging.getLogger('api.health')

router = APIRouter()


@router.get("/api/health")
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
        logger.exception("Health check failed")
        raise HTTPException(status_code=503, detail="Service unavailable")
    finally:
        put_conn(conn)

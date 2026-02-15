"""AbuseIPDB status and manual enrichment endpoints."""

import json
import logging
import time

from fastapi import APIRouter, HTTPException

from enrichment import is_public_ip
from deps import abuseipdb, enricher_db

logger = logging.getLogger('api.abuseipdb')

router = APIRouter()


@router.get("/api/abuseipdb/status")
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


@router.post("/api/enrich/{ip}")
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
        logger.debug("Could not backdate ip_threats for %s (may not exist yet)", ip, exc_info=True)

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
        logger.exception("Failed to patch logs for %s", ip)

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

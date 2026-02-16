"""UniFi settings, connection test, firewall proxy, and device endpoints."""

import logging
import os

from fastapi import APIRouter, HTTPException, Query
from psycopg2.extras import RealDictCursor

from db import get_config, set_config, encrypt_api_key, decrypt_api_key
from deps import get_conn, put_conn, enricher_db, unifi_api, signal_receiver

logger = logging.getLogger('api.unifi')

router = APIRouter()


@router.get("/api/settings/unifi")
def get_unifi_settings():
    """Current UniFi settings (merged: env + DB + defaults)."""
    return unifi_api.get_settings_info()


@router.put("/api/settings/unifi")
def update_unifi_settings(body: dict):
    """Save UniFi settings to system_config."""
    if 'enabled' in body:
        set_config(enricher_db, 'unifi_enabled', body['enabled'])
    if 'host' in body:
        set_config(enricher_db, 'unifi_host', body['host'])
    if 'api_key' in body:
        key_val = body['api_key']
        if key_val == '':
            set_config(enricher_db, 'unifi_api_key', '')
        elif key_val is not None:
            set_config(enricher_db, 'unifi_api_key', encrypt_api_key(key_val))
    if 'site' in body:
        set_config(enricher_db, 'unifi_site', body['site'])
    if 'verify_ssl' in body:
        set_config(enricher_db, 'unifi_verify_ssl', body['verify_ssl'])
    if 'poll_interval' in body:
        set_config(enricher_db, 'unifi_poll_interval', body['poll_interval'])
    if 'features' in body:
        set_config(enricher_db, 'unifi_features', body['features'])

    unifi_api.reload_config()
    signal_receiver()

    return {"success": True}


@router.post("/api/settings/unifi/test")
def test_unifi_connection(body: dict):
    """Test connection AND save settings on success."""
    host = body.get('host', '').strip()
    site = body.get('site', 'default').strip()
    verify_ssl = body.get('verify_ssl', True)
    use_env_key = body.get('use_env_key', False)
    use_saved_key = body.get('use_saved_key', False)

    if use_env_key:
        api_key = os.environ.get('UNIFI_API_KEY', '')
    elif use_saved_key:
        encrypted = get_config(enricher_db, 'unifi_api_key', '')
        if not encrypted:
            api_key = ''
        else:
            try:
                api_key = decrypt_api_key(encrypted)
            except Exception:
                logger.warning("Failed to decrypt saved API key — POSTGRES_PASSWORD may have changed")
                raise HTTPException(
                    status_code=400,
                    detail="Saved API key could not be decrypted. Please re-enter your API key.",
                ) from None
    else:
        api_key = body.get('api_key', '').strip()

    if not host or not api_key:
        raise HTTPException(status_code=400, detail="host and api_key are required")

    result = unifi_api.test_connection(host, api_key, site, verify_ssl)

    if result.get('success'):
        # Save to DB on successful test
        set_config(enricher_db, 'unifi_host', host)
        if not use_env_key and not use_saved_key:
            set_config(enricher_db, 'unifi_api_key', encrypt_api_key(api_key))
        set_config(enricher_db, 'unifi_site', site)
        set_config(enricher_db, 'unifi_verify_ssl', verify_ssl)
        set_config(enricher_db, 'unifi_controller_name', result.get('controller_name', ''))
        set_config(enricher_db, 'unifi_controller_version', result.get('version', ''))
        # Enable the API so wizard step 4 (firewall rules) can use it
        set_config(enricher_db, 'unifi_enabled', True)
        unifi_api.reload_config()
        signal_receiver()

    return result


@router.get("/api/setup/unifi-network-config")
def unifi_network_config():
    """UniFi API-based network topology for wizard."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    try:
        return unifi_api.get_network_config()
    except Exception as e:
        logger.exception("Failed to fetch UniFi network config")
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.post("/api/settings/unifi/dismiss-upgrade")
def dismiss_upgrade():
    """Permanently dismiss the v2.0 upgrade modal."""
    set_config(enricher_db, 'upgrade_v2_dismissed', True)
    return {"success": True}


@router.get("/api/firewall/policies")
def get_firewall_policies():
    """Fetch all policies + zones (handles pagination internally)."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    if not unifi_api.features.get('firewall_management', True):
        raise HTTPException(status_code=400, detail="Firewall management is disabled")
    try:
        return unifi_api.get_firewall_data()
    except Exception as e:
        logger.exception("Failed to fetch firewall policies")
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.patch("/api/firewall/policies/{policy_id}")
def patch_firewall_policy(policy_id: str, body: dict):
    """Update a single policy's loggingEnabled."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")

    # Reject DERIVED policies
    origin = body.get('origin', '')
    if origin == 'DERIVED':
        raise HTTPException(
            status_code=400,
            detail="This rule is auto-generated and cannot be modified. Manage it in your UniFi Controller under Traffic Rules."
        )

    logging_enabled = body.get('loggingEnabled')
    if logging_enabled is None:
        raise HTTPException(status_code=400, detail="loggingEnabled is required")

    try:
        result = unifi_api.patch_firewall_policy(policy_id, logging_enabled)
        return {"success": True, "data": result}
    except Exception as e:
        status = 502
        msg = str(e)
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code == 403:
                msg = "Insufficient permissions. Ensure your UniFi API key belongs to a Local Admin account with Network permissions."
                status = 403
            elif e.response.status_code == 422:
                msg = "The controller rejected this change. The rule may have been modified or removed in the UniFi Controller."
                status = 422
            else:
                status = e.response.status_code
        raise HTTPException(status_code=status, detail=msg) from e


@router.post("/api/firewall/policies/bulk-logging")
def bulk_update_logging(body: dict):
    """Batch-update loggingEnabled for multiple policies."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")

    policies = body.get('policies', [])
    if not policies:
        raise HTTPException(status_code=400, detail="policies list is required")

    try:
        return unifi_api.bulk_patch_logging(policies)
    except Exception as e:
        logger.exception("Bulk firewall update failed")
        raise HTTPException(status_code=502, detail=str(e)) from e


# ── Phase 2: Device Endpoints ────────────────────────────────────────────

@router.get("/api/unifi/clients")
def list_unifi_clients(
    search: str = Query(None, description="Filter by name, hostname, IP, or MAC"),
    limit: int = Query(200, ge=1, le=1000),
):
    """Return cached UniFi clients from the database."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if search:
                cur.execute("""
                    SELECT mac, host(ip) as ip, device_name, hostname, oui,
                           network, essid, vlan, is_fixed_ip, is_wired,
                           last_seen, updated_at
                    FROM unifi_clients
                    WHERE device_name ILIKE %s OR hostname ILIKE %s
                       OR host(ip) LIKE %s OR mac::text ILIKE %s
                    ORDER BY last_seen DESC NULLS LAST
                    LIMIT %s
                """, [f'%{search}%', f'%{search}%', f'%{search}%',
                      f'%{search}%', limit])
            else:
                cur.execute("""
                    SELECT mac, host(ip) as ip, device_name, hostname, oui,
                           network, essid, vlan, is_fixed_ip, is_wired,
                           last_seen, updated_at
                    FROM unifi_clients
                    ORDER BY last_seen DESC NULLS LAST
                    LIMIT %s
                """, [limit])
            rows = cur.fetchall()
        conn.commit()
        clients = []
        for r in rows:
            d = dict(r)
            if d.get('mac'):
                d['mac'] = str(d['mac'])
            for ts_key in ('last_seen', 'updated_at'):
                if d.get(ts_key):
                    d[ts_key] = d[ts_key].isoformat()
            clients.append(d)
        return {'clients': clients, 'total': len(clients)}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching UniFi clients")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/unifi/devices")
def list_unifi_devices():
    """Return cached UniFi infrastructure devices from the database."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT mac, host(ip) as ip, device_name, model, shortname,
                       device_type, firmware, serial, state, uptime, updated_at
                FROM unifi_devices
                ORDER BY device_name NULLS LAST, model
            """)
            rows = cur.fetchall()
        conn.commit()
        devices = []
        for r in rows:
            d = dict(r)
            if d.get('mac'):
                d['mac'] = str(d['mac'])
            if d.get('updated_at'):
                d['updated_at'] = d['updated_at'].isoformat()
            devices.append(d)
        return {'devices': devices, 'total': len(devices)}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching UniFi devices")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/unifi/status")
def unifi_poll_status():
    """Return current UniFi polling status."""
    settings = unifi_api.get_settings_info()
    return {
        'enabled': settings['enabled'],
        'status': settings['status'],
        'features': settings['features'],
        'poll_interval': settings['poll_interval'],
    }


@router.post("/api/unifi/backfill-device-names")
def backfill_device_names(body: dict):
    """On-demand backfill: patch historical logs with device names.

    Body: { "since": "2025-01-01T00:00:00Z" }
    Uses MAC-based join for src (DHCP-safe), time-bounded IP for dst.
    """
    since = body.get('since')
    if not since:
        raise HTTPException(status_code=400, detail="'since' date is required")

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # src_device_name: MAC-based join (stable across DHCP changes)
            cur.execute("""
                UPDATE logs
                SET src_device_name = COALESCE(c.device_name, c.hostname, c.oui)
                FROM unifi_clients c
                WHERE logs.mac_address = c.mac
                  AND logs.src_device_name IS NULL
                  AND logs.timestamp >= %s::timestamptz
                  AND COALESCE(c.device_name, c.hostname, c.oui) IS NOT NULL
            """, [since])
            src_patched = cur.rowcount

            # dst_device_name: IP-based join with time window to limit DHCP misattribution
            cur.execute("""
                UPDATE logs
                SET dst_device_name = COALESCE(c.device_name, c.hostname, c.oui)
                FROM unifi_clients c
                WHERE logs.dst_ip = c.ip
                  AND logs.dst_device_name IS NULL
                  AND logs.timestamp >= %s::timestamptz
                  AND logs.timestamp >= c.last_seen - INTERVAL '1 day'
                  AND COALESCE(c.device_name, c.hostname, c.oui) IS NOT NULL
            """, [since])
            dst_patched = cur.rowcount

        conn.commit()
        logger.info("Device name backfill: %d src, %d dst patched (since %s)",
                     src_patched, dst_patched, since)
        return {
            'success': True,
            'src_patched': src_patched,
            'dst_patched': dst_patched,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Device name backfill failed")
        raise HTTPException(status_code=500, detail="Backfill failed") from e
    finally:
        put_conn(conn)

"""Setup wizard and configuration endpoints."""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from psycopg2.extras import RealDictCursor

from db import get_config, set_config, count_logs
from deps import get_conn, put_conn, enricher_db, unifi_api, signal_receiver

logger = logging.getLogger('api.setup')

router = APIRouter()


@router.get("/api/config")
def get_current_config():
    """Return current system configuration."""
    return {
        "wan_interfaces": get_config(enricher_db, "wan_interfaces", ["ppp0"]),
        "interface_labels": get_config(enricher_db, "interface_labels", {}),
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "config_version": get_config(enricher_db, "config_version", 1),
        "upgrade_v2_dismissed": get_config(enricher_db, "upgrade_v2_dismissed", False),
        "unifi_enabled": unifi_api.enabled,
    }


@router.get("/api/setup/status")
def setup_status():
    """Check if setup wizard is complete."""
    return {
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "logs_count": count_logs(enricher_db, 'firewall'),
    }


@router.get("/api/setup/wan-candidates")
def wan_candidates():
    """Return non-bridge firewall interfaces with their associated WAN IP."""
    return {
        'candidates': enricher_db.get_wan_ip_candidates(),
    }


@router.get("/api/setup/network-segments")
def network_segments(wan_interfaces: Optional[str] = None):
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
    except Exception as e:
        logger.exception("Error querying network segments")
        raise HTTPException(status_code=500, detail="Failed to query network segments") from e
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


@router.post("/api/setup/complete")
def complete_setup(body: dict):
    """Save wizard configuration and trigger receiver reload."""
    if not body.get('wan_interfaces'):
        raise HTTPException(status_code=400, detail="wan_interfaces required")

    # Read current WAN config before overwriting (for backfill comparison)
    current_wan = set(get_config(enricher_db, "wan_interfaces", ["ppp0"]))

    set_config(enricher_db, "wan_interfaces", body["wan_interfaces"])
    set_config(enricher_db, "interface_labels", body.get("interface_labels", {}))
    set_config(enricher_db, "setup_complete", True)
    set_config(enricher_db, "config_version", 2)

    # Save wizard path (unifi_api or log_detection)
    wizard_path = body.get("wizard_path", "log_detection")
    set_config(enricher_db, "wizard_path", wizard_path)

    # Enable UniFi API if wizard used the API path
    if wizard_path == "unifi_api":
        set_config(enricher_db, "unifi_enabled", True)
        unifi_api.reload_config()

    # Trigger direction backfill if WAN interfaces actually changed
    new_wan = set(body["wan_interfaces"])
    if new_wan != current_wan:
        set_config(enricher_db, "direction_backfill_pending", True)

    # Signal receiver process to reload config
    signal_receiver()

    return {"success": True}


@router.get("/api/interfaces")
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
    except Exception as e:
        logger.exception("Error querying interfaces")
        raise HTTPException(status_code=500, detail="Failed to query interfaces") from e
    finally:
        put_conn(conn)

    result = []
    for iface in sorted(interfaces):
        result.append({
            'name': iface,
            'label': labels.get(iface, iface)
        })

    return {'interfaces': result}

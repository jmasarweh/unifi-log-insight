"""
UniFi Log Insight - UniFi Controller API Client

Handles all interactions with the UniFi Controller's Classic and Integration APIs.
Phase 1: Settings, wizard network config, firewall policy management.
Phase 2: Client/device polling, IP-to-device-name enrichment.
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone

import requests
from requests.exceptions import ConnectionError, Timeout, SSLError

from db import encrypt_api_key, decrypt_api_key

logger = logging.getLogger(__name__)

# WAN physical interface mapping from API wan_type + wan_networkgroup
_WAN_PHYSICAL_MAP = {
    ('pppoe', 'WAN'): 'ppp0',
    ('pppoe', 'WAN2'): 'ppp1',
    ('dhcp', 'WAN'): 'eth4',
    ('static', 'WAN'): 'eth4',
    ('dhcp', 'WAN2'): 'eth5',
    ('static', 'WAN2'): 'eth5',
}


class UniFiAPI:
    """UniFi Controller API client.

    Phase 1: Settings, wizard network config, firewall policy management.
    Phase 2: Client/device polling, IP-to-device-name enrichment.
    """

    TIMEOUT = 10  # seconds per request

    def __init__(self, db):
        self._db = db
        self._session = None
        self._site_uuid = None
        self.host = ''
        self.api_key = ''
        self.site = 'default'
        self.verify_ssl = True
        self.enabled = False
        self.features = {}
        # Phase 2: polling state
        self._poll_thread = None
        self._poll_stop = threading.Event()
        self._lock = threading.Lock()
        self._ip_to_name = {}
        self._mac_to_name = {}
        self._last_poll = None
        self._last_poll_error = None
        self._client_count = 0
        self._device_count = 0
        try:
            self._resolve_config()
        except Exception as e:
            logger.warning("UniFiAPI: config resolution failed (DB may not be ready): %s", e)

    # ── Config Resolution ─────────────────────────────────────────────────────

    def _resolve_config(self):
        """Load settings: env var > system_config DB > default."""
        self.host = (os.environ.get('UNIFI_HOST') or
                     self._db.get_config('unifi_host', '')).rstrip('/')
        self.api_key = (os.environ.get('UNIFI_API_KEY') or
                        self._decrypt_db_key())
        self.site = (os.environ.get('UNIFI_SITE') or
                     self._db.get_config('unifi_site', 'default'))

        ssl_env = os.environ.get('UNIFI_VERIFY_SSL', '').lower()
        if ssl_env in ('false', '0', 'no'):
            self.verify_ssl = False
        elif ssl_env:
            self.verify_ssl = True
        else:
            self.verify_ssl = self._db.get_config('unifi_verify_ssl', True)

        # Suppress noisy InsecureRequestWarning when SSL verification is
        # disabled AND log level is INFO. DEBUG/WARNING+ still see them.
        import warnings, urllib3
        if not self.verify_ssl and logger.getEffectiveLevel() == logging.INFO:
            warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
        else:
            warnings.filterwarnings('default', category=urllib3.exceptions.InsecureRequestWarning)

        self.features = self._db.get_config('unifi_features', {
            'client_names': True, 'device_discovery': True,
            'network_config': True, 'firewall_management': True,
        })

        # Master toggle AND credentials must both be present
        unifi_enabled_env = os.environ.get('UNIFI_ENABLED', '').lower()
        if unifi_enabled_env in ('true', '1', 'yes'):
            unifi_enabled = True
        elif unifi_enabled_env in ('false', '0', 'no'):
            unifi_enabled = False
        else:
            unifi_enabled = self._db.get_config('unifi_enabled', False)

        self.enabled = bool(unifi_enabled) and bool(self.host and self.api_key)

        # Auto-enable when both env vars are set
        if (not unifi_enabled and self.host and self.api_key
                and os.environ.get('UNIFI_HOST') and os.environ.get('UNIFI_API_KEY')):
            try:
                self._db.set_config('unifi_enabled', True)
                self.enabled = True
                logger.info("UniFi API auto-enabled (UNIFI_HOST + UNIFI_API_KEY env vars detected)")
            except Exception as e:
                logger.debug("Failed to auto-enable UniFi (UNIFI_HOST+UNIFI_API_KEY): %s", e)

    def _decrypt_db_key(self) -> str:
        """Read and decrypt API key from system_config."""
        encrypted = self._db.get_config('unifi_api_key', '')
        if not encrypted:
            return ''
        try:
            return decrypt_api_key(encrypted)
        except Exception:
            logger.warning("Failed to decrypt saved API key — POSTGRES_PASSWORD may have changed")
            return ''

    def reload_config(self):
        """Re-read settings, invalidate session + site UUID, restart polling if needed."""
        was_polling = self._poll_thread is not None and self._poll_thread.is_alive()
        self._session = None
        self._site_uuid = None
        self._resolve_config()
        logger.info("UniFi API config reloaded (enabled=%s, host=%s)", self.enabled, self.host or '(none)')
        # Restart polling if it was running (or start it if newly enabled)
        if was_polling or self.enabled:
            self.start_polling()

    def get_config_source(self, key: str) -> str:
        """Return 'env', 'db', or 'default' for a config key."""
        env_map = {
            'host': 'UNIFI_HOST',
            'api_key': 'UNIFI_API_KEY',
            'site': 'UNIFI_SITE',
            'verify_ssl': 'UNIFI_VERIFY_SSL',
        }
        env_var = env_map.get(key)
        if env_var and os.environ.get(env_var):
            return 'env'
        db_key = f'unifi_{key}'
        val = self._db.get_config(db_key)
        if val is not None and val != '':
            return 'db'
        return 'default'

    # ── HTTP Session ──────────────────────────────────────────────────────────

    def _get_session(self):
        """Lazily create and configure requests.Session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers['X-API-KEY'] = self.api_key
            self._session.verify = self.verify_ssl
        return self._session

    def _make_session(self, api_key: str, verify_ssl: bool):
        """Create a temporary session for test_connection."""
        s = requests.Session()
        s.headers['X-API-KEY'] = api_key
        s.verify = verify_ssl
        return s

    # ── Classic API Helpers ───────────────────────────────────────────────────

    def _get(self, path, host=None, session=None):
        """GET from classic API: /proxy/network/api/s/{site}/{path}"""
        h = host or self.host
        s = session or self._get_session()
        site = self.site
        url = f"{h}/proxy/network/api/s/{site}/{path.lstrip('/')}"
        resp = s.get(url, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # ── Integration API Helpers ───────────────────────────────────────────────

    def _get_integration(self, path, host=None, session=None):
        """GET from integration API (no site prefix)."""
        h = host or self.host
        s = session or self._get_session()
        url = f"{h}/proxy/network{path}"
        resp = s.get(url, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _get_integration_site(self, path):
        """GET from integration API with site UUID prefix."""
        if not self._site_uuid:
            self._discover_site_uuid()
        url = f"{self.host}/proxy/network/integration/v1/sites/{self._site_uuid}{path}"
        resp = self._get_session().get(url, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _patch_integration_site(self, path, body):
        """PATCH to integration API with site UUID prefix."""
        if not self._site_uuid:
            self._discover_site_uuid()
        url = f"{self.host}/proxy/network/integration/v1/sites/{self._site_uuid}{path}"
        resp = self._get_session().patch(url, json=body, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # ── Site UUID Discovery ───────────────────────────────────────────────────

    def _discover_site_uuid(self, host=None, session=None):
        """Map classic site name to integration API UUID."""
        sites = self._get_integration('/integration/v1/sites', host=host, session=session)
        for s in sites.get('data', []):
            if s.get('internalReference') == self.site:
                self._site_uuid = s['id']
                logger.info("Discovered site UUID: %s for site '%s'", self._site_uuid, self.site)
                return
        raise ValueError(f"Site '{self.site}' not found in integration API")

    # ── Phase 1: Connection & Config ──────────────────────────────────────────

    def test_connection(self, host: str, api_key: str, site: str = 'default',
                        verify_ssl: bool = True) -> dict:
        """Test connectivity with provided credentials.

        Returns {success, controller_name, version, site_name} on success,
        or {success: false, error, error_code} on failure.
        Does NOT modify self — uses temporary session.
        """
        host = host.rstrip('/')
        session = self._make_session(api_key, verify_ssl)

        try:
            # Test basic connectivity with sysinfo
            url = f"{host}/proxy/network/api/s/{site}/stat/sysinfo"
            resp = session.get(url, timeout=self.TIMEOUT)

            if resp.status_code == 401:
                return {'success': False, 'error': 'Authentication failed. Check your API key.',
                        'error_code': 'auth_error'}
            if resp.status_code == 403:
                return {'success': False,
                        'error': 'Insufficient permissions. Ensure your API key belongs to a Local Admin account.',
                        'error_code': 'auth_error'}
            resp.raise_for_status()

            data = resp.json()
            info = data.get('data', [{}])[0] if data.get('data') else {}
            controller_name = info.get('name') or info.get('hostname', 'Unknown')
            version = info.get('version', 'Unknown')

            # Also verify integration API access (needed for firewall management)
            sites_url = f"{host}/proxy/network/integration/v1/sites"
            sites_resp = session.get(sites_url, timeout=self.TIMEOUT)
            sites_resp.raise_for_status()
            sites_data = sites_resp.json()

            site_name = None
            for s in sites_data.get('data', []):
                if s.get('internalReference') == site:
                    site_name = s.get('name', site)
                    break

            if site_name is None:
                return {'success': False,
                        'error': f"Site '{site}' not found on this controller.",
                        'error_code': 'invalid_response'}

            return {
                'success': True,
                'controller_name': controller_name,
                'version': version,
                'site_name': site_name,
            }

        except SSLError:
            return {'success': False,
                    'error': 'SSL certificate verification failed. Enable "Skip SSL verification" for self-signed certificates.',
                    'error_code': 'ssl_error'}
        except ConnectionError:
            return {'success': False,
                    'error': 'Could not connect to the controller. Check the URL and ensure it is reachable.',
                    'error_code': 'connection_error'}
        except Timeout:
            return {'success': False,
                    'error': 'Connection timed out. The controller may be unreachable.',
                    'error_code': 'timeout'}
        except requests.HTTPError as e:
            return {'success': False,
                    'error': f'Controller returned error: {e.response.status_code}',
                    'error_code': 'invalid_response'}
        except Exception as e:
            return {'success': False,
                    'error': str(e),
                    'error_code': 'connection_error'}
        finally:
            session.close()

    def get_network_config(self) -> dict:
        """Fetch network topology from Classic + Integration APIs for wizard."""
        if not self.enabled:
            return {'source': 'unifi_api', 'wan_interfaces': [], 'networks': []}

        # ── WAN interfaces from Classic API (/rest/networkconf + /stat/health) ──
        netconf = self._get('rest/networkconf')
        networks_raw = netconf.get('data', [])

        # Per-WAN health: 'wan' subsystem -> WAN, 'wan2' subsystem -> WAN2
        health = self._get('stat/health')
        wan_health = {}
        for subsystem in health.get('data', []):
            sub_name = subsystem.get('subsystem', '')
            if sub_name == 'wan':
                wan_health['WAN'] = subsystem
            elif sub_name == 'wan2':
                wan_health['WAN2'] = subsystem
        logger.debug("stat/health WAN subsystems: %s",
                     {k: {'wan_ip': v.get('wan_ip'), 'status': v.get('status')}
                      for k, v in wan_health.items()})

        # ── Try to resolve physical interfaces from gateway wan1/wan2 objects ──
        device_wan_map = {}  # networkgroup → uplink_ifname from stat/device
        try:
            devices = self._get('stat/device')
            for dev in devices.get('data', []):
                dev_type = dev.get('type', '')
                if dev_type not in ('ugw', 'udm'):
                    continue
                # wan1 object → WAN, wan2 object → WAN2
                for key, group in [('wan1', 'WAN'), ('wan2', 'WAN2')]:
                    wan_obj = dev.get(key)
                    if not wan_obj or not isinstance(wan_obj, dict):
                        continue
                    uplink_ifname = wan_obj.get('uplink_ifname')
                    if uplink_ifname:
                        device_wan_map[group] = uplink_ifname
                if device_wan_map:
                    logger.info("Resolved WAN interfaces from gateway device: %s",
                                device_wan_map)
                break  # Only need the first gateway
        except Exception as e:
            logger.debug("Could not resolve WAN from stat/device: %s", e)

        wan_interfaces = []
        for net in networks_raw:
            if not net.get('enabled', True):
                continue
            if net.get('purpose') != 'wan':
                continue

            name = net.get('name', '')
            # API field is wan_networkgroup (not networkgroup)
            networkgroup = net.get('wan_networkgroup', '') or net.get('networkgroup', '')
            wan_type = net.get('wan_type', 'dhcp')
            wan_type_lower = wan_type.lower()
            logger.debug("WAN entry: name=%s, wan_type=%s, wan_networkgroup=%s",
                         name, wan_type, networkgroup)

            # Prefer gateway device detection over static map
            physical = device_wan_map.get(networkgroup)
            detected_from = 'device'
            if not physical:
                physical = _WAN_PHYSICAL_MAP.get(
                    (wan_type_lower, networkgroup),
                    'eth4' if networkgroup == 'WAN' else 'eth5'
                )
                detected_from = 'map'
                if (wan_type_lower, networkgroup) not in _WAN_PHYSICAL_MAP:
                    logger.warning("Unmapped WAN type: wan_type=%r, wan_networkgroup=%s "
                                   "-> defaulting to %s", wan_type, networkgroup, physical)

            health_sub = wan_health.get(networkgroup, {})
            net_wan_ip = health_sub.get('wan_ip')
            wan_interfaces.append({
                'name': name,
                'wan_ip': net_wan_ip,
                'type': wan_type,
                'networkgroup': networkgroup,
                'physical_interface': physical,
                'active': bool(net_wan_ip),
                'detected_from': detected_from,
            })

        # ── Network segments from Integration API (/networks) ──
        # Subnet lookup from classic API /rest/networkconf (keyed by name)
        subnet_by_name = {}
        for net in networks_raw:
            n = net.get('name', '')
            if n and net.get('ip_subnet'):
                subnet_by_name[n] = net['ip_subnet']

        networks = []
        try:
            int_networks = self._get_integration_site('/networks')
            for net in int_networks.get('data', []):
                if not net.get('enabled', True):
                    continue
                vlan_id = net.get('vlanId')
                if vlan_id is None:
                    continue

                name = net.get('name', '')
                iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
                networks.append({
                    'name': name,
                    'interface': iface,
                    'vlan': vlan_id,
                    'ip_subnet': subnet_by_name.get(name, ''),
                })
        except Exception as e:
            logger.warning("Integration API /networks failed, falling back to classic: %s", e)
            for net in networks_raw:
                if not net.get('enabled', True):
                    continue
                purpose = net.get('purpose', '')
                if purpose not in ('corporate', 'guest', 'vlan-only'):
                    continue
                vlan = net.get('vlan')
                vlan_enabled = net.get('vlan_enabled', False)
                vlan_id = vlan if vlan and vlan_enabled else 1
                iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
                networks.append({
                    'name': net.get('name', ''),
                    'interface': iface,
                    'vlan': vlan_id,
                    'ip_subnet': net.get('ip_subnet', ''),
                })

        return {
            'source': 'unifi_api',
            'wan_interfaces': wan_interfaces,
            'networks': networks,
        }

    # ── VPN Network Discovery ─────────────────────────────────────────────

    # Maps UniFi vpn_type → (interface_prefix, badge)
    _VPN_TYPE_MAP = {
        'wireguard-server': ('wgsrv', 'WGD SRV'),
        'wireguard-client': ('wgclt', 'WGD CLT'),
        'site-magic-wan':   ('wgsts', 'S MAGIC'),
        'teleport':         ('tlprt', 'TELEPORT'),
        'ipsec-vpn':        ('vti',   'S2S IPSEC'),
        'openvpn-server':   ('tun',   'OVPN SRV'),
        'openvpn-client':   ('tun',   'OVPN CLT'),
        'l2tp-server':      ('l2tp',  'L2TP SRV'),
    }

    def get_vpn_networks(self) -> list:
        """Fetch VPN network configs from Classic API (/rest/networkconf).

        Returns list of dicts with normalised fields:
            interface, name, badge, cidr, vpn_type, enabled
        """
        if not self.enabled:
            return []

        try:
            data = self._get('rest/networkconf')
            networks = data.get('data', [])
        except Exception as e:
            logger.warning("Failed to fetch VPN networkconf: %s", e)
            return []

        results = []
        for net in networks:
            vpn_type = net.get('vpn_type', '')
            if not vpn_type:
                continue

            mapping = self._VPN_TYPE_MAP.get(vpn_type)
            if not mapping:
                logger.debug("Unknown vpn_type %r, skipping", vpn_type)
                continue

            prefix, badge = mapping

            # Derive interface name from prefix + wireguard_id (falls back to bare prefix)
            iface = None
            if prefix:
                wg_id = net.get('wireguard_id')
                if wg_id is not None:
                    iface = f'{prefix}{wg_id}'
                # else: no reliable way to derive interface name — leave as None

            # Extract network CIDR from ip_subnet (e.g. "10.10.70.1/29")
            cidr = net.get('ip_subnet', '')

            results.append({
                'interface': iface,
                'name': (net.get('name') or '').strip(),
                'badge': badge,
                'cidr': cidr,
                'vpn_type': vpn_type,
                'enabled': net.get('enabled', True),
            })

        return results

    def get_settings_info(self) -> dict:
        """Return current config with source indicators for Settings UI."""
        return {
            'enabled': self.enabled,
            'host': self.host,
            'host_source': self.get_config_source('host'),
            'api_key_set': bool(self.api_key),
            'api_key_source': self.get_config_source('api_key'),
            'site': self.site,
            'verify_ssl': self.verify_ssl,
            'poll_interval': int(os.environ.get('UNIFI_POLL_INTERVAL', 0) or
                                 self._db.get_config('unifi_poll_interval', 300)),
            'features': self.features,
            'controller_name': self._db.get_config('unifi_controller_name', ''),
            'controller_version': self._db.get_config('unifi_controller_version', ''),
            'status': {
                'connected': self._last_poll is not None and self._last_poll_error is None,
                'last_poll': self._last_poll.isoformat() if self._last_poll else None,
                'last_error': self._last_poll_error,
                'client_count': self._client_count,
                'device_count': self._device_count,
                'polling_paused': False,  # Polling is always active when enabled
            },
        }

    # ── Phase 1: Firewall Management ─────────────────────────────────────────

    def get_firewall_zones(self) -> list:
        """Fetch all firewall zones."""
        data = self._get_integration_site('/firewall/zones')
        return data.get('data', [])

    def get_firewall_policies(self) -> list:
        """Fetch ALL firewall policies (handles pagination internally)."""
        all_policies = []
        offset = 0
        limit = 50
        while True:
            data = self._get_integration_site(
                f'/firewall/policies?offset={offset}&limit={limit}'
            )
            page = data.get('data', [])
            all_policies.extend(page)
            total_count = data.get('totalCount', 0)
            if offset + len(page) >= total_count:
                break
            offset += len(page)
        return all_policies

    def get_firewall_data(self) -> dict:
        """Fetch policies + zones in one call for the frontend."""
        policies = self.get_firewall_policies()
        zones = self.get_firewall_zones()

        logging_enabled = sum(1 for p in policies if p.get('loggingEnabled'))
        logging_disabled = len(policies) - logging_enabled

        return {
            'policies': policies,
            'zones': zones,
            'totalCount': len(policies),
            'loggingEnabled': logging_enabled,
            'loggingDisabled': logging_disabled,
        }

    def patch_firewall_policy(self, policy_id: str, logging_enabled: bool) -> dict:
        """Update loggingEnabled on a single policy."""
        return self._patch_integration_site(
            f'/firewall/policies/{policy_id}',
            {'loggingEnabled': logging_enabled}
        )

    def bulk_patch_logging(self, updates: list[dict]) -> dict:
        """Batch-update loggingEnabled for multiple policies.

        updates: [{"id": "uuid", "loggingEnabled": bool}, ...]
        Returns summary: {total, success, failed, skipped, errors}
        """
        total = len(updates)
        success = 0
        failed = 0
        skipped = 0
        errors = []

        for item in updates:
            policy_id = item.get('id', '')
            logging_val = item.get('loggingEnabled')

            if logging_val is None:
                skipped += 1
                continue

            try:
                self.patch_firewall_policy(policy_id, logging_val)
                success += 1
            except requests.HTTPError as e:
                failed += 1
                errors.append({
                    'id': policy_id,
                    'error': f'HTTP {e.response.status_code}: {e.response.text[:200]}'
                })
            except Exception as e:
                failed += 1
                errors.append({'id': policy_id, 'error': str(e)})

            # Be controller-friendly: 100ms delay between requests
            time.sleep(0.1)

        return {
            'total': total,
            'success': success,
            'failed': failed,
            'skipped': skipped,
            'errors': errors[:20],  # Cap error details
        }

    # ── Phase 2: Client/Device Polling ───────────────────────────────────────

    def poll(self) -> bool:
        """Single poll cycle: fetch clients + devices, rebuild maps, persist.

        Returns True on success, False on error.
        """
        if not self.enabled:
            return False

        try:
            clients = []
            devices = []

            if self.features.get('client_names', True):
                clients = self._poll_clients()
            if self.features.get('device_discovery', True):
                devices = self._poll_devices()

            # Build in-memory maps atomically
            ip_map = {}
            mac_map = {}
            for c in clients:
                name = c.get('device_name') or c.get('hostname') or c.get('oui')
                if name:
                    if c.get('mac'):
                        mac_map[c['mac'].lower()] = name
                    if c.get('ip'):
                        ip_map[c['ip']] = name
            for d in devices:
                name = d.get('device_name') or d.get('model')
                if name:
                    if d.get('mac'):
                        mac_map[d['mac'].lower()] = name
                    if d.get('ip'):
                        ip_map[d['ip']] = name

            # Add WAN IPs → gateway device name before atomic swap
            if self.features.get('network_config', True):
                try:
                    net_config = self.get_network_config()
                    # Find gateway device name from polled devices
                    gateway_name = None
                    for d in devices:
                        if d.get('device_type') in ('ugw', 'udm', 'uxg'):
                            gateway_name = d.get('device_name') or d.get('model')
                            break
                    if gateway_name:
                        wan_ip_names = {}
                        for wan in net_config.get('wan_interfaces', []):
                            wan_ip = wan.get('wan_ip')
                            if wan_ip:
                                ip_map[wan_ip] = gateway_name
                                wan_ip_names[wan_ip] = gateway_name
                        if wan_ip_names:
                            self._db.set_config('wan_ip_names', wan_ip_names)
                    # Extract gateway IP→VLAN mapping
                    gateway_vlans = {}
                    for net in net_config.get('networks', []):
                        subnet = net.get('ip_subnet', '')
                        if '/' in subnet:
                            gw_ip = subnet.split('/')[0]
                            gateway_vlans[gw_ip] = {
                                'vlan': net.get('vlan'),
                                'name': net.get('name', ''),
                            }
                    if gateway_vlans:
                        self._db.set_config('gateway_ip_vlans', gateway_vlans)
                        self._db.set_config('gateway_ips', list(gateway_vlans.keys()))
                except Exception as e:
                    logger.warning("Failed to extract network config: %s", e)

            # Atomic swap under lock
            with self._lock:
                self._ip_to_name = ip_map
                self._mac_to_name = mac_map
                self._client_count = len(clients)
                self._device_count = len(devices)

            # Persist to DB
            if clients:
                self._db.upsert_unifi_clients(clients)
            if devices:
                self._db.upsert_unifi_devices(devices)

            self._last_poll = datetime.now(timezone.utc)
            self._last_poll_error = None
            logger.info("UniFi poll: %d clients, %d devices synced",
                        len(clients), len(devices))
            return True

        except Exception as e:
            self._last_poll_error = str(e)
            logger.exception("UniFi poll failed")
            return False

    def _poll_clients(self) -> list[dict]:
        """Fetch active + historical clients, merge into unified list."""
        # Active clients (rich data: ip, network, essid, vlan)
        active_by_mac = {}
        try:
            data = self._get('stat/sta')
            for c in data.get('data', []):
                mac = c.get('mac', '').lower()
                if not mac:
                    continue
                active_by_mac[mac] = {
                    'mac': mac,
                    'ip': c.get('ip') or c.get('last_ip'),
                    'device_name': c.get('name'),
                    'hostname': c.get('hostname'),
                    'oui': c.get('oui'),
                    'network': c.get('network'),
                    'essid': c.get('essid'),
                    'vlan': c.get('vlan'),
                    'is_fixed_ip': c.get('use_fixedip', False),
                    'is_wired': c.get('is_wired'),
                    'last_seen': _parse_epoch(c.get('last_seen')),
                }
        except Exception as e:
            logger.warning("Failed to fetch stat/sta: %s", e)

        # All known clients (historical — reduced fields)
        all_by_mac = {}
        try:
            data = self._get('stat/alluser')
            for c in data.get('data', []):
                mac = c.get('mac', '').lower()
                if not mac:
                    continue
                all_by_mac[mac] = {
                    'mac': mac,
                    'ip': c.get('last_ip'),  # no 'ip' in alluser
                    'device_name': c.get('name'),
                    'hostname': c.get('hostname'),
                    'oui': c.get('oui'),
                    'network': c.get('last_connection_network_name'),
                    'essid': None,  # not available in alluser
                    'vlan': None,
                    'is_fixed_ip': c.get('use_fixedip', False),
                    'is_wired': c.get('is_wired'),
                    'last_seen': _parse_epoch(c.get('last_seen')),
                }
        except Exception as e:
            logger.warning("Failed to fetch stat/alluser: %s", e)

        # Merge: active clients take priority (richer data)
        merged = {**all_by_mac, **active_by_mac}
        return list(merged.values())

    def _poll_devices(self) -> list[dict]:
        """Fetch infrastructure devices (APs, switches, gateways)."""
        try:
            data = self._get('stat/device')
            devices = []
            for d in data.get('data', []):
                mac = d.get('mac', '').lower()
                if not mac:
                    continue
                devices.append({
                    'mac': mac,
                    'ip': d.get('ip'),
                    'device_name': d.get('name'),
                    'model': d.get('model'),
                    'shortname': d.get('shortname'),
                    'device_type': d.get('type'),
                    'firmware': d.get('version'),
                    'serial': d.get('serial'),
                    'state': d.get('state'),
                    'uptime': d.get('uptime'),
                })
            return devices
        except Exception as e:
            logger.warning("Failed to fetch stat/device: %s", e)
            return []

    def stop_polling(self):
        """Stop the background polling thread if running."""
        if self._poll_thread is not None and self._poll_thread.is_alive():
            self._poll_stop.set()
            self._poll_thread.join(timeout=5)
            logger.info("UniFi polling stopped")

    def start_polling(self):
        """Start (or restart) the background polling daemon thread."""
        # Stop existing thread if running
        self.stop_polling()

        if not self.enabled:
            return

        # Clear any stale paused flag (toggle was removed, polling always active)
        self._db.set_config('unifi_polling_paused', False)

        poll_interval = int(os.environ.get('UNIFI_POLL_INTERVAL', 0) or
                            self._db.get_config('unifi_poll_interval', 300))

        # Load cached maps from DB on cold start
        try:
            ip_map, mac_map = self._db.load_device_name_maps()
            # Also load persisted WAN IP → gateway name mappings
            wan_ip_names = self._db.get_config('wan_ip_names', {})
            if wan_ip_names:
                ip_map.update(wan_ip_names)
            with self._lock:
                self._ip_to_name = ip_map
                self._mac_to_name = mac_map
            if ip_map:
                logger.info("Loaded %d cached device names from DB", len(ip_map))
        except Exception as e:
            logger.warning("Failed to load cached device names from DB: %s", e)

        self._poll_stop = threading.Event()

        def _poll_loop():
            # Initial poll immediately
            self.poll()
            while not self._poll_stop.wait(poll_interval):
                self.poll()

        self._poll_thread = threading.Thread(target=_poll_loop, daemon=True,
                                              name='unifi-poller')
        self._poll_thread.start()
        logger.info("UniFi polling started (interval=%ds)", poll_interval)

    def resolve_name(self, ip: str | None = None, mac: str | None = None) -> str | None:
        """Resolve device name by IP or MAC from in-memory cache.

        Returns None if client_names feature is disabled or no match found.
        """
        if not self.features.get('client_names', True):
            return None
        with self._lock:
            if mac:
                name = self._mac_to_name.get(mac.lower())
                if name:
                    return name
            if ip:
                return self._ip_to_name.get(ip)
        return None


def _parse_epoch(epoch) -> datetime | None:
    """Convert UniFi epoch timestamp to datetime, or None."""
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None

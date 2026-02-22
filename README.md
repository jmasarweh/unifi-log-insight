# 🔍 UniFi Log Insight



Real-time log analysis for UniFi routers and gateways - captures syslog over UDP, parses firewall, DHCP, Wi-Fi, and system events, enriches them with GeoIP, ASN, threat intelligence, and reverse DNS, then serves everything through a live Dashboard.

Single Docker container. No external dependencies. Zero data collection.

---

<img width="1985" height="1108" alt="Log Stream" src="https://github.com/user-attachments/assets/56a6ac3a-275a-4245-aaef-1462b35ccdc2" />

<img width="1831" height="1261" alt="Dashboard" src="https://github.com/user-attachments/assets/7c0934e5-2342-4b64-8407-eaecf018e42d" />

<img width="2165" height="1238" alt="Setup Wizard & Firewall Management" src="https://github.com/user-attachments/assets/2cb5ba91-dd0c-4e2a-9527-12a4ed1099d8" />

<img width="1826" height="1251" alt="Expanded Log Detail" src="https://github.com/user-attachments/assets/a1b43da1-3641-45fd-97dc-b00ecc47bde8" />

---

## ✨ Features

- 📺 **Live Log Stream** - Auto-refreshing table with expandable details, copy-to-clipboard, and intelligent pause/resume
- 📊 **Dashboard** - Traffic breakdowns, top blocked/allowed countries and IPs, top threats with ASN/city/rDNS/categories, top devices, services, DNS queries
- 🔎 **Filters** - Log type, time range, action, direction, VPN badge, interface, service, country, ASN, threat score, IP, rule name, text search
- 🌍 **IP Enrichment** - GeoIP (country, city, coordinates), ASN, reverse DNS via MaxMind GeoLite2 with scheduled auto-update and hot-reload
- 🛡️ **AbuseIPDB Integration** - Threat scoring (23 categories, Tor detection, usage type), daily blacklist pre-seeding, automatic backfill
- 📡 **Syslog Receiver** - UDP 514 listener parsing firewall, DHCP, Wi-Fi, DNS, and system events
- 🔀 **Multi-WAN & Direction** - Per-interface WAN IP mapping for failover/load-balanced setups. Auto-classifies traffic as inbound, outbound, inter-VLAN, local, or VPN
- 🔐 **VPN Detection** - Auto-detects VPN interfaces (WireGuard, OpenVPN, Teleport, Site Magic) with badge assignment, labels, and CIDRs
- 🔌 **UniFi Integration** - Network discovery, device name resolution, and firewall syslog management via **UniFi OS** (API key) or **self-hosted controllers** (username/password)
- 🛡️ **Firewall Syslog Manager** - Zone matrix with bulk toggle - enable syslog on firewall rules without leaving the app (UniFi OS)
- 📛 **Device Names** - Friendly names from UniFi clients/devices with historical backfill
- 🎨 **Theming & Preferences** - Dark/light theme, country display format, IP subline (show ASN beneath IPs)
- 🏷️ **Interface Labels** - Color-coded labels for traffic flow, applied retroactively to all logs
- 📥 **CSV Export** - Download filtered results up to 100K rows
- 🗑️ **Retention** - Configurable per log type (60-day default, 10-day DNS). Adjustable via Settings or env vars
- 💾 **Backup & Restore** - Export/import all settings as JSON
- 🔤 **DNS Ready** - Full DNS query parsing ([requires configuration](#-dns-logging))
- 📱 **Mobile Responsive** - Collapsible filters, full-width table on small screens
- 🧙 **Setup Wizard** - Two paths: **UniFi API** (auto-detects WAN, VLANs, topology) or **Log Detection** (discovers interfaces from live traffic)

---

## 📋 Prerequisites

- **Docker** and **Docker Compose**
- **UniFi Router** (or any UniFi gateway that supports remote syslog)
- **MaxMind GeoLite2 account** ([free signup](https://www.maxmind.com/en/geolite2/signup)) - for GeoIP/ASN lookups
- **AbuseIPDB API key** ([free tier](https://www.abuseipdb.com/register?plan=free), optional) - for threat scoring

---
## 🚀 Quick Start

> 🖧 **Running Unraid?** Skip to the [Unraid Setup](#-unraid-setup) section for a no-terminal install guide.

## 1. Configure Your UniFi Router

### 1.1 Enable Syslog on the Router

In your UniFi Network controller:

1. Go to **Settings → CyberSecure → Traffic Logging**
2. Enable **Activity Logging (Syslog)**
3. Under Contents, select Clients, Critical, Devices, Security Detections, Triggers, VPN, Firewall Default Policy
4. Set the syslog server to `<docker-host-ip>` on port `514`
5. Click Apply Changes

### 1.2 Enable Syslog Per Firewall Rule

Each firewall rule must have syslog individually enabled. There are two ways to do this:

**Option A - Use UniFi Log Insight (recommended):** Connect via the UniFi API during setup (or later in Settings), then use the built-in **Firewall Syslog Manager** to view all your zone policies and bulk-toggle syslog - no need to touch the UniFi controller UI.

**Option B - Manually in the UniFi controller:** Go to **Settings → Policy Engines → Zones**, select each rule, and enable the **Syslog** toggle.

> **Note:** Without per-rule syslog enabled, firewall logs will not appear even if global Activity Logging is configured.

<img width="2056" height="1164" alt="Firewall syslog toggle in UniFi" src="https://github.com/user-attachments/assets/cc08f009-0c70-4d7a-8bf0-5de5e404909a" />

## 2. Install

### Option A - Pull Pre-built Image (recommended)

Create a directory anywhere and add two files:

**`docker-compose.yml`**

```yaml
services:
  unifi-log-insight:
    image: ghcr.io/jmasarweh/unifi-log-insight:latest
    container_name: unifi-log-insight
    restart: unless-stopped
    ports:
      - "514:514/udp"
      - "8090:8000"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./maxmind:/app/maxmind
    env_file:
      - .env

volumes:
  pgdata:
    name: unifi-log-insight-pgdata
```

**`.env`** - create with your API keys:

```env
# PostgreSQL (required)
POSTGRES_PASSWORD=your_strong_password_here

# MaxMind GeoLite2 - free at https://www.maxmind.com/en/geolite2/signup
# Auto-downloads .mmdb files on first boot if not already present
MAXMIND_ACCOUNT_ID=your_account_id
MAXMIND_LICENSE_KEY=your_license_key

# AbuseIPDB - free at https://www.abuseipdb.com/register (optional)
ABUSEIPDB_API_KEY=your_key_here

# Timezone (for cron schedules). See https://gist.github.com/Soheab/3bec6dd6c1e90962ef46b8545823820d
TZ=Europe/London

# UniFi API (optional - can also be configured via Settings UI)
# UNIFI_HOST=https://192.168.1.1
# UNIFI_API_KEY=your_unifi_api_key_here
```

Then run:

```bash
docker compose up - d
```

### Option B - Build from Source

```bash
git clone https://github.com/jmasarweh/unifi-log-insight.git
cd unifi-log-insight
# Create .env as shown above
docker compose up - d - -build
```

## 3. Open the UI

Navigate to `http://<docker-host-ip>:8090`

On first launch, a **Setup Wizard** will guide you through configuration. You can choose between two paths:

#### Path A - UniFi API (recommended)

Connect to your UniFi Controller to auto-detect everything:

1. **Connect** - Choose your controller type:
   - **UniFi OS** (cloud key, UDM, UDR) - Enter your controller IP and API key (Local Admin)
   - **Self-hosted controller** - Enter your controller IP, username, and password

   If your controller uses a self-signed or custom SSL certificate, enable **Skip SSL verification** under Advanced before testing.
2. **WAN Detection** - WAN interfaces are auto-detected from the controller's network config.
3. **Network Labels** - VLANs and subnets are pre-populated from the controller. Just review and label.
4. **Firewall Rules** - View your zone matrix and enable syslog on firewall rules directly from the wizard (UniFi OS only).

#### Path B - Log Detection

If you don't want to connect the API, the wizard falls back to log-based discovery:

1. **WAN Detection** - Select your WAN interface(s) from interfaces seen in traffic. Common interfaces:

   | UniFi Model | Typical WAN Interface |
   |---|---|
   | UDR (PPPoE) | `ppp0` |
   | UDR (DHCP) | `eth3` |
   | UDM / UDM-SE | `eth8` |
   | USG | `eth0` |
   | UDM-Pro | `eth8` or `eth9` |

2. **Network Labels** - Give each interface a friendly name (e.g., "IoT" instead of "br20").
3. **Summary** - Review and save.

You can reconfigure at any time via the **Settings gear** in the top-right corner of the UI.

---

## 🏗️ Architecture

Everything runs inside a single Docker container, managed by supervisord:

```mermaid
graph LR
    subgraph Docker Container
        direction TB

        subgraph Ingestion
            SR["📡 Syslog Receiver\nUDP :514"]
            EN["🌍 Enrichment\nGeoIP · ASN · AbuseIPDB · rDNS"]
        end

        subgraph Storage
            PG["🐘 PostgreSQL\nlogs · ip_threats"]
        end

        subgraph Serving
            API["⚡ FastAPI + React UI\n:8000"]
        end

        subgraph Background
            CRON["🕐 Cron\nMaxMind Updates"]
            SCHED["🔄 Scheduler\nBlacklist · Retention · Backfill"]
        end

        SR - -> EN - -> PG
        PG - -> API
        SCHED - -> PG
    end

    UDP["🔌 UDP :514\nsyslog in"] - -> SR
    API - -> HTTP["🌐 HTTP :8090\nUI + API out"]
```

### 🔀 Log Processing Pipeline

1. **Receive** - Raw syslog UDP packets from Unifi
2. **Parse** - Extract fields from iptables, hostapd, dhclient, and dnsmasq messages (when DNS logging is enabled)
3. **Validate** - IP address validation rejects malformed data before DB insert
4. **Classify** - Determine direction (inbound/outbound/inter-VLAN/local/VPN) based on interfaces and WAN IP
5. **Enrich** - GeoIP country/city/coords, ASN org name, AbuseIPDB threat score + categories + detail fields (verbose mode), reverse DNS
6. **Store** - Batched inserts into PostgreSQL with row-by-row fallback on failure
7. **Serve** - REST API with pagination, filtering, sorting, and CSV export

---

## ⚙️ Configuration Reference

### Environment Variables

| Variable | Description |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL password for the `unifi` user |
| `ABUSEIPDB_API_KEY` | Enables threat scoring on blocked inbound IPs. Free tier: 1,000 check lookups/day + 5 blacklist pulls/day |
| `MAXMIND_ACCOUNT_ID` | Enables GeoIP auto-update. Without it, manually place `.mmdb` files |
| `MAXMIND_LICENSE_KEY` | Paired with account ID for auto-update |
| `TZ` | Timezone for cron schedules. Defaults to UTC. Examples: `Europe/London`, `Asia/Amman`, `America/New_York`. [See supported timezones](https://gist.github.com/Soheab/3bec6dd6c1e90962ef46b8545823820d) |
| `LOG_LEVEL` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Defaults to `INFO`. Set to `WARNING` for quiet steady-state. Use `DEBUG` for troubleshooting |
| `UNIFI_HOST` | *(optional)* UniFi Controller URL (e.g., `https://192.168.1.1`). Can also be set via the Settings UI |
| `UNIFI_API_KEY` | *(optional)* UniFi API key (Local Admin, for UniFi OS). Can also be set via the Settings UI where it's stored encrypted |
| `UNIFI_SITE` | *(optional)* UniFi site name. Defaults to `default` |
| `UNIFI_VERIFY_SSL` | *(optional)* Set to `false` for self-signed certificates. Defaults to `true` |
| `UNIFI_POLL_INTERVAL` | *(optional)* Device polling interval in seconds. Defaults to `300` (5 minutes) |
| `RETENTION_DAYS` | *(optional)* Log retention in days for firewall/DHCP/Wi-Fi/system. Defaults to `60`. Can also be set via Settings UI |
| `DNS_RETENTION_DAYS` | *(optional)* DNS log retention in days. Defaults to `10`. Can also be set via Settings UI |

### Ports

| Port | Protocol | Purpose |
|---|---|---|
| 514 | UDP | Syslog receiver (incoming logs from Unifi) |
| 8090 | TCP | Web UI and REST API |

### Retention Policy

| Log Type | Default | Range |
|---|---|---|
| Firewall, DHCP, Wi-Fi, System | 60 days | 60–365 days |
| DNS (when enabled) | 10 days | 1–365 days |

Retention is configurable via the **Settings > Data & Backups** slider, or via `RETENTION_DAYS` / `DNS_RETENTION_DAYS` environment variables. Cleanup runs daily at 03:00 (container local time).

---

## 🗺️ MaxMind Auto-Update

When credentials are configured, GeoLite2 databases update automatically on **Wednesday and Saturday at 7:00 AM** (local time per `TZ` - [supported timezones](https://gist.github.com/Soheab/3bec6dd6c1e90962ef46b8545823820d)). This aligns with MaxMind's Tuesday/Friday publish schedule, giving a buffer for propagation.

The receiver hot-reloads databases via signal - no container restart required.

### Manual Update

```bash
docker exec unifi-log-insight /app/geoip-update.sh
```

### Check Update Logs

```bash
docker exec unifi-log-insight cat /var/log/geoip-update.log
```

---

## 🛡️ AbuseIPDB Integration

When `ABUSEIPDB_API_KEY` is configured, the system provides multi-layered threat intelligence:

### Threat Scoring

Blocked firewall events trigger a lookup against AbuseIPDB using verbose mode, returning:
- **Confidence score** (0–100%) with severity classification (Clean/Low/Medium/High/Critical)
- **Attack categories** - Decoded from 23 category codes (Port Scan, SSH, Brute-Force, DDoS, etc.)
- **Usage type** - Data Center, Residential, VPN, etc.
- **Tor exit node** detection
- **Whitelist** status
- **Report count** and last reported date

### Three-Tier Cache

To minimise API usage, lookups follow a cache hierarchy:

1. **In-memory cache** - Hot path, zero I/O
2. **PostgreSQL `ip_threats` table** - Persistent across container rebuilds, 4-day TTL
3. **AbuseIPDB API** - Only called on cache miss, results written back to both tiers

### Blacklist Pre-seeding

A daily pull of the AbuseIPDB blacklist (10,000 highest-risk IPs at 100% confidence) is bulk-inserted into the threat cache. Any blocked IP matching the blacklist gets an instant score from cache - no API call consumed. Uses a separate quota (5 calls/day) independent of the check individual IP quota.

The blacklist runs on startup (30-second delay) and then daily at 04:00.

### Rate Limiting

The system uses AbuseIPDB response headers (`X-RateLimit-Remaining`, `Retry-After`) as the single source of truth - no internal counters that desync on container rebuilds. On 429 responses, the enricher pauses automatically until the limit resets (which is midnight UTC).

---

## 🖥️ UI Guide

### Log Stream

The main view shows a live-updating table of parsed logs:

- **Type filters** - Toggle firewall, DNS, DHCP, Wi-Fi, system
- **Time range** - 1h, 6h, 24h, 7d, 30d, 60d (up to 365d based on retention setting)
- **Action filters** - Allow, block, redirect
- **Direction filters** - Inbound, outbound, VLAN, NAT, VPN
- **VPN badge filter** - Filter by VPN type (WireGuard, OpenVPN, IPsec, L2TP, Teleport, Site Magic)
- **Interface filter** - Multi-select by interface name or label (e.g., "IoT", "br20")
- **Service filter** - Filter by detected service (HTTP, DNS, SSH, etc.)
- **Country filter** - Filter by country code
- **ASN filter** - Filter by Autonomous System name
- **Threat score** - Minimum AbuseIPDB threat score threshold
- **Text search** - Filter by IP, rule name, or raw log content

Click any row to expand full details including enrichment data, parsed rule breakdown, AbuseIPDB intelligence (score, decoded attack categories, usage type, hostnames, report count, last reported date, Tor/whitelist status), device names (when UniFi API is connected), copy-to-clipboard buttons, and raw log.

The stream auto-pauses when a row is expanded and shows a count of new logs received. It resumes on collapse.

### Settings

Access settings via the **gear icon** in the top-right corner. Four sections:

- **WAN & Networks** - WAN interface selection, network labels, VPN badge configuration. Discovered VPN networks appear as cards that can be assigned badges, labels, and CIDRs
- **Firewall** - Zone matrix with bulk syslog toggle (UniFi OS only)
- **Data & Backups** - Retention sliders, manual cleanup, config export/import
- **User Interface** - Theme (dark/light), country display format (flag + name, flag only, name only), IP address subline (show ASN beneath IPs in log table)

### Dashboard

Aggregated views with configurable time range (1h to 365d, based on retention setting):
- Total logs, blocked count, high-threat count, allowed count
- Traffic direction breakdown (inbound, outbound, VLAN, NAT, VPN)
- Traffic-over-time area chart and traffic-by-action stacked chart (allowed/blocked/redirect)
- Top blocked countries and IPs (external and internal, with device names from UniFi)
- Top threat IPs - enriched with ASN, city, rDNS, decoded attack categories, last seen
- Top allowed destinations and active internal devices (with device name + VLAN badges)
- Top blocked/allowed services, top DNS queries

---

## 📡 API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/logs` | Paginated log list with all filters |
| `GET /api/logs/{id}` | Single log detail with threat data |
| `GET /api/stats?time_range=24h` | Dashboard aggregations |
| `GET /api/export` | CSV export with current filters |
| `GET /api/health` | Health check with total count and latest timestamp |
| `GET /api/services` | Distinct service names for filter dropdown |
| `GET /api/interfaces` | Distinct interfaces seen in logs |
| `GET /api/config` | Current system configuration (WAN, labels, setup status) |
| `POST /api/setup/complete` | Save wizard configuration |
| `GET /api/setup/wan-candidates` | Auto-detected WAN interface candidates |
| `GET /api/setup/network-segments` | Discovered network segments with suggested labels |
| `POST /api/enrich/{ip}` | Force fresh AbuseIPDB lookup for an IP |
| `GET /api/settings/unifi` | Current UniFi API settings |
| `PUT /api/settings/unifi` | Update UniFi API settings |
| `POST /api/settings/unifi/test` | Test UniFi connection and save on success |
| `GET /api/settings/ui` | Current UI display preferences (theme, country format, IP subline) |
| `PUT /api/settings/ui` | Update UI display preferences |
| `GET /api/firewall/policies` | All firewall policies with zone data |
| `PATCH /api/firewall/policies/{id}` | Toggle syslog on a firewall policy |
| `POST /api/firewall/policies/bulk-logging` | Bulk-toggle syslog on multiple policies |
| `GET /api/unifi/clients` | Cached UniFi client list |
| `GET /api/unifi/devices` | Cached UniFi infrastructure devices |
| `GET /api/unifi/status` | UniFi polling status |
| `GET /api/config/export` | Export all settings as JSON |
| `POST /api/config/import` | Import settings from JSON backup |
| `POST /api/config/vpn-networks` | Save VPN network configuration (badges, labels, CIDRs) |
| `GET /api/config/retention` | Current retention configuration |
| `POST /api/config/retention` | Update retention settings |
| `POST /api/config/retention/cleanup` | Run retention cleanup immediately |
| `GET /api/setup/status` | Setup wizard completion status |
| `GET /api/setup/unifi-network-config` | UniFi network discovery config |
| `GET /api/abuseipdb/status` | AbuseIPDB threat cache and rate limit status |
| `POST /api/unifi/backfill-device-names` | Backfill device names from UniFi into existing logs |
| `GET /api/unifi/gateway-image` | Gateway model and image info |
| `POST /api/settings/unifi/dismiss-upgrade` | Dismiss upgrade notification banner |
| `POST /api/settings/unifi/dismiss-vpn-toast` | Dismiss VPN introduction toast |

---

## 🔤 DNS Logging

The app includes full DNS query parsing, but **some Unifi Routers/Gateways do not send DNS logs by default**. Their dnsmasq instance lacks the `log-queries` directive, and its configuration is auto-generated by `ubios-udapi-server` - manual edits are overwritten on reboot.

**Current status:** There is no supported persistent method to enable DNS syslog on newer Unifi devices without workarounds that risk breaking on firmware updates.

**Options if you want DNS visibility:**

- **Pi-hole / AdGuard Home** - Deploy as your network's DNS server. These log all queries natively and also provide ad blocking. Point your router's DHCP to hand out the Pi-hole IP as the DNS server.
- **Wait for Ubiquiti** - A future firmware update may expose a DNS logging toggle. The app will capture DNS logs automatically once the router starts emitting them.

The dashboard includes a "Top DNS Queries" panel and the filter bar has a DNS type toggle - both will populate once DNS logs start flowing.

---

## 🖧 Unraid Setup

Install directly from Unraid's Docker UI - no terminal needed.

1. Go to the **Docker** tab and click **Add Container**
2. Set **Repository** to `ghcr.io/jmasarweh/unifi-log-insight:latest`
3. Set **Name** to `unifi-log-insight`
4. Add the following **Port Mappings**:

   | Container Port | Host Port | Type |
   |---|---|---|
   | `514` | `514` | UDP |
   | `8000` | `8090` | TCP |

5. Add the following **Volume Mappings**:

   | Container Path | Host Path | Purpose |
   |---|---|---|
   | `/var/lib/postgresql/data` | `/mnt/user/appdata/unifi-log-insight/pgdata` | Database storage |
   | `/app/maxmind` | `/mnt/user/appdata/unifi-log-insight/maxmind` | GeoIP databases (auto-downloaded) |

6. Add **Environment Variables**:

   | Key | Value |
   |---|---|
   | `POSTGRES_PASSWORD` | *(your password)* |
   | `TZ` | *(your timezone, e.g. `America/New_York`)* [See supported timezones](https://gist.github.com/Soheab/3bec6dd6c1e90962ef46b8545823820d) |
   | `ABUSEIPDB_API_KEY` | *(optional - get free key at [abuseipdb.com](https://www.abuseipdb.com/register))* |
   | `MAXMIND_ACCOUNT_ID` | *(optional - get free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup))* |
   | `MAXMIND_LICENSE_KEY` | *(paired with account ID)* |

7. Click **Apply** to start the container
8. Open `http://<unraid-ip>:8090` and complete the Setup Wizard
9. Configure your UniFi router's syslog to point at `<unraid-ip>:514`

> **Updating:** Click the container's update icon in the Docker tab when a new version is available. Your database and configuration are preserved in the mapped volumes.

---

## 🔧 Troubleshooting

### No logs appearing

1. Verify syslog is configured on the router and pointing to the correct IP (see [Step 1](#1-configure-your-unifi-router))
2. Ensure per-rule syslog is enabled - use the app's **Firewall Syslog Manager** (Settings → Firewall) or toggle manually in the UniFi controller
3. Check the container is receiving packets: `docker logs unifi-log-insight | grep "received"`
4. Ensure UDP port 514 isn't blocked by the host firewall


### GeoIP not working

1. Check if `.mmdb` files exist: `docker exec unifi-log-insight ls - la /app/maxmind/`
2. Check enrichment status: `curl http://<host>:8090/api/health`
3. If using auto-update, verify credentials: `docker exec unifi-log-insight /app/geoip-update.sh`

### Container won't start

1. Check logs: `docker compose logs`
2. Verify `.env` exists and `POSTGRES_PASSWORD` is set
3. If PostgreSQL data is corrupted, reset: `docker compose down - v && docker compose up - d - -build`

---

## ⚖️ Disclaimer

This project is not affiliated with, endorsed by, or associated with Ubiquiti Inc. "UniFi" and related brand names are trademarks of Ubiquiti Inc. All rights to those trademarks are reserved by their respective owners.

---

## 📄 License

MIT

# UniFi Log Insight

<img width="1985" height="1108" alt="image" src="https://github.com/user-attachments/assets/56a6ac3a-275a-4245-aaef-1462b35ccdc2" />

<img width="2131" height="1178" alt="image" src="https://github.com/user-attachments/assets/c40b5f19-7dd0-4f35-93b8-fa8a2233a422" />



---

Real-time log analysis for UniFi Routers (and Gateways). Receives syslog over UDP, parses firewall/DHCP/Wi-Fi/system events, enriches with GeoIP, ASN, threat intelligence, and reverse DNS, stores everything in PostgreSQL, and serves a live React dashboard.

Built for home network monitoring — runs as a single Docker container with zero external dependencies.

---

## Features

- **Syslog Receiver** — Listens on UDP 514, parses iptables firewall rules, DHCP leases, Wi-Fi events, and system messages
- **IP Enrichment** — MaxMind GeoLite2 (country, city, coordinates), ASN lookup, AbuseIPDB threat intelligence (score, 23 attack categories, usage type, Tor/whitelist detection, report counts), reverse DNS
- **Smart Direction Detection** — Classifies traffic as inbound, outbound, inter-VLAN, or local with automatic WAN IP learning
- **DNS Ready** — Parser supports DNS query/answer logging (requires additional Unifi configuration — see [DNS Logging](#dns-logging) below)
- **Live UI** — Auto-refreshing log stream with expandable detail rows, intelligent pause/resume when inspecting logs
- **Filters** — Filter by log type, time range, action (allow/block/redirect), direction, IP address, rule name, and raw text search
- **Dashboard** — Traffic breakdown by type and direction, logs-per-hour chart, top blocked countries/IPs (WAN IP and non-routable excluded), top threat IPs (enriched with ASN, city, rDNS, decoded categories, last seen), top DNS queries
- **AbuseIPDB Blacklist** — Daily pull of 10,000 highest-risk IPs pre-seeded into the threat cache for instant scoring without API calls (separate quota: 5 calls/day)
- **Persistent Threat Cache** — `ip_threats` table stores AbuseIPDB results (score, categories, usage type, Tor status, report counts) for 4-day reuse, surviving container rebuilds. Three-tier lookup: in-memory → PostgreSQL → API call
- **Backfill Daemon** — Automatically patches historical logs that have NULL threat scores against the persistent cache
- **Batch Insert Resilience** — Row-by-row fallback on batch failures; IP validation at parse time prevents bad data from blocking ingestion
- **Network Path Display** — Color-coded interface labels (Main, IoT, Hotspot, WAN) showing traffic flow direction
- **CSV Export** — Download filtered results up to 100K rows
- **Auto-Retention** — 60-day retention for firewall/DHCP/Wi-Fi, 10-day for DNS
- **MaxMind Auto-Update** — Scheduled GeoLite2 database refresh with hot-reload (no restart needed)

---

## Prerequisites

- **Docker** and **Docker Compose** on the host machine
- **UniFi Dream Router** (or any UniFi gateway that supports remote syslog)
- **MaxMind GeoLite2 account** (free) — for GeoIP/ASN lookups
- **AbuseIPDB API key** (free tier, optional) — for threat scoring on blocked IPs

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/jmasarweh/unifi-log-insight.git
cd unifi-log-insight
```

### 2. Configure Environment

Create a `.env` file in the project root:

```env
# PostgreSQL (required)
POSTGRES_PASSWORD=your_strong_password_here

# AbuseIPDB - free at https://www.abuseipdb.com/register (optional)
ABUSEIPDB_API_KEY=your_key_here

# MaxMind GeoLite2 - free at https://www.maxmind.com/en/geolite2/signup (optional but recommended)
MAXMIND_ACCOUNT_ID=your_account_id
MAXMIND_LICENSE_KEY=your_license_key

# Timezone for scheduled tasks (used by cron for MaxMind updates)
TZ=Europe/London
```

### 3. Configure Network Interfaces

The app needs to know your WAN interface to classify traffic direction (inbound/outbound/inter-VLAN). It defaults to `ppp0` (PPPoE), which is wrong for most non-PPPoE setups.

**Find your WAN interface:**

| UniFi Model | Typical WAN Interface |
|---|---|
| UDR (PPPoE) | `ppp0` |
| UDR (DHCP) | `eth3` |
| UDM / UDM-SE | `eth8` |
| USG | `eth0` |
| UDM-Pro | `eth8` or `eth9` |

**Edit `receiver/parsers.py`** — In the `derive_direction()` function, replace all three occurrences of `'ppp0'` with your WAN interface name.

**Edit `receiver/parsers.py`** — Update the `INTERFACE_MAP` dictionary (around line 71) with your VLAN layout:
```python
INTERFACE_MAP = {
    'br0':  'Main',       # Your default LAN
    'br20': 'IoT',        # Example: IoT VLAN
    'br40': 'Guest',      # Example: Guest VLAN
    'ppp0': 'WAN',        # Your WAN interface
}
```

**Edit `ui/src/utils.js`** — Update the `INTERFACE_NAMES` object (around line 79) to match the same labels.

> **Note:** A setup wizard to automate this configuration is coming soon. These manual edits will no longer be needed once it ships.

### 4. MaxMind Databases

You have two options:

**Option A — Auto-download (recommended):** Set `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` in `.env`. If no `.mmdb` files exist on first boot, the container downloads them automatically.

**Option B — Manual download:** Download from your [MaxMind account](https://www.maxmind.com/en/accounts/current/geoip/downloads) and place in the `maxmind/` directory:
- `GeoLite2-City.mmdb`
- `GeoLite2-ASN.mmdb`

### 5. Build and Run

```bash
docker compose up -d --build
```

### 6. Configure Your Unifi Router Syslog

In your UniFi Network controller:
1. Go to **Settings → System → Advanced**
2. Enable **Remote Syslog**
3. Set the syslog server to `<docker-host-ip>` on port `514`

### 7### 3. Configure Network Interfaces

The app needs to know your WAN interface to classify traffic direction (inbound/outbound/inter-VLAN). It defaults to `ppp0` (PPPoE), which is wrong for most non-PPPoE setups.

**Find your WAN interface:**

| UniFi Model | Typical WAN Interface |
|---|---|
| UDR (PPPoE) | `ppp0` |
| UDR (DHCP) | `eth3` |
| UDM / UDM-SE | `eth8` |
| USG | `eth0` |
| UDM-Pro | `eth8` or `eth9` |

**Edit `receiver/parsers.py`** — In the `derive_direction()` function, replace all three occurrences of `'ppp0'` with your WAN interface name.

**Edit `receiver/parsers.py`** — Update the `INTERFACE_MAP` dictionary (around line 71) with your VLAN layout:
```python
INTERFACE_MAP = {
    'br0':  'Main',       # Your default LAN
    'br20': 'IoT',        # Example: IoT VLAN
    'br40': 'Guest',      # Example: Guest VLAN
    'ppp0': 'WAN',        # Your WAN interface
}
```

**Edit `ui/src/utils.js`** — Update the `INTERFACE_NAMES` object (around line 79) to match the same labels.

> **Note:** A setup wizard to automate this configuration is coming soon. These manual edits will no longer be needed once it ships.. Open the UI

Navigate to `http://<docker-host-ip>:8090`

---

## Architecture

Everything runs inside a single Docker container, managed by supervisord:

```
┌──────────────────────────────────────────────────────┐
│  Docker Container                                    │
│                                                      │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────┐  │
│  │   Syslog     │──▶│   Enrichment  │──▶│ PostgreSQL│  │
│  │  Receiver    │   │  GeoIP/ASN   │   │  Storage  │  │
│  │  UDP :514    │   │  AbuseIPDB   │   │          │  │
│  │             │   │  rDNS        │   │          │  │
│  └─────────────┘   └──────────────┘   └────┬─────┘  │
│                                            │        │
│  ┌─────────────┐   ┌─────────────┐   ┌─────┴──────┐  │
│  │    Cron      │   │  Scheduler   │   │  FastAPI    │  │
│  │  MaxMind    │   │  Blacklist   │   │  REST API   │  │
│  │  Updates    │   │  Retention   │   │  + React UI │  │
│  │             │   │  Backfill    │   │  :8000      │  │
│  └─────────────┘   └─────────────┘   └────────────┘  │
└──────────────────────────────────────────────────────┘
        UDP :514                        HTTP :8090
      (syslog in)                     (UI + API out)
```

### Log Processing Pipeline

1. **Receive** — Raw syslog UDP packets from Unifi
2. **Parse** — Extract fields from iptables, hostapd, dhclient, and dnsmasq messages (when DNS logging is enabled)
3. **Validate** — IP address validation rejects malformed data before DB insert
4. **Classify** — Determine direction (inbound/outbound/inter-VLAN/local) based on interfaces and WAN IP
5. **Enrich** — GeoIP country/city/coords, ASN org name, AbuseIPDB threat score + categories + detail fields (verbose mode), reverse DNS
6. **Store** — Batched inserts into PostgreSQL with row-by-row fallback on failure
7. **Serve** — REST API with pagination, filtering, sorting, and CSV export

---

## Configuration Reference

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password for the `unifi` user |
| `ABUSEIPDB_API_KEY` | No | Enables threat scoring on blocked inbound IPs. Free tier: 1,000 check lookups/day + 5 blacklist pulls/day |
| `MAXMIND_ACCOUNT_ID` | No | Enables GeoIP auto-update. Without it, manually place `.mmdb` files |
| `MAXMIND_LICENSE_KEY` | No | Paired with account ID for auto-update |
| `TZ` | No | Timezone for cron schedules. Defaults to UTC. Examples: `Europe/London`, `Asia/Amman`, `America/New_York` |

### Ports

| Port | Protocol | Purpose |
|---|---|---|
| 514 | UDP | Syslog receiver (incoming logs from Unifi) |
| 8090 | TCP | Web UI and REST API |

### Retention Policy

| Log Type | Retention |
|---|---|
| Firewall, DHCP, Wi-Fi, System | 60 days |
| DNS (when enabled) | 10 days |

Cleanup runs daily at 03:00 (container local time).

---

## MaxMind Auto-Update

When credentials are configured, GeoLite2 databases update automatically on **Wednesday and Saturday at 7:00 AM** (local time per `TZ`). This aligns with MaxMind's Tuesday/Friday publish schedule, giving a buffer for propagation.

The receiver hot-reloads databases via signal — no container restart required.

### Manual Update

```bash
docker exec unifi-log-insight /app/geoip-update.sh
```

### Check Update Logs

```bash
docker exec unifi-log-insight cat /var/log/geoip-update.log
```

---

## AbuseIPDB Integration

When `ABUSEIPDB_API_KEY` is configured, the system provides multi-layered threat intelligence:

### Threat Scoring

Blocked firewall events trigger a lookup against AbuseIPDB using verbose mode, returning:
- **Confidence score** (0–100%) with severity classification (Clean/Low/Medium/High/Critical)
- **Attack categories** — Decoded from 23 category codes (Port Scan, SSH, Brute-Force, DDoS, etc.)
- **Usage type** — Data Center, Residential, VPN, etc.
- **Tor exit node** detection
- **Whitelist** status
- **Report count** and last reported date

### Three-Tier Cache

To minimise API usage, lookups follow a cache hierarchy:

1. **In-memory cache** — Hot path, zero I/O
2. **PostgreSQL `ip_threats` table** — Persistent across container rebuilds, 4-day TTL
3. **AbuseIPDB API** — Only called on cache miss, results written back to both tiers

### Blacklist Pre-seeding

A daily pull of the AbuseIPDB blacklist (10,000 highest-risk IPs at 100% confidence) is bulk-inserted into the threat cache. Any blocked IP matching the blacklist gets an instant score from cache — no API call consumed. Uses a separate quota (5 calls/day) independent of the check quota.

The blacklist runs on startup (30-second delay) and then daily at 04:00.

### Rate Limiting

The system uses AbuseIPDB response headers (`X-RateLimit-Remaining`, `Retry-After`) as the single source of truth — no internal counters that desync on container rebuilds. On 429 responses, the enricher pauses automatically until the limit resets.

---

## UI Guide

### Log Stream

The main view shows a live-updating table of parsed logs:

- **Type filters** — Toggle firewall, DNS, DHCP, Wi-Fi, system
- **Time range** — 1h, 6h, 24h, 7d, 30d
- **Action filters** — Allow, block, redirect
- **Direction filters** — Inbound, outbound, VLAN, NAT
- **Text search** — Filter by IP, rule name, or raw log content

Click any row to expand full details including enrichment data, parsed rule breakdown, AbuseIPDB intelligence (score, decoded attack categories, usage type, hostnames, report count, last reported date, Tor/whitelist status), and raw log.

The stream auto-pauses when a row is expanded and shows a count of new logs received. It resumes on collapse.

### Dashboard

Aggregated views with configurable time range:
- Total logs, blocked count, high-threat count
- Traffic direction breakdown
- Logs-per-hour bar chart
- Top blocked countries and IPs (WAN IP and 0.0.0.0 auto-excluded)
- Top threat IPs — enriched with ASN, city, rDNS, decoded attack categories, last seen
- Top DNS queries (when DNS logging is enabled)

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/logs` | Paginated log list with all filters |
| `GET /api/logs/{id}` | Single log detail |
| `GET /api/stats?time_range=24h` | Dashboard aggregations |
| `GET /api/export` | CSV export with current filters |
| `GET /api/health` | Health check with total count and latest timestamp |

---

## DNS Logging

The app includes full DNS query parsing, but **some Unifi Routers/Gateways do not send DNS logs by default**. Their dnsmasq instance lacks the `log-queries` directive, and its configuration is auto-generated by `ubios-udapi-server` — manual edits are overwritten on reboot.

**Current status:** There is no supported persistent method to enable DNS syslog on newer Unifi devices without workarounds that risk breaking on firmware updates.

**Options if you want DNS visibility:**

- **Pi-hole / AdGuard Home** — Deploy as your network's DNS server. These log all queries natively and also provide ad blocking. Point your router's DHCP to hand out the Pi-hole IP as the DNS server.
- **Wait for Ubiquiti** — A future firmware update may expose a DNS logging toggle. The app will capture DNS logs automatically once the router starts emitting them.

The dashboard includes a "Top DNS Queries" panel and the filter bar has a DNS type toggle — both will populate once DNS logs start flowing.

---

## Troubleshooting

### No logs appearing

1. Verify Unifi syslog is configured and pointing to the correct IP
2. Check the container is receiving packets: `docker logs unifi-log-insight | grep "received"`
3. Ensure UDP port 514 isn't blocked by the host firewall

### GeoIP not working

1. Check if `.mmdb` files exist: `docker exec unifi-log-insight ls -la /app/maxmind/`
2. Check enrichment status: `curl http://<host>:8090/api/health`
3. If using auto-update, verify credentials: `docker exec unifi-log-insight /app/geoip-update.sh`

### Container won't start

1. Check logs: `docker compose logs`
2. Verify `.env` exists and `POSTGRES_PASSWORD` is set
3. If PostgreSQL data is corrupted, reset: `docker compose down -v && docker compose up -d --build`

---

## License

MIT
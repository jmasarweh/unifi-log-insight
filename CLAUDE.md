# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Repo:** `jmasarweh/unifi-log-insight` (local clone)
**Key files:** `receiver/backfill.py`, `receiver/api.py`, `receiver/enrichment.py`, `receiver/db.py`, `ui/src/components/LogDetail.jsx`
**Note:** The container has a flat `/app/` structure — no `receiver/` subdirectory at runtime. All Python files sit in `/app/`.

## Build & Run

```bash
docker compose up -d --build          # Build and start
docker compose down                   # Stop
docker compose down -v                # Stop and wipe PostgreSQL data
docker logs unifi-log-insight         # View logs
docker exec unifi-log-insight /app/geoip-update.sh  # Manual MaxMind update
```

**UI development** (outside Docker):
```bash
cd ui && npm install && npm run dev   # Dev server with API proxy to localhost:8000
npm run build                         # Production build → ui/dist
```

There are no tests or linting configured. Verify changes by:
- Container logs: `docker logs unifi-log-insight -f`
- API health: `curl http://localhost:8090/api/health`
- UI at `http://localhost:8090`

## Architecture

Single Docker container running 4 supervised processes (priority order):
1. **PostgreSQL 16** — `unifi_logs` database
2. **receiver** (`receiver/main.py`) — UDP syslog listener + enrichment + backfill
3. **api** (`receiver/api.py`) — FastAPI REST API + static React UI on port 8000
4. **cron** — scheduled MaxMind GeoIP database updates

The Dockerfile is a multi-stage build: Node stage builds the React UI, Ubuntu stage runs everything else. Port mapping: `514/udp` (syslog), `8090→8000` (web UI).

### Log Processing Pipeline

```
UDP packet → SyslogReceiver._handle_message()
  → parsers.parse_log()       # regex extraction, IP validation, direction classification
  → enricher.enrich()         # GeoIP/ASN (local), rDNS, AbuseIPDB (blocked firewall only)
  → batch buffer (50 msgs or 2s timeout)
  → db.insert_logs_batch()    # execute_batch with row-by-row fallback
```

### Three-Tier Threat Cache

AbuseIPDB lookups follow this hierarchy (see `AbuseIPDBEnricher.lookup()`):

1. **In-memory TTLCache** (24h) — thread-safe Python dict, zero I/O
2. **PostgreSQL `ip_threats` table** (4-day freshness) — survives container rebuilds
3. **AbuseIPDB API** — only on combined cache miss, writes back to both tiers

Rate limiting uses API response headers (`X-RateLimit-Remaining`) as single source of truth — no internal counters. Stats written to `/tmp/abuseipdb_stats.json` for cross-process coordination (separate supervisord programs don't share Python memory). The API process has its own `AbuseIPDBEnricher` instance for the manual enrich endpoint; it uses the stats file as the primary budget gate rather than its local enricher state.

### Enrichment Scope

The enricher (`enrichment.py:Enricher.enrich()`) applies AbuseIPDB lookups to **all blocked firewall events** with no direction filter. It picks whichever IP is public: `src_ip` preferred, then `dst_ip` fallback. This means both inbound and outbound blocked traffic get enriched.

### Backfill Daemon

`BackfillTask` (backfill.py) runs every 30 minutes with a 6-step cycle:
1. Patch NULL threat_score logs from `ip_threats` cache (src_ip first, then dst_ip)
2. Patch logs that have scores but missing abuse detail fields (pre-verbose data)
3. Re-enrich stale `ip_threats` entries missing verbose fields (two-stage: 100 most recently seen IPs, then top 25 by threat score)
4. Find orphan IPs not in `ip_threats` (UNION of src_ip + dst_ip, public IPs only)
5. Look up orphans via AbuseIPDB (budget-gated)
6. Final patch pass

The backfill shares the same `AbuseIPDBEnricher` instance as live enrichment — rate limit state, memory cache, and budget are coordinated.

### Blacklist Pre-seeding

`BlacklistFetcher` pulls 10K highest-risk IPs daily into `ip_threats`. Uses `GREATEST()` to never downgrade existing richer check-API scores and preserves richer category arrays over blacklist-only `["blacklist"]` entries. Separate API quota from check lookups.

## Database

Two tables in `unifi_logs` database:

- **`logs`** — all parsed log entries with enrichment columns. 60-day retention (10-day for DNS). Cleanup runs daily at 03:00.
- **`ip_threats`** — persistent AbuseIPDB cache. Primary key: `ip` (INET). No retention — entries accumulate but are considered stale after 4 days for lookup purposes.

Schema migrations run idempotently on every boot via `db.py:_ensure_schema()`. Initial schema is in `init.sql`. Table ownership is transferred to the `unifi` user in `entrypoint.sh` so that `ALTER TABLE` migrations succeed (PostgreSQL requires ownership for DDL, not just `GRANT ALL`).

## Key Patterns

- **INET type**: PostgreSQL INET columns can return values with `/32` suffix depending on psycopg2 behavior. Use `host()` in SQL when extracting IPs as strings for API calls.
- **Batch insert resilience**: `insert_logs_batch()` uses `execute_batch()` with row-by-row fallback — one bad row doesn't block the batch.
- **Connection pooling**: `ThreadedConnectionPool(2, 10)` with a `contextmanager` pattern (`db.get_conn()`).
- **Signal handling**: `SIGTERM/SIGINT` → graceful shutdown, `SIGUSR1` → hot-reload GeoIP databases.
- **WAN IP exclusion**: Automatically learned from firewall rule names containing `WAN_LOCAL`, excluded from AbuseIPDB lookups.
- **API detail endpoint** (`GET /api/logs/{id}`) joins `ip_threats` on **both** `src_ip` and `dst_ip` with COALESCE, supplementing log-level data with cached threat data at query time.
- **Syslog timestamp year inference**: Syslog messages omit the year. The parser (`parsers.py:parse_syslog_timestamp()`) uses the current year and only rolls back to the previous year when the log month is >6 months ahead of the current month (Dec log arriving in Jan). Do **not** use a simple `ts > now` check — gateway clocks are often slightly ahead of the container clock, which would mis-stamp same-day logs with the previous year.
- **SPA path traversal protection**: `serve_spa` in `api.py` resolves the requested path with `pathlib.Path.resolve()` and validates it stays within `STATIC_DIR` before serving. URL-decodes first to prevent encoded `../` bypass.
- **Manual enrich endpoint** (`POST /api/enrich/{ip}`): clears memory cache, backdates `ip_threats.looked_up_at`, calls `lookup()` to force a fresh API hit, then patches all matching log rows. The UI (`LogDetail.jsx`) merges the response into display state immediately.

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password for `unifi` user |
| `ABUSEIPDB_API_KEY` | No | Threat scoring (1000 checks/day + 5 blacklist pulls/day) |
| `MAXMIND_ACCOUNT_ID` | No | GeoIP auto-update |
| `MAXMIND_LICENSE_KEY` | No | Paired with account ID |
| `TZ` | No | Timezone for cron schedules (default: UTC) |
| `LOG_LEVEL` | No | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: `INFO`) |

## File Structure

```
receiver/
├── main.py          # UDP listener, SyslogReceiver class, scheduler thread
├── parsers.py       # Regex parsing for firewall/DNS/DHCP/WiFi, direction logic
├── db.py            # PostgreSQL pool, batch insert, ip_threats cache operations
├── enrichment.py    # GeoIPEnricher, AbuseIPDBEnricher, RDNSEnricher, TTLCache
├── api.py           # FastAPI app with /api/logs, /api/stats, /api/export, /api/enrich, /api/abuseipdb/status
├── backfill.py      # BackfillTask daemon for NULL threat score patching
├── blacklist.py     # Daily AbuseIPDB blacklist fetcher
└── requirements.txt
ui/                  # React 18 + Vite + Tailwind frontend
├── src/main.jsx     # App entry point
├── src/api.js       # API client functions
└── src/components/  # FilterBar, LogStream, Pagination
```

## Release & Version Management

The version flows: `VERSION` file → Dockerfile COPY → `/app/VERSION` → `api.py:_read_version()` → `/api/health` response. The frontend fetches the latest GitHub release and compares it to the app's version. If they don't match, an "Update available" banner appears.

**CI (automated):** The `docker-publish.yml` workflow writes the git tag into `VERSION` before building, so published images always have the correct version. No manual step needed.

**Local builds:** The repo's `VERSION` file is used as-is. Update it when cutting a new release so local `docker compose build` matches too.

Currently at: **v2.0.0**

## Parser Direction Logic

Direction derived from interfaces in `parsers.py:derive_direction()`:
- `ppp0` = WAN interface
- `br0` = Main LAN (VLAN 1), `br20` = IoT (VLAN 20), `br40` = Hotspot (VLAN 40)

Firewall action from UniFi rule naming convention in `derive_action()`:
- `-A-` = allow, `-B-` or `-D-` = block, `-R-` = reject
- `DNAT` or `PREROUTING` in name = redirect (NAT)

# CLAUDE.md

UniFi Log Insight is a self-hosted network monitoring tool for UniFi gateways. It captures syslog messages (firewall, DNS, DHCP, WiFi), enriches them with GeoIP, device names, and AbuseIPDB threat scores, and presents everything through a React dashboard with filtering, analytics, and firewall policy management.

**Repo:** `jmasarweh/unifi-log-insight` — single Docker container: PostgreSQL 16 + Python syslog receiver + FastAPI API + React UI.
**Runtime note:** The container has a flat `/app/` structure — no `receiver/` subdirectory. All Python files sit in `/app/`.
**Version:** v2.9.0 (`VERSION` file → Dockerfile → `deps.py:_read_version()` → `/api/health`). CI writes git tag into `VERSION`. Frontend compares to latest GitHub release for update banner.

**Deep-dive references** (read on demand when working on specific subsystems):
- `CLAUDE-architecture.md` — API routes, log pipeline, UniFi integration, threat cache, enrichment, backfill, blacklist
- `CLAUDE-database.md` — schema, encryption, environment variables
- `CLAUDE-parsers.md` — direction logic, zone matrix algorithm, file structure

## Build & Run

```bash
docker compose up -d --build          # Build and start
docker compose down                   # Stop
docker compose down -v                # Stop and wipe PostgreSQL data, only if asked by the user.
docker logs unifi-log-insight         # View logs
```

**UI development:** `cd ui && npm install && npm run dev` (proxies API to localhost:8000). `npm run build` → `ui/dist`.

No tests or linting. Verify via: container logs, `curl http://localhost:8090/api/health`, UI at `http://localhost:8090`.

## Architecture Overview

4 supervised processes: PostgreSQL 16, receiver (`main.py` — UDP syslog + enrichment + backfill), API (`api.py` — FastAPI + SPA on port 8000), cron (GeoIP updates). Ports: `514/udp` syslog, `8090→8000` web.

`api.py` is a thin shell registering 6 routers from `routes/`. Shared state lives in `deps.py` as singletons. Config hierarchy: env vars > `system_config` DB table > defaults.

Pipeline: UDP → `parsers.parse_log()` → `enricher.enrich()` → batch buffer (50 msgs / 2s) → `db.insert_logs_batch()`.

## Critical Patterns

- **DRY: Modify, don't duplicate**: When changing defaults or values, modify existing constants in place. Never create parallel mappings alongside existing ones — reshape the existing structure instead.
- **INET `/32` suffix**: psycopg2 may append `/32` to INET values. Use `host()` in SQL when extracting IPs as strings.
- **Syslog year inference**: Parser uses current year, rolls back only when log month is >6 months ahead (Dec→Jan). Do NOT use `ts > now` — gateway clocks run slightly ahead.
- **Signal handling**: `SIGTERM/SIGINT` → shutdown, `SIGUSR1` → reload GeoIP, `SIGUSR2` → reload config from `system_config`.
- **Batch insert resilience**: `execute_batch()` with row-by-row fallback.
- **SPA path traversal**: `serve_spa` validates resolved path stays within `STATIC_DIR` after URL-decode.
- **WAN IP exclusion**: Auto-learned from `WAN_LOCAL` rules and UniFi API; excluded from AbuseIPDB lookups.
- **Device name enrichment**: LEFT JOIN `unifi_clients` + `unifi_devices` on IPs with COALESCE fallback chain.
- **API key encryption**: Fernet from `POSTGRES_PASSWORD` via PBKDF2. If password changes, stored keys are unrecoverable.
- **Timezone migration**: One-time boot backfill gated by `system_config.tz_backfill_done` + advisory lock.

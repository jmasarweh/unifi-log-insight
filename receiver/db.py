"""
UniFi Log Insight - Database Module

Handles PostgreSQL connection pooling, log insertion, and retention cleanup.
"""

import os
import logging
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool, extras

logger = logging.getLogger(__name__)

# Column names matching the logs table
INSERT_COLUMNS = [
    'timestamp', 'log_type', 'direction',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service_name',
    'rule_name', 'rule_desc', 'rule_action',
    'interface_in', 'interface_out',
    'mac_address', 'hostname',
    'dns_query', 'dns_type', 'dns_answer',
    'dhcp_event', 'wifi_event',
    'geo_country', 'geo_city', 'geo_lat', 'geo_lon',
    'asn_number', 'asn_name',
    'threat_score', 'threat_categories', 'rdns',
    'abuse_usage_type', 'abuse_hostnames',
    'abuse_total_reports', 'abuse_last_reported',
    'abuse_is_whitelisted', 'abuse_is_tor',
    'raw_log',
]

INSERT_SQL = f"""
    INSERT INTO logs ({', '.join(INSERT_COLUMNS)})
    VALUES ({', '.join(['%s'] * len(INSERT_COLUMNS))})
"""


class Database:
    """PostgreSQL connection pool and operations."""

    def __init__(self, conn_params: dict = None, min_conn: int = 2, max_conn: int = 10):
        self.conn_params = conn_params or {
            'host': '127.0.0.1',
            'port': 5432,
            'dbname': 'unifi_logs',
            'user': 'unifi',
            'password': os.environ.get('POSTGRES_PASSWORD', 'changeme'),
        }
        self.pool = None
        self.min_conn = min_conn
        self.max_conn = max_conn

    def connect(self):
        """Initialize the connection pool."""
        logger.info("Connecting to PostgreSQL...")
        self.pool = pool.ThreadedConnectionPool(
            self.min_conn, self.max_conn, **self.conn_params
        )
        logger.info("PostgreSQL connection pool ready (min=%d, max=%d)", self.min_conn, self.max_conn)
        self._ensure_schema()

    def _ensure_schema(self):
        """Run idempotent schema migrations (safe on every boot)."""
        migrations = [
            # ip_threats persistent cache (added Phase 6)
            """CREATE TABLE IF NOT EXISTS ip_threats (
                ip              INET PRIMARY KEY,
                threat_score    INTEGER NOT NULL DEFAULT 0,
                threat_categories TEXT[],
                looked_up_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS idx_ip_threats_looked_up ON ip_threats (looked_up_at)",
            # AbuseIPDB detail columns on logs (Phase 10)
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_usage_type TEXT",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_hostnames TEXT",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_total_reports INTEGER",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_last_reported TIMESTAMPTZ",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_is_whitelisted BOOLEAN",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_is_tor BOOLEAN",
            # AbuseIPDB detail columns on ip_threats cache (Phase 10)
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_usage_type TEXT",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_hostnames TEXT",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_total_reports INTEGER",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_last_reported TIMESTAMPTZ",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_is_whitelisted BOOLEAN",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_is_tor BOOLEAN",
            # IANA service name mapping (after protocol column)
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS service_name TEXT",
            "CREATE INDEX IF NOT EXISTS idx_logs_service_name ON logs (service_name) WHERE service_name IS NOT NULL",
        ]
        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    for sql in migrations:
                        cur.execute(sql)
            logger.info("Schema migrations applied.")
        except Exception as e:
            logger.error("Schema migration failed: %s", e)

    def close(self):
        """Close all connections in the pool."""
        if self.pool:
            self.pool.closeall()
            logger.info("PostgreSQL connection pool closed.")

    @contextmanager
    def get_conn(self):
        """Get a connection from the pool."""
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn)

    def insert_log(self, parsed: dict):
        """Insert a single parsed log entry."""
        values = tuple(parsed.get(col) for col in INSERT_COLUMNS)

        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(INSERT_SQL, values)

    def insert_logs_batch(self, logs: list[dict]):
        """Insert multiple parsed log entries in a single transaction.
        
        If batch insert fails, falls back to row-by-row to isolate bad data.
        """
        if not logs:
            return

        rows = [
            tuple(log.get(col) for col in INSERT_COLUMNS)
            for log in logs
        ]

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(cur, INSERT_SQL, rows, page_size=100)
            logger.debug("Batch inserted %d logs", len(logs))
        except Exception as batch_err:
            logger.warning("Batch insert failed (%s), falling back to row-by-row for %d logs",
                          batch_err, len(logs))
            inserted = 0
            dropped = 0
            for row in rows:
                try:
                    with self.get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(INSERT_SQL, row)
                    inserted += 1
                except Exception as row_err:
                    dropped += 1
                    logger.warning("Dropped bad log row: %s — raw: %.200s", row_err, row[-1] if row else '?')
            logger.info("Row-by-row fallback: %d inserted, %d dropped", inserted, dropped)

    def run_retention_cleanup(self):
        """Run the retention cleanup function. Returns number of deleted rows."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT cleanup_old_logs()")
                deleted = cur.fetchone()[0]
        if deleted > 0:
            logger.info("Retention cleanup: deleted %d old logs", deleted)
        return deleted

    def get_stats(self) -> dict:
        """Get basic stats for health check / logging."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM logs")
                total = cur.fetchone()[0]
                cur.execute(
                    "SELECT log_type, COUNT(*) FROM logs "
                    "WHERE timestamp > NOW() - INTERVAL '1 hour' "
                    "GROUP BY log_type ORDER BY count DESC"
                )
                hourly = {row[0]: row[1] for row in cur.fetchall()}
        return {'total': total, 'last_hour': hourly}

    # ── Threat cache (ip_threats table) ──────────────────────────────────────

    def get_threat_cache(self, ip: str, max_age_days: int = 4) -> dict | None:
        """Look up a cached threat score. Returns dict or None if stale/missing."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT threat_score, threat_categories, "
                    "abuse_usage_type, abuse_hostnames, abuse_total_reports, "
                    "abuse_last_reported, abuse_is_whitelisted, abuse_is_tor "
                    "FROM ip_threats "
                    "WHERE ip = %s AND looked_up_at > NOW() - INTERVAL '%s days'",
                    [ip, max_age_days]
                )
                row = cur.fetchone()
                if row:
                    result = {
                        'threat_score': row[0],
                        'threat_categories': row[1] or [],
                    }
                    # Include extra fields if present
                    if row[2]: result['abuse_usage_type'] = row[2]
                    if row[3]: result['abuse_hostnames'] = row[3]
                    if row[4] is not None: result['abuse_total_reports'] = row[4]
                    if row[5]: result['abuse_last_reported'] = row[5].isoformat() if hasattr(row[5], 'isoformat') else row[5]
                    if row[6]: result['abuse_is_whitelisted'] = row[6]
                    if row[7]: result['abuse_is_tor'] = row[7]
                    return result
        return None

    def upsert_threat(self, ip: str, threat_data: dict):
        """Insert or update a threat entry for an IP.
        
        threat_data should contain at minimum: threat_score, threat_categories.
        May also contain: abuse_usage_type, abuse_hostnames, abuse_total_reports,
        abuse_last_reported, abuse_is_whitelisted, abuse_is_tor.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO ip_threats (ip, threat_score, threat_categories, "
                    "abuse_usage_type, abuse_hostnames, abuse_total_reports, "
                    "abuse_last_reported, abuse_is_whitelisted, abuse_is_tor, "
                    "looked_up_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()) "
                    "ON CONFLICT (ip) DO UPDATE SET "
                    "  threat_score = EXCLUDED.threat_score, "
                    "  threat_categories = EXCLUDED.threat_categories, "
                    "  abuse_usage_type = COALESCE(EXCLUDED.abuse_usage_type, ip_threats.abuse_usage_type), "
                    "  abuse_hostnames = COALESCE(EXCLUDED.abuse_hostnames, ip_threats.abuse_hostnames), "
                    "  abuse_total_reports = COALESCE(EXCLUDED.abuse_total_reports, ip_threats.abuse_total_reports), "
                    "  abuse_last_reported = COALESCE(EXCLUDED.abuse_last_reported, ip_threats.abuse_last_reported), "
                    "  abuse_is_whitelisted = COALESCE(EXCLUDED.abuse_is_whitelisted, ip_threats.abuse_is_whitelisted), "
                    "  abuse_is_tor = COALESCE(EXCLUDED.abuse_is_tor, ip_threats.abuse_is_tor), "
                    "  looked_up_at = NOW()",
                    [
                        ip,
                        threat_data.get('threat_score', 0),
                        threat_data.get('threat_categories', []),
                        threat_data.get('abuse_usage_type'),
                        threat_data.get('abuse_hostnames'),
                        threat_data.get('abuse_total_reports'),
                        threat_data.get('abuse_last_reported'),
                        threat_data.get('abuse_is_whitelisted'),
                        threat_data.get('abuse_is_tor'),
                    ]
                )

    def bulk_upsert_threats(self, entries: list[tuple]) -> int:
        """Bulk upsert threat scores. entries = [(ip, score, categories), ...].
        
        Uses execute_batch for efficiency. Returns number of rows upserted.
        Only updates existing rows if the new score is >= the existing score,
        so a check-API result with categories won't be overwritten by a
        blacklist entry with just ["blacklist"].
        """
        if not entries:
            return 0

        sql = (
            "INSERT INTO ip_threats (ip, threat_score, threat_categories, looked_up_at) "
            "VALUES (%s, %s, %s, NOW()) "
            "ON CONFLICT (ip) DO UPDATE SET "
            "  threat_score = GREATEST(ip_threats.threat_score, EXCLUDED.threat_score), "
            "  threat_categories = CASE "
            "    WHEN array_length(ip_threats.threat_categories, 1) > 1 "
            "      THEN ip_threats.threat_categories "  # keep richer categories from check API
            "    ELSE EXCLUDED.threat_categories "
            "  END, "
            "  looked_up_at = NOW()"
        )

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(cur, sql, entries, page_size=500)
            logger.info("Bulk upserted %d threat entries", len(entries))
            return len(entries)
        except Exception as e:
            logger.error("Bulk upsert failed: %s", e)
            return 0

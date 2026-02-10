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
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
    'rule_name', 'rule_desc', 'rule_action',
    'interface_in', 'interface_out',
    'mac_address', 'hostname',
    'dns_query', 'dns_type', 'dns_answer',
    'dhcp_event', 'wifi_event',
    'geo_country', 'geo_city', 'geo_lat', 'geo_lon',
    'asn_number', 'asn_name',
    'threat_score', 'threat_categories', 'rdns',
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
                    "SELECT threat_score, threat_categories FROM ip_threats "
                    "WHERE ip = %s AND looked_up_at > NOW() - INTERVAL '%s days'",
                    [ip, max_age_days]
                )
                row = cur.fetchone()
                if row:
                    return {
                        'threat_score': row[0],
                        'threat_categories': row[1] or [],
                    }
        return None

    def upsert_threat(self, ip: str, threat_score: int, threat_categories: list):
        """Insert or update a threat score for an IP."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO ip_threats (ip, threat_score, threat_categories, looked_up_at) "
                    "VALUES (%s, %s, %s, NOW()) "
                    "ON CONFLICT (ip) DO UPDATE SET "
                    "  threat_score = EXCLUDED.threat_score, "
                    "  threat_categories = EXCLUDED.threat_categories, "
                    "  looked_up_at = NOW()",
                    [ip, threat_score, threat_categories]
                )

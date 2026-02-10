"""
UniFi Log Insight - Syslog Receiver

UDP syslog listener that receives logs from UDR, parses them,
and stores them in PostgreSQL.

Phase 1: Receive → Parse → Store
Phase 2 will add: IP enrichment (GeoIP, AbuseIPDB, rDNS)
"""

import os
import sys
import time
import socket
import signal
import logging
import threading
from collections import deque

import schedule

from parsers import parse_log
from db import Database
from enrichment import Enricher
from backfill import BackfillTask

# ── Configuration ──────────────────────────────────────────────────────────────

SYSLOG_PORT = 514
SYSLOG_BUFFER_SIZE = 8192      # Max UDP packet size
BATCH_SIZE = 50                 # Insert logs in batches
BATCH_TIMEOUT = 2.0             # Flush batch after N seconds even if not full
STATS_INTERVAL_MINUTES = 15     # Log stats every N minutes
RETENTION_HOUR = "03:00"        # Run retention cleanup daily at this time

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout,
)
logger = logging.getLogger('receiver')


# ── Syslog Receiver ───────────────────────────────────────────────────────────

class SyslogReceiver:
    """UDP syslog receiver with batched database writes."""

    def __init__(self, db: Database, enricher: Enricher):
        self.db = db
        self.enricher = enricher
        self.sock = None
        self.running = False
        self.batch: list[dict] = []
        self.batch_lock = threading.Lock()
        self.last_flush = time.time()
        self.stats = {
            'received': 0,
            'parsed': 0,
            'failed': 0,
            'inserted': 0,
        }

    def start(self):
        """Start the UDP listener."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Set receive buffer to 1MB to handle bursts
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)

        self.sock.bind(('0.0.0.0', SYSLOG_PORT))
        self.sock.settimeout(1.0)  # Allow periodic batch flushing
        self.running = True

        logger.info("Syslog receiver listening on UDP port %d", SYSLOG_PORT)

        while self.running:
            try:
                data, addr = self.sock.recvfrom(SYSLOG_BUFFER_SIZE)
                self._handle_message(data, addr)
            except socket.timeout:
                pass
            except OSError as e:
                if self.running:
                    logger.error("Socket error: %s", e)
            finally:
                # Check if batch needs flushing by timeout
                self._maybe_flush_batch()

    def stop(self):
        """Stop the receiver and flush remaining logs."""
        logger.info("Stopping syslog receiver...")
        self.running = False
        self._flush_batch()
        if self.sock:
            self.sock.close()
        logger.info("Syslog receiver stopped. Stats: %s", self.stats)

    def _handle_message(self, data: bytes, addr: tuple):
        """Process a single syslog message."""
        self.stats['received'] += 1

        try:
            raw_log = data.decode('utf-8', errors='replace').strip()
        except Exception as e:
            logger.warning("Failed to decode message from %s: %s", addr, e)
            self.stats['failed'] += 1
            return

        if not raw_log:
            return

        parsed = parse_log(raw_log)
        if parsed is None:
            self.stats['failed'] += 1
            logger.debug("Unparseable log from %s: %.100s...", addr, raw_log)
            return

        self.stats['parsed'] += 1

        # Enrich with GeoIP, ASN, AbuseIPDB, rDNS
        parsed = self.enricher.enrich(parsed)

        with self.batch_lock:
            self.batch.append(parsed)
            if len(self.batch) >= BATCH_SIZE:
                self._flush_batch()

    def _maybe_flush_batch(self):
        """Flush batch if timeout elapsed."""
        if time.time() - self.last_flush >= BATCH_TIMEOUT:
            with self.batch_lock:
                if self.batch:
                    self._flush_batch()

    def _flush_batch(self):
        """Write current batch to database."""
        if not self.batch:
            self.last_flush = time.time()
            return

        to_insert = self.batch[:]
        self.batch = []
        self.last_flush = time.time()

        try:
            self.db.insert_logs_batch(to_insert)
            self.stats['inserted'] += len(to_insert)
        except Exception as e:
            logger.error("Failed to insert batch of %d logs: %s", len(to_insert), e)
            self.stats['failed'] += len(to_insert)


# ── Scheduler ─────────────────────────────────────────────────────────────────

def run_scheduler(db: Database, enricher: Enricher):
    """Background thread for scheduled tasks (retention cleanup, stats)."""

    def log_stats():
        try:
            db_stats = db.get_stats()
            enrich_stats = enricher.get_stats()
            logger.info("DB stats — total: %s, last hour: %s", db_stats['total'], db_stats['last_hour'])
            logger.info("Enrichment stats — %s", enrich_stats)
        except Exception as e:
            logger.error("Failed to get stats: %s", e)

    def retention_cleanup():
        try:
            db.run_retention_cleanup()
        except Exception as e:
            logger.error("Retention cleanup failed: %s", e)

    schedule.every(STATS_INTERVAL_MINUTES).minutes.do(log_stats)
    schedule.every().day.at(RETENTION_HOUR).do(retention_cleanup)

    logger.info("Scheduler started — stats every %dm, retention daily at %s",
                 STATS_INTERVAL_MINUTES, RETENTION_HOUR)

    while True:
        schedule.run_pending()
        time.sleep(10)


# ── Main ──────────────────────────────────────────────────────────────────────

def wait_for_postgres(conn_params: dict, max_retries: int = 30, delay: float = 2.0):
    """Wait for PostgreSQL to be ready."""
    import psycopg2
    for i in range(max_retries):
        try:
            conn = psycopg2.connect(**conn_params)
            conn.close()
            logger.info("PostgreSQL is ready.")
            return
        except psycopg2.OperationalError:
            logger.info("Waiting for PostgreSQL... (%d/%d)", i + 1, max_retries)
            time.sleep(delay)
    logger.error("PostgreSQL not available after %d retries", max_retries)
    sys.exit(1)


def main():
    # Build connection params (safe for passwords with special chars)
    conn_params = {
        'host': '127.0.0.1',
        'port': 5432,
        'dbname': 'unifi_logs',
        'user': 'unifi',
        'password': os.environ.get('POSTGRES_PASSWORD', 'changeme'),
    }

    # Wait for PostgreSQL
    wait_for_postgres(conn_params)

    # Initialize database
    db = Database(conn_params)
    db.connect()

    # Initialize enrichment
    enricher = Enricher(db=db)

    # Start receiver
    receiver = SyslogReceiver(db, enricher)

    # Handle graceful shutdown
    def shutdown(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        receiver.stop()
        enricher.close()
        db.close()
        sys.exit(0)

    # Handle GeoIP database reload
    def reload_geoip(signum, frame):
        logger.info("Received SIGUSR1, reloading GeoIP databases...")
        enricher.reload_geoip()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGUSR1, reload_geoip)

    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, args=(db, enricher), daemon=True)
    scheduler_thread.start()

    # Start backfill daemon (patches NULL threat scores every 30 min)
    backfill = BackfillTask(db, enricher.abuseipdb)
    backfill.start()

    # Start receiving (blocks)
    try:
        receiver.start()
    except KeyboardInterrupt:
        receiver.stop()
        enricher.close()
        db.close()


if __name__ == '__main__':
    main()

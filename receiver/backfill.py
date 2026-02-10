"""
UniFi Log Insight - Threat Score Backfill

Background daemon thread that periodically:
1. Patches NULL threat_score log rows from ip_threats cache
2. Looks up orphan IPs (not in cache) via AbuseIPDB
3. Patches newly-fetched scores back to log rows

Fixes gaps caused by 429 pauses and intermittent API timeouts.
"""

import time
import logging
import threading

logger = logging.getLogger('backfill')

BACKFILL_INTERVAL_SECONDS = 1800  # 30 minutes


class BackfillTask:
    """Periodic backfill of missing threat scores."""

    def __init__(self, db, abuseipdb_enricher):
        """
        Args:
            db: Database instance with connection pool
            abuseipdb_enricher: AbuseIPDBEnricher instance (shared with live enrichment)
        """
        self.db = db
        self.abuseipdb = abuseipdb_enricher
        self._thread = None

    def start(self):
        """Start the backfill daemon thread."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name='backfill')
        self._thread.start()
        logger.info("Backfill task started — runs every %ds", BACKFILL_INTERVAL_SECONDS)

    def _run_loop(self):
        """Main loop — sleep then backfill."""
        # Initial delay: let the system settle after startup
        time.sleep(60)

        while True:
            try:
                self._run_once()
            except Exception as e:
                logger.error("Backfill cycle failed: %s", e)

            time.sleep(BACKFILL_INTERVAL_SECONDS)

    def _run_once(self):
        """Execute one backfill cycle."""
        # Step 1: Patch NULL-scored rows from ip_threats cache
        patched = self._patch_from_cache()

        # Step 2: Find orphan IPs (NULL score, not in ip_threats)
        orphans = self._find_orphans()

        # Step 3: Look up orphans via AbuseIPDB (respects shared rate limits)
        budget = self.abuseipdb.remaining_budget
        if orphans and budget == 0:
            logger.info(
                "Backfill: %d rows patched from cache, %d orphans pending but no API budget left",
                patched, len(orphans)
            )
            return

        # Only attempt as many as we have budget for
        to_lookup = orphans[:budget] if budget > 0 else []
        skipped = len(orphans) - len(to_lookup)

        looked_up = 0
        failed = 0
        for ip in to_lookup:
            result = self.abuseipdb.lookup(ip)
            if result and 'threat_score' in result:
                looked_up += 1
            else:
                failed += 1
            time.sleep(1)  # Avoid rapid-fire API calls causing timeouts

        # Step 4: Patch again to write newly-fetched scores to log rows
        patched_2 = 0
        if looked_up > 0:
            patched_2 = self._patch_from_cache()

        total_patched = patched + patched_2
        if total_patched > 0 or looked_up > 0 or failed > 0 or skipped > 0:
            logger.info(
                "Backfill complete: %d rows patched from cache, "
                "%d orphan IPs looked up, %d failed, %d skipped (no budget), "
                "%d rows patched from new lookups",
                patched, looked_up, failed, skipped, patched_2
            )
        else:
            logger.info("Backfill: nothing to do")

    def _patch_from_cache(self) -> int:
        """Update NULL threat_score log rows from ip_threats table.
        
        Only patches inbound blocked firewall logs (src_ip).
        Returns number of rows updated.
        """
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE logs
                    SET threat_score = t.threat_score,
                        threat_categories = t.threat_categories
                    FROM ip_threats t
                    WHERE logs.src_ip = t.ip
                      AND logs.threat_score IS NULL
                      AND logs.log_type = 'firewall'
                      AND logs.rule_action = 'block'
                      AND logs.direction = 'inbound'
                """)
                return cur.rowcount

    def _find_orphans(self) -> list[str]:
        """Find IPs with NULL scores that are NOT in ip_threats cache.
        
        These are IPs where the API call genuinely failed (timeout/error).
        Only looks at inbound blocked firewall logs (src_ip).
        """
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT l.src_ip
                    FROM logs l
                    LEFT JOIN ip_threats t ON l.src_ip = t.ip
                    WHERE l.threat_score IS NULL
                      AND l.log_type = 'firewall'
                      AND l.rule_action = 'block'
                      AND l.direction = 'inbound'
                      AND l.src_ip IS NOT NULL
                      AND t.ip IS NULL
                """)
                return [row[0] for row in cur.fetchall()]

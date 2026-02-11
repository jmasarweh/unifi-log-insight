"""
UniFi Log Insight - Threat Score Backfill

Background daemon thread that periodically:
1. Patches NULL threat_score log rows from ip_threats cache
2. Patches logs that have scores but missing abuse detail fields
3. Re-enriches stale ip_threats entries (pre-verbose) to populate abuse fields
4. Looks up orphan IPs (not in cache) via AbuseIPDB
5. Patches newly-fetched scores back to log rows

Fixes gaps caused by 429 pauses, intermittent API timeouts,
and the Phase 10 verbose migration.
"""

import time
import logging
import threading

from enrichment import is_public_ip

logger = logging.getLogger('backfill')

BACKFILL_INTERVAL_SECONDS = 1800  # 30 minutes
STALE_REENRICH_BATCH = 25  # Max IPs to re-enrich per cycle


class BackfillTask:
    """Periodic backfill of missing threat scores and abuse detail fields."""

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
        patched_null = self._patch_from_cache()

        # Step 2: Patch logs that have scores but missing abuse detail fields
        patched_abuse = self._patch_abuse_fields()

        # Step 3: Re-enrich stale ip_threats (pre-verbose entries missing abuse fields)
        reenriched = self._reenrich_stale_threats()

        # Step 4: Find orphan IPs (NULL score, not in ip_threats)
        orphans = self._find_orphans()

        # Step 5: Look up orphans via AbuseIPDB (respects shared rate limits)
        budget = self.abuseipdb.remaining_budget
        if orphans and budget == 0:
            logger.info(
                "Backfill: %d null-score patched, %d abuse-fields patched, "
                "%d re-enriched, %d orphans pending but no API budget",
                patched_null, patched_abuse, reenriched, len(orphans)
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

        # Step 6: Patch again to write newly-fetched scores to log rows
        patched_final = 0
        if looked_up > 0 or reenriched > 0:
            patched_final = self._patch_from_cache() + self._patch_abuse_fields()

        total_patched = patched_null + patched_abuse + patched_final
        if total_patched > 0 or looked_up > 0 or failed > 0 or skipped > 0 or reenriched > 0:
            logger.info(
                "Backfill complete: %d null-score patched, %d abuse-fields patched, "
                "%d ip_threats re-enriched, %d orphans looked up, %d failed, "
                "%d skipped (no budget), %d rows patched from new data",
                patched_null, patched_abuse, reenriched,
                looked_up, failed, skipped, patched_final
            )
        else:
            logger.info("Backfill: nothing to do")

    def _patch_from_cache(self) -> int:
        """Update NULL threat_score log rows from ip_threats table.

        Patches score, categories, and AbuseIPDB detail fields.
        Two-pass approach mirrors enricher priority: src_ip first, then dst_ip
        for remaining NULLs (e.g. outbound blocked traffic).
        Returns number of rows updated.
        """
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                # Pass 1: patch where src_ip matches (most common — inbound)
                cur.execute("""
                    UPDATE logs
                    SET threat_score = t.threat_score,
                        threat_categories = t.threat_categories,
                        abuse_usage_type = COALESCE(logs.abuse_usage_type, t.abuse_usage_type),
                        abuse_hostnames = COALESCE(logs.abuse_hostnames, t.abuse_hostnames),
                        abuse_total_reports = COALESCE(logs.abuse_total_reports, t.abuse_total_reports),
                        abuse_last_reported = COALESCE(logs.abuse_last_reported, t.abuse_last_reported),
                        abuse_is_whitelisted = COALESCE(logs.abuse_is_whitelisted, t.abuse_is_whitelisted),
                        abuse_is_tor = COALESCE(logs.abuse_is_tor, t.abuse_is_tor)
                    FROM ip_threats t
                    WHERE logs.src_ip = t.ip
                      AND logs.threat_score IS NULL
                      AND logs.log_type = 'firewall'
                      AND logs.rule_action = 'block'
                """)
                patched = cur.rowcount

                # Pass 2: patch remaining NULLs where dst_ip matches
                # (outbound blocked traffic where dst_ip was the enriched IP).
                # Pass 1 already filled src_ip matches, so this only touches
                # rows where src_ip had no ip_threats entry — matching enricher
                # fallback logic (prefer src_ip, else dst_ip).
                cur.execute("""
                    UPDATE logs
                    SET threat_score = t.threat_score,
                        threat_categories = t.threat_categories,
                        abuse_usage_type = COALESCE(logs.abuse_usage_type, t.abuse_usage_type),
                        abuse_hostnames = COALESCE(logs.abuse_hostnames, t.abuse_hostnames),
                        abuse_total_reports = COALESCE(logs.abuse_total_reports, t.abuse_total_reports),
                        abuse_last_reported = COALESCE(logs.abuse_last_reported, t.abuse_last_reported),
                        abuse_is_whitelisted = COALESCE(logs.abuse_is_whitelisted, t.abuse_is_whitelisted),
                        abuse_is_tor = COALESCE(logs.abuse_is_tor, t.abuse_is_tor)
                    FROM ip_threats t
                    WHERE logs.dst_ip = t.ip
                      AND logs.threat_score IS NULL
                      AND logs.log_type = 'firewall'
                      AND logs.rule_action = 'block'
                """)
                patched += cur.rowcount

                return patched

    def _patch_abuse_fields(self) -> int:
        """Patch logs that HAVE a threat_score but are MISSING abuse detail fields.

        This covers logs scored before verbose mode was enabled.
        Only patches from ip_threats entries that have abuse data.
        Two-pass: src_ip first, then dst_ip for remaining gaps.
        Returns number of rows updated.
        """
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                # Pass 1: src_ip match
                cur.execute("""
                    UPDATE logs
                    SET abuse_usage_type = t.abuse_usage_type,
                        abuse_hostnames = t.abuse_hostnames,
                        abuse_total_reports = t.abuse_total_reports,
                        abuse_last_reported = t.abuse_last_reported,
                        abuse_is_whitelisted = t.abuse_is_whitelisted,
                        abuse_is_tor = t.abuse_is_tor,
                        threat_categories = CASE
                            WHEN t.threat_categories IS NOT NULL
                                 AND array_length(t.threat_categories, 1) > 0
                                 AND (logs.threat_categories IS NULL
                                      OR array_length(logs.threat_categories, 1) IS NULL
                                      OR array_length(logs.threat_categories, 1) = 0)
                            THEN t.threat_categories
                            ELSE logs.threat_categories
                        END
                    FROM ip_threats t
                    WHERE logs.src_ip = t.ip
                      AND logs.threat_score IS NOT NULL
                      AND logs.abuse_usage_type IS NULL
                      AND t.abuse_usage_type IS NOT NULL
                      AND logs.log_type = 'firewall'
                      AND logs.rule_action = 'block'
                """)
                patched = cur.rowcount

                # Pass 2: dst_ip match for remaining gaps
                cur.execute("""
                    UPDATE logs
                    SET abuse_usage_type = t.abuse_usage_type,
                        abuse_hostnames = t.abuse_hostnames,
                        abuse_total_reports = t.abuse_total_reports,
                        abuse_last_reported = t.abuse_last_reported,
                        abuse_is_whitelisted = t.abuse_is_whitelisted,
                        abuse_is_tor = t.abuse_is_tor,
                        threat_categories = CASE
                            WHEN t.threat_categories IS NOT NULL
                                 AND array_length(t.threat_categories, 1) > 0
                                 AND (logs.threat_categories IS NULL
                                      OR array_length(logs.threat_categories, 1) IS NULL
                                      OR array_length(logs.threat_categories, 1) = 0)
                            THEN t.threat_categories
                            ELSE logs.threat_categories
                        END
                    FROM ip_threats t
                    WHERE logs.dst_ip = t.ip
                      AND logs.threat_score IS NOT NULL
                      AND logs.abuse_usage_type IS NULL
                      AND t.abuse_usage_type IS NOT NULL
                      AND logs.log_type = 'firewall'
                      AND logs.rule_action = 'block'
                """)
                patched += cur.rowcount

                return patched

    def _reenrich_stale_threats(self) -> int:
        """Re-lookup ip_threats entries that are missing abuse detail fields.

        These are entries created before verbose mode was enabled.
        Excludes blacklist-only entries (they don't have detail data).
        Limited to STALE_REENRICH_BATCH per cycle to conserve API budget.

        Strategy: expire stale entries by backdating looked_up_at, then
        call lookup() which will see them as expired and hit the API.
        Returns number of IPs re-enriched.
        """
        budget = self.abuseipdb.remaining_budget
        if budget == 0:
            return 0

        batch_size = min(STALE_REENRICH_BATCH, budget)

        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                # Find stale entries
                cur.execute("""
                    SELECT host(ip) as ip_str
                    FROM ip_threats
                    WHERE abuse_usage_type IS NULL
                      AND (threat_categories IS NULL
                           OR threat_categories = '{}'
                           OR threat_categories = '{"blacklist"}')
                      AND threat_score > 0
                    ORDER BY threat_score DESC
                    LIMIT %s
                """, [batch_size])
                stale_ips = [row[0] for row in cur.fetchall()]

        if not stale_ips:
            return 0

        # Expire these entries so lookup() bypasses cache and hits API
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE ip_threats
                    SET looked_up_at = NOW() - INTERVAL '30 days'
                    WHERE ip = ANY(%s::inet[])
                """, [stale_ips])

        # Clear from memory cache too
        for ip in stale_ips:
            self.abuseipdb.cache.delete(ip)

        reenriched = 0
        for ip in stale_ips:
            result = self.abuseipdb.lookup(ip)
            if result and result.get('abuse_usage_type'):
                reenriched += 1
            time.sleep(1)  # Avoid rapid-fire API calls

        return reenriched

    def _find_orphans(self) -> list[str]:
        """Find public IPs with NULL scores that are NOT in ip_threats cache.

        Checks both src_ip and dst_ip to match enricher scope.
        Uses host() to guarantee bare IP strings (no /32 suffix from INET).
        Returns only public IPs (enricher skips private IPs).
        """
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT host(ip) FROM (
                        SELECT l.src_ip AS ip
                        FROM logs l
                        LEFT JOIN ip_threats t ON l.src_ip = t.ip
                        WHERE l.threat_score IS NULL
                          AND l.log_type = 'firewall'
                          AND l.rule_action = 'block'
                          AND l.src_ip IS NOT NULL
                          AND t.ip IS NULL
                        UNION
                        SELECT l.dst_ip AS ip
                        FROM logs l
                        LEFT JOIN ip_threats t ON l.dst_ip = t.ip
                        WHERE l.threat_score IS NULL
                          AND l.log_type = 'firewall'
                          AND l.rule_action = 'block'
                          AND l.dst_ip IS NOT NULL
                          AND t.ip IS NULL
                    ) sub
                """)
                return [row[0] for row in cur.fetchall()
                        if is_public_ip(row[0])]
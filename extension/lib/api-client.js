import { CACHE_TTL, BATCH_MAX, MAX_CACHE_SIZE } from './constants.js';

/**
 * API client for communicating with the Log Insight backend.
 * Used by the service worker — makes direct fetch calls.
 */

let baseUrl = '';
const threatCache = new Map(); // ip -> { data, timestamp }

export function setBaseUrl(url) {
  baseUrl = url.replace(/\/+$/, '');
}

export function getBaseUrl() {
  return baseUrl;
}

/**
 * Check if the Log Insight server is reachable and return health data.
 */
export async function checkHealth(url) {
  const target = url || baseUrl;
  if (!target) return null;
  try {
    const resp = await fetch(`${target}/api/health`, { signal: AbortSignal.timeout(5000) });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (err) {
    console.debug('[ULI][API] health check failed:', target, err?.message);
    return null;
  }
}

/**
 * Fetch UniFi settings to discover the controller URL.
 */
export async function fetchUniFiSettings() {
  if (!baseUrl) return null;
  try {
    const resp = await fetch(`${baseUrl}/api/settings/unifi`, { signal: AbortSignal.timeout(5000) });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (err) {
    console.debug('[ULI][API] fetchUniFiSettings failed:', err?.message);
    return null;
  }
}

/**
 * Batch lookup threat data for multiple IPs from the local cache.
 * Uses POST /api/threats/batch endpoint.
 */
export async function batchThreatLookup(ips) {
  if (!baseUrl || !ips?.length) return {};

  // Check in-memory cache first
  const uncached = [];
  const results = {};
  for (const ip of ips) {
    const cached = threatCache.get(ip);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      results[ip] = cached.data;
    } else {
      uncached.push(ip);
    }
  }

  if (uncached.length === 0) return results;

  // Batch fetch uncached IPs (respect max batch size)
  for (let i = 0; i < uncached.length; i += BATCH_MAX) {
    const batch = uncached.slice(i, i + BATCH_MAX);
    try {
      const resp = await fetch(`${baseUrl}/api/threats/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips: batch }),
        signal: AbortSignal.timeout(5000),
      });
      if (!resp.ok) {
        console.debug('[ULI][API] batch threat lookup returned', resp.status, resp.statusText, resp.url);
        continue;
      }
      const data = await resp.json();
      for (const [ip, threat] of Object.entries(data.results || {})) {
        results[ip] = threat;
        if (threatCache.has(ip)) {
          threatCache.delete(ip);
        } else if (threatCache.size >= MAX_CACHE_SIZE) {
          // Evict oldest (FIFO) entry only when inserting a new key
          const oldest = threatCache.keys().next().value;
          threatCache.delete(oldest);
        }
        threatCache.set(ip, { data: threat, timestamp: Date.now() });
      }
    } catch (err) {
      console.warn('[ULI][API] batch threat lookup failed:', err?.message);
    }
  }

  return results;
}

/**
 * Fetch traffic overview stats (total, allowed, blocked, threats, direction breakdown).
 * Returns a slim subset of /api/stats to keep the popup lightweight.
 */
export async function fetchTrafficStats(timeRange = '24h') {
  if (!baseUrl) return null;
  try {
    const resp = await fetch(
      `${baseUrl}/api/stats/overview?time_range=${encodeURIComponent(timeRange)}`,
      { signal: AbortSignal.timeout(8000) },
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    return {
      total: data.total ?? 0,
      allowed: data.allowed ?? 0,
      blocked: data.blocked ?? 0,
      threats: data.threats ?? 0,
      by_direction: data.by_direction ?? {},
    };
  } catch (err) {
    console.debug('[ULI][API] fetchTrafficStats failed:', err?.message);
    return null;
  }
}

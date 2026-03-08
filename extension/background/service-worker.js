import { DEFAULT_BASE_URL } from '../lib/constants.js';
import { getSettings, saveSettings, setCache } from '../lib/storage.js';
import { checkHealth, fetchUniFiSettings, batchThreatLookup, setBaseUrl, getBaseUrl } from '../lib/api-client.js';

// ── Startup & Auto-Discovery ────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  discover();
});

chrome.runtime.onStartup.addListener(() => {
  discover();
});

/**
 * Auto-discover the Log Insight server and UniFi controller URL.
 * 1. Try stored URL first, then localhost:8090
 * 2. If found, fetch UniFi settings to get controller URL
 * 3. Register content scripts for the controller origin
 */
async function discover() {
  try {
    const settings = await getSettings();

    // Try stored URL first
    if (settings.logInsightUrl) {
      const health = await checkHealth(settings.logInsightUrl);
      if (health) {
        setBaseUrl(settings.logInsightUrl);
        await onConnected(health, settings);
        return;
      }
    }

    // Try default localhost
    const health = await checkHealth(DEFAULT_BASE_URL);
    if (health) {
      setBaseUrl(DEFAULT_BASE_URL);
      await saveSettings({ logInsightUrl: DEFAULT_BASE_URL });
      await onConnected(health, { ...settings, logInsightUrl: DEFAULT_BASE_URL });
      return;
    }

    // Not found — popup will prompt user
    setBadge('?', '#fbbf24');
  } catch (err) {
    console.error('Discovery failed:', err);
    setBadge('!', '#f87171');
  }
}

/**
 * Called when Log Insight server is successfully reached.
 */
async function onConnected(health, settings) {
  setBadge('', '#34d399'); // green — connected
  await setCache('health', { data: health, timestamp: Date.now() });

  // Always mark as configured — Log Insight is reachable
  await saveSettings({ configured: true });

  // Discover controller URL from UniFi settings
  if (!settings.controllerUrl) {
    const unifi = await fetchUniFiSettings();
    if (unifi && unifi.host) {
      const controllerUrl = unifi.host.replace(/\/+$/, '');
      await saveSettings({ controllerUrl });
      await registerContentScripts(controllerUrl);
    }
  } else {
    await registerContentScripts(settings.controllerUrl);
  }
}

// ── Dynamic Content Script Registration ─────────────────────────────────────

async function registerContentScripts(controllerUrl) {
  if (!controllerUrl) return;

  // Build origin match pattern from controller URL
  const origin = toOriginPattern(controllerUrl);
  if (!origin) return;

  // Check host permission for the controller origin
  const hasPermission = await chrome.permissions.contains({ origins: [origin] });
  if (!hasPermission) {
    // Can't request permissions from service worker — store for popup to handle
    await chrome.storage.local.set({ pendingOrigin: origin });
    return;
  }

  // Permission granted — clear any pending request
  await chrome.storage.local.remove('pendingOrigin');

  // Unregister any existing scripts first
  try {
    await chrome.scripting.unregisterContentScripts({ ids: ['uli-controller'] });
  } catch { /* ignore if not registered */ }

  // Register all content scripts together — they share the same isolated world.
  // controller-detector.js runs first, dispatches 'uli-ready' for the others.
  await chrome.scripting.registerContentScripts([{
    id: 'uli-controller',
    matches: [origin],
    js: [
      'content/controller-detector.js',
      'content/tab-injector.js',
      'content/flow-enricher.js',
    ],
    css: ['content/styles.css'],
    runAt: 'document_idle',
  }]);
}

/**
 * Convert a URL to an origin match pattern.
 * e.g., "https://192.168.1.1:443" -> "https://192.168.1.1/*"
 */
function toOriginPattern(url) {
  try {
    const u = new URL(url);
    // Include port in pattern if non-default
    const hostPort = u.port ? `${u.hostname}:${u.port}` : u.hostname;
    return `${u.protocol}//${hostPort}/*`;
  } catch {
    return null;
  }
}

// ── Badge Icon ──────────────────────────────────────────────────────────────

function setBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

// ── Message Handling (content scripts -> service worker) ────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch(err => {
    sendResponse({ ok: false, error: err.message });
  });
  return true; // async response
});

async function handleMessage(msg) {
  // Restore in-memory baseUrl if service worker restarted
  if (!getBaseUrl()) {
    const s = await getSettings();
    if (s.logInsightUrl) setBaseUrl(s.logInsightUrl);
  }

  switch (msg.type) {
    case 'HEALTH_CHECK': {
      const health = await checkHealth(msg.url || undefined);
      return { ok: !!health, data: health };
    }

    case 'BATCH_THREAT_LOOKUP': {
      const results = await batchThreatLookup(msg.ips || []);
      return { ok: true, data: results };
    }

    case 'GET_CONFIG': {
      const settings = await getSettings();
      return { ok: true, data: settings };
    }

    case 'SET_BASE_URL': {
      if (typeof msg.url !== 'string' || !msg.url.trim()) {
        return { ok: false, error: 'Missing or invalid url' };
      }
      const url = msg.url.replace(/\/+$/, '');
      const health = await checkHealth(url);
      if (!health) return { ok: false, error: 'Could not connect' };
      const currentSettings = await getSettings();
      setBaseUrl(url);
      await saveSettings({ logInsightUrl: url });
      await onConnected(health, { ...currentSettings, logInsightUrl: url });
      return { ok: true, data: health };
    }

    case 'PERMISSION_GRANTED': {
      // Called from popup after user grants permission
      const settings = await getSettings();
      if (settings.controllerUrl) {
        await registerContentScripts(settings.controllerUrl);
      }
      return { ok: true };
    }

    case 'GET_BASE_URL': {
      return { ok: true, url: getBaseUrl() };
    }

    case 'DEBUG': {
      const settings = await getSettings();
      const pending = await chrome.storage.local.get('pendingOrigin');
      let registeredScripts = [];
      try {
        registeredScripts = await chrome.scripting.getRegisteredContentScripts();
      } catch (e) {
        registeredScripts = [{ error: e.message }];
      }
      let permissions = {};
      try {
        permissions = await chrome.permissions.getAll();
      } catch (e) {
        permissions = { error: e.message };
      }
      return {
        ok: true,
        data: {
          settings,
          baseUrl: getBaseUrl(),
          pendingOrigin: pending.pendingOrigin || null,
          registeredScripts,
          permissions,
        },
      };
    }

    case 'DISCONNECT': {
      setBaseUrl('');
      setBadge('?', '#fbbf24');
      return { ok: true };
    }

    default:
      return { ok: false, error: `Unknown message type: ${msg.type}` };
  }
}

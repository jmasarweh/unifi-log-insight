const setupView = document.getElementById('setup-view');
const connectedView = document.getElementById('connected-view');
const permissionView = document.getElementById('permission-view');

const urlInput = document.getElementById('url-input');
const connectBtn = document.getElementById('connect-btn');
const setupError = document.getElementById('setup-error');

const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const versionBadge = document.getElementById('version-badge');
const totalLogs = document.getElementById('total-logs');
const blockedToday = document.getElementById('blocked-today');

const openDashboard = document.getElementById('open-dashboard');
const openThreatMap = document.getElementById('open-threat-map');
const openLogs = document.getElementById('open-logs');

const toggleTab = document.getElementById('toggle-tab');
const toggleEnrich = document.getElementById('toggle-enrich');
const disconnectBtn = document.getElementById('disconnect-btn');

const grantBtn = document.getElementById('grant-btn');
const permissionOrigin = document.getElementById('permission-origin');

const reloadBar = document.getElementById('reload-bar');
const reloadBtn = document.getElementById('reload-btn');

// -- Init --

async function init() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
    if (!resp || !resp.ok) {
      showSetup();
      return;
    }
    const settings = resp.data;

    toggleTab.checked = settings.enableTabInjection;
    toggleEnrich.checked = settings.enableFlowEnrichment;

    if (!settings.logInsightUrl || !settings.configured) {
      showSetup();
      return;
    }

    // Check for pending permission grant
    const cached = await chrome.storage.local.get('pendingOrigin');
    if (cached.pendingOrigin) {
      showPermissionRequest(cached.pendingOrigin);
      return;
    }

    showConnected(settings);
  } catch (err) {
    console.error('Popup init error:', err);
    showSetup();
  }
}

// -- Setup View --

function showSetup() {
  setupView.hidden = false;
  connectedView.hidden = true;
  permissionView.hidden = true;
}

connectBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim().replace(/\/+$/, '');
  if (!url) { showError('Please enter a URL'); return; }

  connectBtn.textContent = 'Connecting...';
  connectBtn.disabled = true;
  setupError.hidden = true;

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'SET_BASE_URL', url });

    if (resp.ok) {
      const settings = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });

      // Check if permission is needed
      const cached = await chrome.storage.local.get('pendingOrigin');
      if (cached.pendingOrigin) {
        showPermissionRequest(cached.pendingOrigin);
      } else {
        showConnected(settings.data);
      }
    } else {
      showError(resp.error || 'Could not connect to Log Insight server');
    }
  } catch (err) {
    showError(err.message || 'Connection failed');
  } finally {
    connectBtn.textContent = 'Connect';
    connectBtn.disabled = false;
  }
});

urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') connectBtn.click();
});

function showError(msg) {
  setupError.textContent = msg;
  setupError.hidden = false;
}

// -- Permission View --

function showPermissionRequest(origin) {
  setupView.hidden = true;
  connectedView.hidden = true;
  permissionView.hidden = false;
  permissionOrigin.textContent = origin;

  grantBtn.onclick = async () => {
    const granted = await chrome.permissions.request({ origins: [origin] });
    if (granted) {
      await chrome.storage.local.remove('pendingOrigin');
      await chrome.runtime.sendMessage({ type: 'PERMISSION_GRANTED' });
      const settings = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
      showConnected(settings.data);
    }
  };
}

// -- Connected View --

async function showConnected(settings) {
  setupView.hidden = true;
  connectedView.hidden = true;
  permissionView.hidden = true;

  const baseUrl = settings.logInsightUrl;

  // Set quick links
  openDashboard.href = baseUrl;
  openThreatMap.href = baseUrl + '/#threat-map';
  openLogs.href = baseUrl + '/#logs';

  // Health check
  const resp = await chrome.runtime.sendMessage({ type: 'HEALTH_CHECK' });
  if (resp.ok && resp.data) {
    statusDot.className = 'status-dot connected';
    statusText.textContent = 'Connected';
    versionBadge.textContent = `v${resp.data.version}`;
    totalLogs.textContent = formatNumber(resp.data.total_logs);
    // TODO: Replace with real /api/stats/blocked-today endpoint
    blockedToday.textContent = '-';
  } else {
    statusDot.className = 'status-dot disconnected';
    statusText.textContent = 'Unreachable';
    versionBadge.textContent = '';
  }

  connectedView.hidden = false;
}

// -- Toggles --

function onToggleChanged() {
  chrome.storage.sync.set({
    enableTabInjection: toggleTab.checked,
    enableFlowEnrichment: toggleEnrich.checked,
  });
  reloadBar.hidden = false;
}

toggleTab.addEventListener('change', onToggleChanged);
toggleEnrich.addEventListener('change', onToggleChanged);

// -- Reload controller tab --

reloadBtn.addEventListener('click', async () => {
  reloadBar.hidden = true;

  const resp = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
  const controllerUrl = resp?.data?.controllerUrl;
  if (!controllerUrl) return;

  try {
    const origin = new URL(controllerUrl).origin;
    const tabs = await chrome.tabs.query({ url: origin + '/*' });
    for (const tab of tabs) {
      chrome.tabs.reload(tab.id);
    }
  } catch { /* ignore */ }
});

// -- Disconnect --

disconnectBtn.addEventListener('click', async () => {
  await chrome.storage.sync.set({ logInsightUrl: '', controllerUrl: '', configured: false });
  await chrome.storage.local.clear();
  await chrome.runtime.sendMessage({ type: 'DISCONNECT' });
  showSetup();
});

// -- Helpers --

function formatNumber(n) {
  if (n === null || n === undefined) return '-';
  return n.toLocaleString();
}

// -- Debug --

async function loadDebug() {
  const out = document.getElementById('debug-out');
  if (!out) return;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'DEBUG' });
    out.textContent = JSON.stringify(resp, null, 2);
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

// -- Start --

init();
loadDebug();

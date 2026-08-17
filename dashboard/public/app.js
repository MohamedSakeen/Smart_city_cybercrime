// Smart City Cybercrime SOC Dashboard - Core Client Application
const API_HOST = window.location.hostname || 'localhost';
const DETECTION_ENGINE = `${window.location.protocol}//${API_HOST}:4010`;
const DEVICES = [
  { id: 'traffic-camera', name: 'Traffic Camera', url: `${window.location.protocol}//${API_HOST}:4001` },
  { id: 'smart-meter', name: 'Smart Meter', url: `${window.location.protocol}//${API_HOST}:4002` },
  { id: 'streetlight', name: 'Streetlight', url: `${window.location.protocol}//${API_HOST}:4003` }
];

let autoRefreshActive = true;
let currentTab = 'overview';
let activeIncFilter = 'ALL';
let incidentsData = [];
let alertsData = [];
let assetsData = [];
let eventsData = [];
let metricsData = null;

// Initialize Navigation & Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupGlobalSearch();
  setupSyncControls();
  refreshAll();
  setInterval(() => {
    if (autoRefreshActive) refreshAll();
  }, 3000);
});

function setupNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  // Incident filter pills
  document.querySelectorAll('[data-inc-filter]').forEach(pill => {
    pill.addEventListener('click', (e) => {
      document.querySelectorAll('[data-inc-filter]').forEach(p => p.classList.remove('active'));
      e.target.classList.add('active');
      activeIncFilter = e.target.getAttribute('data-inc-filter');
      renderIncidentsTable();
    });
  });

  // Modal Close
  document.getElementById('modal-close-btn').addEventListener('click', closeModal);
  document.getElementById('modal-backdrop').addEventListener('click', (e) => {
    if (e.target.id === 'modal-backdrop') closeModal();
  });

  // Mobile drawer toggle
  const mobileBtn = document.getElementById('mobile-toggle');
  const sidebar = document.getElementById('sidebar');
  if (mobileBtn) {
    mobileBtn.addEventListener('click', () => sidebar.classList.toggle('open'));
  }

  document.getElementById('clear-sim-log').addEventListener('click', () => {
    document.getElementById('sim-console-output').innerHTML = '<div class="log-line system">> Console cleared.</div>';
  });
}

function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
  });
  document.querySelectorAll('.tab-content').forEach(tab => {
    tab.classList.toggle('active', tab.id === `tab-${tabId}`);
  });

  const titles = {
    overview: 'SOC Security Overview',
    incidents: 'Incident Management Workspace',
    alerts: 'Detection Alerts Registry',
    events: 'Live Security Event Stream',
    assets: 'Asset Inventory & Topology',
    simulator: 'Cyber Range Attack Simulator',
    evidence: 'Forensic Evidence Storage',
    reports: 'PDF Incident Reports',
    health: 'System Health & Metrics'
  };
  document.getElementById('page-title').textContent = titles[tabId] || 'SOC Dashboard';
}

function setupSyncControls() {
  const btn = document.getElementById('pause-sync-btn');
  btn.addEventListener('click', () => {
    autoRefreshActive = !autoRefreshActive;
    const dot = document.getElementById('sync-dot');
    const status = document.getElementById('sync-status');
    
    if (autoRefreshActive) {
      dot.style.backgroundColor = 'var(--accent-green)';
      status.textContent = 'System Healthy';
      btn.title = 'Pause Auto Refresh';
    } else {
      dot.style.backgroundColor = 'var(--accent-yellow)';
      status.textContent = 'Polling Paused';
      btn.title = 'Resume Auto Refresh';
    }
  });
}

function setupGlobalSearch() {
  const input = document.getElementById('global-search');
  input.addEventListener('input', (e) => {
    const term = e.target.value.toLowerCase().trim();
    if (!term) return;
    
    if (term.includes('inc') || term.includes('attack') || term.includes('brute') || term.includes('inject')) {
      switchTab('incidents');
    } else if (term.includes('cam') || term.includes('meter') || term.includes('light') || term.includes('asset')) {
      switchTab('assets');
    } else if (term.includes('hash') || term.includes('evid') || term.includes('sha')) {
      switchTab('evidence');
    }
  });
}

// Master Data Refresh Cycle
async function refreshAll() {
  const syncTime = document.getElementById('sync-time');
  syncTime.textContent = new Date().toLocaleTimeString();

  try {
    const [metricsRes, assetsRes, incidentsRes, alertsRes, eventsRes, healthRes] = await Promise.all([
      fetch(`${DETECTION_ENGINE}/api/metrics`).then(r => r.json()).catch(() => null),
      fetch(`${DETECTION_ENGINE}/api/assets`).then(r => r.json()).catch(() => null),
      fetch(`${DETECTION_ENGINE}/api/incidents`).then(r => r.json()).catch(() => null),
      fetch(`${DETECTION_ENGINE}/alerts`).then(r => r.json()).catch(() => null),
      fetch(`${DETECTION_ENGINE}/api/events`).then(r => r.json()).catch(() => null),
      fetch(`${DETECTION_ENGINE}/api/health`).then(r => r.json()).catch(() => null)
    ]);

    if (metricsRes && metricsRes.data) {
      metricsData = metricsRes.data;
      renderKPIs(metricsData);
      renderSecurityPosture(metricsData);
    }

    if (assetsRes && assetsRes.data) {
      assetsData = assetsRes.data;
      renderAssetsGrid();
      renderTopologySVG();
    }

    if (incidentsRes && incidentsRes.data) {
      incidentsData = incidentsRes.data;
      document.getElementById('nav-incident-badge').textContent = incidentsData.filter(i => i.status !== 'RESOLVED').length;
      renderIncidentsTable();
    }

    if (alertsRes) {
      alertsData = alertsRes;
      renderAlertsTable();
      renderEvidenceTable();
      renderReportsTable();
    }

    if (eventsRes && eventsRes.data) {
      eventsData = eventsRes.data;
      renderLiveActivityFeed();
      renderRawEventsStream();
    }

    if (healthRes) {
      renderSystemHealth(healthRes);
    }
  } catch (err) {
    console.error('Refresh error:', err);
  }
}

// --- Renderers ---

function renderKPIs(m) {
  document.getElementById('kpi-assets').textContent = m.totalAssets;
  document.getElementById('kpi-assets-sub').textContent = `${m.onlineAssets} Online | ${m.offlineAssets} Offline`;
  
  document.getElementById('kpi-open-incidents').textContent = m.openIncidents;
  document.getElementById('kpi-high-risk-sub').textContent = `${m.highRiskIncidents} High/Critical Risk`;
  
  document.getElementById('kpi-events').textContent = m.totalEvents;
  document.getElementById('kpi-mttd').textContent = m.mttdSec;
}

function renderSecurityPosture(m) {
  const scoreEl = document.getElementById('risk-score');
  const barEl = document.getElementById('risk-bar');
  const tagEl = document.getElementById('posture-status-tag');

  const score = m.riskScore;
  scoreEl.textContent = score;
  barEl.style.width = `${score}%`;

  if (score >= 70) {
    scoreEl.style.color = 'var(--accent-red)';
    tagEl.className = 'badge-tag high';
    tagEl.textContent = 'HIGH RISK';
    tagEl.style.background = 'var(--status-high-bg)';
    tagEl.style.color = 'var(--status-high-text)';
  } else if (score >= 40) {
    scoreEl.style.color = 'var(--accent-yellow)';
    tagEl.textContent = 'ELEVATED THREAT';
    tagEl.style.background = 'var(--status-med-bg)';
    tagEl.style.color = 'var(--status-med-text)';
  } else {
    scoreEl.style.color = 'var(--accent-green)';
    tagEl.textContent = 'NORMAL';
    tagEl.style.background = 'var(--status-ok-bg)';
    tagEl.style.color = 'var(--status-ok-text)';
  }
}

function renderLiveActivityFeed() {
  const container = document.getElementById('live-activity-feed');
  const filter = document.getElementById('feed-severity-filter').value;
  
  let list = [...eventsData];
  if (filter !== 'ALL') {
    list = list.filter(e => {
      if (filter === 'High' && (e.type.includes('FAILURE') || e.type.includes('DENIED') || e.type.includes('FIRMWARE'))) return true;
      if (filter === 'Medium' && e.type.includes('SUSPICIOUS')) return true;
      return false;
    });
  }

  if (list.length === 0) {
    container.innerHTML = '<div class="loading-placeholder">No security events logged in activity feed.</div>';
    return;
  }

  container.innerHTML = list.slice(0, 15).map(e => `
    <div class="activity-item">
      <div class="activity-left">
        <span class="activity-ts">${new Date(e.ts).toLocaleTimeString()}</span>
        <span class="badge ${getEventSeverityBadgeClass(e.type)}">${e.device}</span>
        <strong>${e.type}</strong>
      </div>
      <div class="sub-text">${JSON.stringify(e.detail)}</div>
    </div>
  `).join('');
}

function getEventSeverityBadgeClass(type) {
  if (type.includes('FAILURE') || type.includes('DENIED') || type.includes('FIRMWARE')) return 'high';
  if (type.includes('SUSPICIOUS')) return 'medium';
  return 'low';
}

function renderTopologySVG() {
  const container = document.getElementById('topology-view');
  container.innerHTML = `
    <svg width="100%" height="200" viewBox="0 0 500 200" style="background: #F1ECE8; border-radius: 8px; border: 1px solid rgba(0,0,0,0.06);">
      <!-- Central SOC Engine Node -->
      <g transform="translate(250, 35)">
        <rect x="-80" y="-18" width="160" height="36" rx="6" fill="#FFFFFF" stroke="#283FFF" stroke-width="2"/>
        <text x="0" y="4" text-anchor="middle" fill="#283FFF" font-size="11" font-family="var(--font-sans)" font-weight="700">SOC ENGINE [:4010]</text>
      </g>

      <!-- Connections -->
      <line x1="250" y1="53" x2="80" y2="130" stroke="#6b7280" stroke-width="1.5" stroke-dasharray="4,4"/>
      <line x1="250" y1="53" x2="250" y2="130" stroke="#6b7280" stroke-width="1.5" stroke-dasharray="4,4"/>
      <line x1="250" y1="53" x2="420" y2="130" stroke="#6b7280" stroke-width="1.5" stroke-dasharray="4,4"/>

      <!-- Node 1: Camera -->
      <g transform="translate(80, 130)">
        <rect x="-55" y="-18" width="110" height="36" rx="6" fill="#FFFFFF" stroke="${getAssetStroke('traffic-camera')}" stroke-width="2"/>
        <text x="0" y="-2" text-anchor="middle" fill="#18181b" font-size="11" font-family="var(--font-sans)" font-weight="600">Camera</text>
        <text x="0" y="10" text-anchor="middle" fill="#6b7280" font-size="9" font-family="var(--font-mono)">:4001</text>
      </g>

      <!-- Node 2: Meter -->
      <g transform="translate(250, 130)">
        <rect x="-55" y="-18" width="110" height="36" rx="6" fill="#FFFFFF" stroke="${getAssetStroke('smart-meter')}" stroke-width="2"/>
        <text x="0" y="-2" text-anchor="middle" fill="#18181b" font-size="11" font-family="var(--font-sans)" font-weight="600">Meter</text>
        <text x="0" y="10" text-anchor="middle" fill="#6b7280" font-size="9" font-family="var(--font-mono)">:4002</text>
      </g>

      <!-- Node 3: Streetlight -->
      <g transform="translate(420, 130)">
        <rect x="-55" y="-18" width="110" height="36" rx="6" fill="#FFFFFF" stroke="${getAssetStroke('streetlight')}" stroke-width="2"/>
        <text x="0" y="-2" text-anchor="middle" fill="#18181b" font-size="11" font-family="var(--font-sans)" font-weight="600">Streetlight</text>
        <text x="0" y="10" text-anchor="middle" fill="#6b7280" font-size="9" font-family="var(--font-mono)">:4003</text>
      </g>
    </svg>
  `;
}

function getAssetStroke(id) {
  const asset = assetsData.find(a => a.id === id);
  if (!asset || asset.status === 'offline') return '#FF5A3A';
  if (asset.riskLevel === 'High') return '#FF5A3A';
  if (asset.riskLevel === 'Medium') return '#FFAF20';
  return '#283FFF';
}

function renderIncidentsTable() {
  const tbody = document.getElementById('incidents-table-body');
  let list = [...incidentsData];
  if (activeIncFilter !== 'ALL') {
    list = list.filter(i => i.status === activeIncFilter);
  }

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted text-center">No incidents match filter '${activeIncFilter}'. Launch a simulation to generate one.</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(inc => `
    <tr>
      <td><span class="badge ${inc.severity.toLowerCase()}">${inc.severity}</span></td>
      <td><strong class="mono">${inc.id}</strong></td>
      <td>${inc.device}</td>
      <td>${inc.ruleName || inc.ruleType}</td>
      <td><span class="badge ${getStatusBadgeClass(inc.status)}">${inc.status}</span></td>
      <td><code>${inc.mitre ? inc.mitre.id + ' (' + inc.mitre.name + ')' : 'N/A'}</code></td>
      <td class="mono">${new Date(inc.createdAt).toLocaleTimeString()}</td>
      <td>
        <button class="btn btn-secondary" onclick="openIncidentWorkspace('${inc.id}')">Investigate</button>
      </td>
    </tr>
  `).join('');
}

function getStatusBadgeClass(st) {
  if (st === 'NEW') return 'high';
  if (st === 'INVESTIGATING') return 'medium';
  if (st === 'CONTAINED' || st === 'RESOLVED') return 'resolved';
  return 'info';
}

function renderAlertsTable() {
  const tbody = document.getElementById('alerts-table-body');
  const countEl = document.getElementById('alerts-total-count');
  countEl.textContent = `${alertsData.length} Alerts Captured`;

  if (alertsData.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted text-center">No alerts logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = alertsData.map(a => `
    <tr>
      <td><span class="badge ${a.severity.toLowerCase()}">${a.severity}</span></td>
      <td><strong class="mono">${a.id}</strong></td>
      <td>${a.device}</td>
      <td>${a.ruleType}</td>
      <td>${a.message}</td>
      <td class="mono">${a.detectionLatencyMs ? a.detectionLatencyMs + 'ms' : '0ms'}</td>
      <td><code>${a.id}.json</code></td>
      <td>
        <button class="btn btn-secondary" onclick="openIncidentWorkspace('${a.incidentId}')">Inspect</button>
        <a href="${DETECTION_ENGINE}/alerts/${a.id}/report" target="_blank"><button class="btn btn-primary">PDF Report</button></a>
      </td>
    </tr>
  `).join('');
}

function renderRawEventsStream() {
  const container = document.getElementById('raw-events-list');
  const term = document.getElementById('events-search').value.toLowerCase().trim();

  let list = [...eventsData];
  if (term) {
    list = list.filter(e => e.type.toLowerCase().includes(term) || JSON.stringify(e.detail).toLowerCase().includes(term));
  }

  if (list.length === 0) {
    container.innerHTML = '<div class="loading-placeholder">No matching events logged.</div>';
    return;
  }

  container.innerHTML = list.map(e => `
    <div class="activity-item">
      <div class="activity-left">
        <span class="activity-ts">${new Date(e.ts).toLocaleTimeString()}</span>
        <span class="badge ${getEventSeverityBadgeClass(e.type)}">${e.device}</span>
        <strong>${e.type}</strong>
      </div>
      <pre style="margin:0; font-size:11px; background:var(--color-bg-page); padding:6px; border:1px solid var(--color-border); border-radius:4px;">${JSON.stringify(e.detail)}</pre>
    </div>
  `).join('');
}

function renderAssetsGrid() {
  const container = document.getElementById('assets-cards-container');
  container.innerHTML = assetsData.map(a => `
    <div class="asset-card">
      <div class="panel-header">
        <div>
          <h3>${a.name}</h3>
          <span class="sub-text">${a.location}</span>
        </div>
        <span class="badge ${a.riskLevel === 'High' ? 'high' : 'medium'}">${a.riskLevel} Risk</span>
      </div>

      <div class="posture-metrics" style="margin-bottom: 12px;">
        <div class="posture-item"><span class="label">Status</span><span class="val">${a.status.toUpperCase()} ●</span></div>
        <div class="posture-item"><span class="label">Criticality</span><span class="val">${a.criticality}</span></div>
        <div class="posture-item"><span class="label">Active Incidents</span><span class="val danger">${a.openIncidentsCount}</span></div>
      </div>

      <div style="font-size:12px;">
        <strong>Documented Vulnerabilities:</strong>
        <ul style="margin-left: 18px; margin-top: 6px; color: var(--color-red-orange);">
          ${a.vulnerabilities.map(v => `<li>${v}</li>`).join('')}
        </ul>
      </div>
    </div>
  `).join('');
}

function renderEvidenceTable() {
  const tbody = document.getElementById('evidence-table-body');
  if (alertsData.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-muted text-center">No evidence stored.</td></tr>`;
    return;
  }

  tbody.innerHTML = alertsData.map(a => `
    <tr>
      <td><strong class="mono">${a.id}</strong></td>
      <td class="mono">${a.incidentId || 'INC-2026-0001'}</td>
      <td>${a.device}</td>
      <td class="mono">${new Date(a.ts).toLocaleTimeString()}</td>
      <td><code>SHA-256 HASH GUARD</code></td>
      <td>SOC Automated Collection</td>
      <td>
        <button class="btn btn-secondary" onclick="verifyEvidence('${a.id}')">Verify SHA-256</button>
      </td>
    </tr>
  `).join('');
}

function renderReportsTable() {
  const tbody = document.getElementById('reports-table-body');
  if (alertsData.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-muted text-center">No incident reports available.</td></tr>`;
    return;
  }

  tbody.innerHTML = alertsData.map(a => `
    <tr>
      <td><strong class="mono">IncidentReport-${a.id}.pdf</strong></td>
      <td class="mono">${a.incidentId || 'INC-2026-0001'}</td>
      <td>${a.device}</td>
      <td>${a.ruleType}</td>
      <td><span class="badge info">PDF Deliverable</span></td>
      <td>
        <a href="${DETECTION_ENGINE}/alerts/${a.id}/report" target="_blank"><button class="btn btn-primary">Download PDF</button></a>
      </td>
    </tr>
  `).join('');
}

function renderSystemHealth(h) {
  const container = document.getElementById('health-services-grid');
  container.innerHTML = `
    <div class="kpi-card">
      <div class="kpi-title">Detection Engine API</div>
      <div class="kpi-value info" style="font-size:22px;">${h.status}</div>
      <div class="kpi-subtext">MTTD: ${h.mttd}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Evidence Disk Storage</div>
      <div class="kpi-value" style="font-size:22px;">${h.evidenceStorage?.recordCount || 0} Records</div>
      <div class="kpi-subtext">Path: /detection-engine/data/evidence</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Traffic Camera (:4001)</div>
      <div class="kpi-value" style="font-size:22px;">${h.devices?.['traffic-camera']?.status?.toUpperCase() || 'OFFLINE'}</div>
      <div class="kpi-subtext">Latency: ${h.devices?.['traffic-camera']?.latencyMs || 0}ms</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Smart Meter (:4002)</div>
      <div class="kpi-value" style="font-size:22px;">${h.devices?.['smart-meter']?.status?.toUpperCase() || 'OFFLINE'}</div>
      <div class="kpi-subtext">Latency: ${h.devices?.['smart-meter']?.latencyMs || 0}ms</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Streetlight Controller (:4003)</div>
      <div class="kpi-value" style="font-size:22px;">${h.devices?.['streetlight']?.status?.toUpperCase() || 'OFFLINE'}</div>
      <div class="kpi-subtext">Latency: ${h.devices?.['streetlight']?.latencyMs || 0}ms</div>
    </div>
  `;
}

// --- Incident Investigation Workspace Modal ---

async function openIncidentWorkspace(incId) {
  const modal = document.getElementById('modal-backdrop');
  const body = document.getElementById('modal-body-content');
  
  try {
    const res = await fetch(`${DETECTION_ENGINE}/api/incidents/${incId}`);
    const data = await res.json();
    const inc = data.data;

    document.getElementById('modal-title').textContent = `${inc.id}: ${inc.title}`;
    document.getElementById('modal-severity-badge').textContent = inc.severity;
    document.getElementById('modal-severity-badge').className = `badge ${inc.severity.toLowerCase()}`;

    body.innerHTML = `
      <div class="panel-header" style="background:var(--color-bg-page); padding:10px; border:1px solid var(--color-border); border-radius:6px; margin-bottom:14px;">
        <div>
          <strong>Status:</strong> <span class="badge ${getStatusBadgeClass(inc.status)}">${inc.status}</span>
          <span style="margin-left: 12px; color: var(--color-text-muted);">Assigned: ${inc.assignedTo}</span>
        </div>
        <div class="panel-actions" style="display:flex; gap:6px;">
          <button class="btn btn-secondary" onclick="updateIncidentStatus('${inc.id}', 'ACKNOWLEDGED')">Acknowledge</button>
          <button class="btn btn-warning" onclick="updateIncidentStatus('${inc.id}', 'INVESTIGATING')">Investigate</button>
          <button class="btn btn-danger" onclick="updateIncidentStatus('${inc.id}', 'CONTAINED')">Contain</button>
          <button class="btn btn-primary" onclick="updateIncidentStatus('${inc.id}', 'RESOLVED')">Resolve</button>
        </div>
      </div>

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom:14px;">
        <div style="border:1px solid var(--color-border); border-radius:6px; padding:12px; background:#fff;">
          <h4 style="font-size:13px; font-weight:700; margin-bottom:8px;">Attack Timeline & Forensics</h4>
          <p><strong>Captured At:</strong> <span class="mono">${inc.createdAt}</span></p>
          <p><strong>Detection Latency:</strong> <span class="mono">${inc.detectionLatencyMs}ms</span></p>
          <p style="margin-top:6px;"><strong>SHA-256 Evidence Hash:</strong></p>
          <code style="font-size:10px; word-break:break-all; background:var(--color-bg-page); display:block; padding:6px; border-radius:4px; border:1px solid var(--color-border); margin-top:4px;">${inc.evidenceHash}</code>
          <button class="btn btn-secondary" style="margin-top:10px;" onclick="verifyEvidence('${inc.alertId}')">Verify SHA-256 Integrity</button>
        </div>

        <div style="border:1px solid var(--color-border); border-radius:6px; padding:12px; background:#fff;">
          <h4 style="font-size:13px; font-weight:700; margin-bottom:8px;">MITRE ATT&CK Classification</h4>
          ${inc.mitre ? `<p><strong>ID:</strong> <span class="mono">${inc.mitre.id}</span> — ${inc.mitre.name}</p><p style="margin-top:6px;"><a href="${inc.mitre.url}" target="_blank" style="color:var(--color-primary); font-weight:600; text-decoration:none;">View MITRE Documentation &rarr;</a></p>` : '<p>Unclassified</p>'}
          <h4 style="margin-top:12px; font-size:13px; font-weight:700;">Remediation Guidance</h4>
          <p class="sub-text" style="font-size:12px; margin-top:4px;">${inc.remediation}</p>
        </div>
      </div>

      <div style="margin-bottom:12px;">
        <h4 style="font-size:12px; font-weight:700; text-transform:uppercase; margin-bottom:6px; color:var(--color-text-muted);">Trigger Event Payload</h4>
        <pre>${JSON.stringify(inc.evidence?.triggerEvent || {}, null, 2)}</pre>
      </div>

      <div style="margin-bottom:14px;">
        <h4 style="font-size:12px; font-weight:700; text-transform:uppercase; margin-bottom:6px; color:var(--color-text-muted);">Context Window (10 Prior Events)</h4>
        <pre style="max-height:140px;">${JSON.stringify(inc.evidence?.contextWindow || [], null, 2)}</pre>
      </div>

      <div style="border-top:1px solid var(--color-border); padding-top:14px;">
        <a href="${DETECTION_ENGINE}/alerts/${inc.alertId}/report" target="_blank"><button class="btn btn-primary">Download PDF Incident Report</button></a>
      </div>
    `;

    modal.classList.remove('hidden');
  } catch (err) {
    alert('Error loading incident details');
  }
}

async function updateIncidentStatus(incId, status) {
  try {
    await fetch(`${DETECTION_ENGINE}/api/incidents/${incId}/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, note: `Status updated to ${status} via SOC console.` })
    });
    openIncidentWorkspace(incId);
    refreshAll();
  } catch (err) {
    alert('Failed to update status');
  }
}

async function verifyEvidence(alertId) {
  try {
    const res = await fetch(`${DETECTION_ENGINE}/api/evidence/${alertId}/verify`, { method: 'POST' });
    const data = await res.json();
    alert(`Integrity Verification Result:\n\nStatus: ${data.data.status}\nStored SHA-256: ${data.data.storedHash}\nRecomputed Hash: ${data.data.recomputedHash}`);
  } catch (err) {
    alert('Verification failed.');
  }
}

function closeModal() {
  document.getElementById('modal-backdrop').classList.add('hidden');
}

// Attack Simulator Execution
async function runSimulation(scenario) {
  const consoleOut = document.getElementById('sim-console-output');
  consoleOut.innerHTML += `<div class="log-line system">> Launching simulation scenario: '${scenario}'...</div>`;
  consoleOut.scrollTop = consoleOut.scrollHeight;

  try {
    const res = await fetch(`${DETECTION_ENGINE}/api/simulations/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });
    const data = await res.json();

    if (data.steps) {
      data.steps.forEach(s => {
        consoleOut.innerHTML += `<div class="log-line step">[${new Date(s.time).toLocaleTimeString()}] ${s.message}</div>`;
      });
    }
    consoleOut.innerHTML += `<div class="log-line success">> Simulation completed successfully. Detection engine polling now...</div>`;
    consoleOut.scrollTop = consoleOut.scrollHeight;
    
    setTimeout(refreshAll, 1500);
  } catch (err) {
    consoleOut.innerHTML += `<div class="log-line warning">> Error launching simulation: ${err.message}</div>`;
  }
}

window.openIncidentWorkspace = openIncidentWorkspace;
window.updateIncidentStatus = updateIncidentStatus;
window.verifyEvidence = verifyEvidence;
window.runSimulation = runSimulation;

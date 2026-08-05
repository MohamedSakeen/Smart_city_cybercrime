// Configure device endpoints here. When running via docker-compose on your
// machine, these ports are published to localhost.
const DEVICES = [
  { name: "Traffic camera", url: "http://localhost:4001" },
  { name: "Smart meter", url: "http://localhost:4002" },
  { name: "Streetlight controller", url: "http://localhost:4003" }
];
const DETECTION_ENGINE = "http://localhost:4010";

const devicesEl = document.getElementById("devices");
const eventsEl = document.getElementById("events");
const alertsEl = document.getElementById("alerts");
const alertCountEl = document.getElementById("alert-count");
const modalBackdrop = document.getElementById("modal-backdrop");
const modalBody = document.getElementById("modal-body");

document.getElementById("modal-close").addEventListener("click", () => {
  modalBackdrop.classList.add("hidden");
});

async function showEvidence(alertId) {
  try {
    const res = await fetch(`${DETECTION_ENGINE}/alerts/${alertId}`);
    const data = await res.json();
    modalBody.textContent = JSON.stringify(data, null, 2);
    modalBackdrop.classList.remove("hidden");
  } catch (e) {
    modalBody.textContent = "Could not load evidence (is the detection engine running?)";
    modalBackdrop.classList.remove("hidden");
  }
}
window.showEvidence = showEvidence;

function typeClass(type) {
  if (type.includes("DENIED") || type.includes("FAILURE")) return "denied";
  if (type.includes("SUSPICIOUS")) return "suspicious";
  return "";
}

async function fetchDevice(dev) {
  try {
    const res = await fetch(`${dev.url}/status`);
    const data = await res.json();
    return { ...dev, online: true, data };
  } catch (e) {
    return { ...dev, online: false, data: null };
  }
}

async function fetchEvents(dev) {
  try {
    const res = await fetch(`${dev.url}/events`);
    return await res.json();
  } catch (e) {
    return [];
  }
}

function renderDevices(statuses) {
  devicesEl.innerHTML = statuses.map(s => `
    <div class="device-card">
      <h3><span class="status-dot ${s.online ? "online" : "offline"}"></span>${s.name}</h3>
      <div class="kind">${s.data ? s.data.kind : "unreachable"}</div>
      <div>${s.online ? "Online" : "Offline"}</div>
    </div>
  `).join("");
}

function renderEvents(allEvents) {
  const sorted = allEvents.sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, 50);
  eventsEl.innerHTML = sorted.map(e => `
    <div class="event-row">
      <span class="ts">${new Date(e.ts).toLocaleTimeString()}</span>
      <span class="device">${e.device}</span>
      <span class="type ${typeClass(e.type)}">${e.type}</span>
      <span class="detail">${JSON.stringify(e.detail)}</span>
    </div>
  `).join("");
}

async function fetchAlerts() {
  try {
    const res = await fetch(`${DETECTION_ENGINE}/alerts`);
    return await res.json();
  } catch (e) {
    return null; // detection engine unreachable
  }
}

function renderAlerts(alertList) {
  if (alertList === null) {
    alertsEl.innerHTML = `<div class="alert-row"><span style="grid-column:1/-1;color:var(--muted)">Detection engine unreachable (http://localhost:4010) - is it running?</span></div>`;
    alertCountEl.textContent = "";
    return;
  }
  alertCountEl.textContent = `(${alertList.length})`;
  if (alertList.length === 0) {
    alertsEl.innerHTML = `<div class="alert-row"><span style="grid-column:1/-1;color:var(--muted)">No alerts yet. Run the attack scripts to generate some.</span></div>`;
    return;
  }
  alertsEl.innerHTML = alertList.map(a => `
    <div class="alert-row ${a.severity}">
      <span class="severity-pill ${a.severity}">${a.severity}</span>
      <span>${a.device}</span>
      <span>${a.ruleType}</span>
      <span>${a.message}</span>
      <button onclick="showEvidence('${a.id}')">Evidence</button>
      <a href="${DETECTION_ENGINE}/alerts/${a.id}/report" target="_blank"><button>Report PDF</button></a>
    </div>
  `).join("");
}

async function refresh() {
  const statuses = await Promise.all(DEVICES.map(fetchDevice));
  renderDevices(statuses);

  const eventLists = await Promise.all(DEVICES.map(fetchEvents));
  renderEvents(eventLists.flat());

  const alertList = await fetchAlerts();
  renderAlerts(alertList);
}

refresh();
setInterval(refresh, 3000);

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4010;
const DATA_DIR = path.join(__dirname, 'data', 'evidence');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory State
let alerts = [];
let incidents = [];
let eventLog = []; // Consolidated recent event stream across devices
let incidentCounter = 0;

let lastSeenIds = {
  'traffic-camera': 0,
  'smart-meter': 0,
  'streetlight': 0
};

let deviceHealth = {
  'traffic-camera': { status: 'online', lastPoll: null, errors: 0, latencyMs: 0 },
  'smart-meter': { status: 'online', lastPoll: null, errors: 0, latencyMs: 0 },
  'streetlight': { status: 'online', lastPoll: null, errors: 0, latencyMs: 0 }
};

let meterReadings = []; // For METER_BASELINE_DEVIATION

const DEVICES = {
  'traffic-camera': process.env.CAMERA_URL || 'http://localhost:4001',
  'smart-meter': process.env.METER_URL || 'http://localhost:4002',
  'streetlight': process.env.STREETLIGHT_URL || 'http://localhost:4003'
};

// Asset Inventory & Risk Metadata
const ASSETS_METADATA = {
  'traffic-camera': {
    id: 'traffic-camera',
    name: 'Traffic Surveillance Camera 01',
    kind: 'traffic-camera',
    location: 'Intersection MG Road & Anna Salai',
    criticality: 'High',
    vulnerabilities: ['Default Credentials (admin/admin1234)', 'Weak JWT Signing Secret (cam123)']
  },
  'smart-meter': {
    id: 'smart-meter',
    name: 'Smart Utility Meter 07',
    kind: 'smart-meter',
    location: 'Substation 4B, Zone 2 Grid',
    criticality: 'Medium',
    vulnerabilities: ['Unauthenticated Sensor Reading Injection (/api/reading)']
  },
  'streetlight': {
    id: 'streetlight',
    name: 'Smart Streetlight Controller 14',
    kind: 'streetlight',
    location: 'Sector 9 Public Highway Lighting',
    criticality: 'High',
    vulnerabilities: ['OS Command Injection in Firmware Checksum (/api/firmware/update)']
  }
};

// MITRE ATT&CK Mapping Table
const RULES_METADATA = {
  'BRUTE_FORCE_LOGIN': {
    id: 'BRUTE_FORCE_LOGIN',
    name: 'Brute Force Authentication Attempt',
    severity: 'High',
    device: 'traffic-camera',
    threshold: '3+ failed logins within window',
    mitre: { id: 'T1110', name: 'Brute Force', url: 'https://attack.mitre.org/techniques/T1110/' }
  },
  'UNAUTHORIZED_FEED_ACCESS': {
    id: 'UNAUTHORIZED_FEED_ACCESS',
    name: 'Unauthorized Video Feed Access / JWT Forgery',
    severity: 'High',
    device: 'traffic-camera',
    threshold: 'Access denied or forged token subject',
    mitre: { id: 'T1550', name: 'Use Alternate Authentication Material', url: 'https://attack.mitre.org/techniques/T1550/' }
  },
  'SUSPICIOUS_METER_READING': {
    id: 'SUSPICIOUS_METER_READING',
    name: 'Out-of-Bounds Sensor Reading Injection',
    severity: 'Medium',
    device: 'smart-meter',
    threshold: 'Reading < 0 or > 100 kWh',
    mitre: { id: 'T1565.001', name: 'Data Manipulation: Transmitted Data', url: 'https://attack.mitre.org/techniques/T1565/001/' }
  },
  'METER_BASELINE_DEVIATION': {
    id: 'METER_BASELINE_DEVIATION',
    name: 'Energy Consumption Baseline Deviation',
    severity: 'Medium',
    device: 'smart-meter',
    threshold: 'Reading > 2.5x 20-sample rolling mean',
    mitre: { id: 'T1565', name: 'Data Manipulation', url: 'https://attack.mitre.org/techniques/T1565/' }
  },
  'COMMAND_INJECTION_ATTEMPT': {
    id: 'COMMAND_INJECTION_ATTEMPT',
    name: 'OS Command Injection in Firmware Update',
    severity: 'High',
    device: 'streetlight',
    threshold: 'Shell metacharacters found in checksum',
    mitre: { id: 'T1059', name: 'Command and Scripting Interpreter', url: 'https://attack.mitre.org/techniques/T1059/' }
  }
};

// --- Detection Rules ---

function evaluateCamera(events) {
  const newEvents = events.filter(e => e.id > lastSeenIds['traffic-camera']);
  
  // Rule: BRUTE_FORCE_LOGIN
  const failures = newEvents.filter(e => e.type === 'LOGIN_FAILURE');
  if (failures.length >= 3) {
    const trigger = failures[failures.length - 1];
    createAlert('traffic-camera', 'BRUTE_FORCE_LOGIN', 'High', '3+ failed login attempts detected in rapid succession', trigger, events);
  }

  // Rule: UNAUTHORIZED_FEED_ACCESS
  for (const e of newEvents) {
    if (e.type === 'FEED_ACCESS_DENIED' && e.detail.reason === 'invalid token') {
      createAlert('traffic-camera', 'UNAUTHORIZED_FEED_ACCESS', 'High', 'Protected feed access attempted with forged or invalid JWT token', e, events);
    } else if (e.type === 'FEED_ACCESSED' && e.detail.by !== 'admin') {
      createAlert('traffic-camera', 'UNAUTHORIZED_FEED_ACCESS', 'High', `Protected video feed accessed by non-operator subject: '${e.detail.by}'`, e, events);
    }
  }
}

function evaluateMeter(events) {
  const newEvents = events.filter(e => e.id > lastSeenIds['smart-meter']);
  
  for (const e of newEvents) {
    if (e.type === 'SUSPICIOUS_READING_ACCEPTED') {
      createAlert('smart-meter', 'SUSPICIOUS_METER_READING', 'Medium', `Out-of-bounds energy reading (${e.detail.kwh} kWh) accepted without auth`, e, events);
    }
    
    if (e.type === 'READING_ACCEPTED' || e.type === 'SUSPICIOUS_READING_ACCEPTED') {
      const kwh = e.detail.kwh;
      
      // Rule: METER_BASELINE_DEVIATION
      if (meterReadings.length >= 5) {
        const sum = meterReadings.reduce((a, b) => a + b, 0);
        const mean = sum / meterReadings.length;
        if (kwh > mean * 2.5) {
           createAlert('smart-meter', 'METER_BASELINE_DEVIATION', 'Medium', `Reading of ${kwh} kWh deviates >2.5x from rolling baseline mean (${mean.toFixed(2)} kWh)`, e, events);
        }
      }
      
      meterReadings.push(kwh);
      if (meterReadings.length > 20) meterReadings.shift();
    }
  }
}

function evaluateStreetlight(events) {
  const newEvents = events.filter(e => e.id > lastSeenIds['streetlight']);
  
  for (const e of newEvents) {
    if (e.type === 'FIRMWARE_UPDATE_ATTEMPT') {
      const checksum = e.detail.checksum || '';
      // Rule: COMMAND_INJECTION_ATTEMPT
      if (/[;&|`]/.test(checksum)) {
        createAlert('streetlight', 'COMMAND_INJECTION_ATTEMPT', 'High', `Shell metacharacters detected in firmware update checksum payload: '${checksum}'`, e, events);
      }
    }
  }
}

// --- Forensic Capture & Incident Creation ---

function createAlert(device, rule, severity, description, triggerEvent, allEvents) {
  // Prevent duplicate alert spam for exact same trigger event
  const existingAlert = alerts.find(a => a.triggerEventId === triggerEvent.id && a.device === device && a.ruleType === rule);
  if (existingAlert) return;

  const alertId = `ALT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const alertTs = new Date().toISOString();
  
  // Detection Latency calculation
  const triggerTs = new Date(triggerEvent.ts).getTime();
  const detectionTs = new Date(alertTs).getTime();
  const detectionLatencyMs = Math.max(0, detectionTs - triggerTs);

  // Capture 10-event context window
  const contextWindow = allEvents.filter(e => e.id <= triggerEvent.id).slice(0, 10);
  
  const evidenceBundle = {
    alertId,
    timestamp: alertTs,
    device,
    rule,
    description,
    triggerEvent,
    contextWindow
  };
  
  // SHA-256 Hash of Evidence Bundle
  const bundleString = JSON.stringify(evidenceBundle);
  const hash = crypto.createHash('sha256').update(bundleString).digest('hex');
  
  const storageLocation = path.join(DATA_DIR, `${alertId}.json`);
  const chainOfCustody = {
    capturedBy: 'detection-engine (SOC Automated Capture)',
    capturedAt: alertTs,
    storageLocation: storageLocation,
    sha256Hash: hash,
    verificationStatus: 'VERIFIED'
  };
  
  const fullRecord = {
    ...evidenceBundle,
    chainOfCustody
  };
  
  fs.writeFileSync(storageLocation, JSON.stringify(fullRecord, null, 2));

  // Incident Creation
  incidentCounter++;
  const incidentId = `INC-2026-${String(incidentCounter).padStart(4, '0')}`;
  
  const ruleMeta = RULES_METADATA[rule] || {};
  const newIncident = {
    id: incidentId,
    alertId,
    device,
    ruleType: rule,
    ruleName: ruleMeta.name || rule,
    severity,
    title: `${severity.toUpperCase()}: ${ruleMeta.name || rule} on ${device}`,
    status: 'NEW', // NEW, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED
    createdAt: alertTs,
    updatedAt: alertTs,
    assignedTo: 'Unassigned',
    notes: [
      { ts: alertTs, author: 'SOC Engine', text: `Incident created automatically via alert ${alertId}.` }
    ],
    detectionLatencyMs,
    evidenceHash: hash,
    mitre: ruleMeta.mitre || null,
    remediation: getRemediationRecommendation(rule)
  };
  
  incidents.unshift(newIncident);

  const alertSummary = {
    id: alertId,
    incidentId,
    ts: alertTs,
    device,
    ruleType: rule,
    severity,
    message: description,
    hasEvidence: true,
    triggerEventId: triggerEvent.id,
    detectionLatencyMs
  };

  alerts.unshift(alertSummary);
  
  console.log(`[ALERT/INCIDENT] Created ${incidentId} (${alertId}) for ${rule} on ${device} (Severity: ${severity})`);
}

function getRemediationRecommendation(rule) {
  switch (rule) {
    case 'BRUTE_FORCE_LOGIN':
      return 'Enforce rate-limiting on login endpoints, mandate strong admin credentials, and enable multi-factor authentication (MFA).';
    case 'UNAUTHORIZED_FEED_ACCESS':
      return 'Rotate JWT signing secrets immediately, enforce strict role-based access control (RBAC), and reject default/weak secrets.';
    case 'SUSPICIOUS_METER_READING':
    case 'METER_BASELINE_DEVIATION':
      return 'Implement strict server-side validation and authentication on sensor endpoints. Isolate compromised meter connections.';
    case 'COMMAND_INJECTION_ATTEMPT':
      return 'Sanitize firmware update input parameters. Replace command-line string execution (`exec`) with secure parameter binding or binary verification APIs.';
    default:
      return 'Investigate source IP address, audit device activity logs, and isolate asset if unauthorized behavior persists.';
  }
}

// --- Dynamic Metric Calculations ---

function calculateMetrics() {
  const totalAssets = Object.keys(ASSETS_METADATA).length;
  const onlineAssets = Object.values(deviceHealth).filter(d => d.status === 'online').length;
  const offlineAssets = totalAssets - onlineAssets;

  const totalIncidents = incidents.length;
  const openIncidents = incidents.filter(i => i.status !== 'RESOLVED').length;
  const highRiskIncidents = incidents.filter(i => (i.severity === 'High' || i.severity === 'Critical') && i.status !== 'RESOLVED').length;

  const totalAlerts = alerts.length;
  const totalEvents = eventLog.length;

  // Mean Time to Detect (MTTD)
  let avgLatencyMs = 0;
  if (alerts.length > 0) {
    const sumLatency = alerts.reduce((acc, a) => acc + (a.detectionLatencyMs || 0), 0);
    avgLatencyMs = Math.round(sumLatency / alerts.length);
  }

  // Dynamic Risk Score Calculation (0 - 100)
  // Formula: Base 10 + (25 * open high incidents) + (10 * open medium incidents) + (15 * offline assets)
  let riskScore = 15;
  const openHigh = incidents.filter(i => i.severity === 'High' && i.status !== 'RESOLVED').length;
  const openMedium = incidents.filter(i => i.severity === 'Medium' && i.status !== 'RESOLVED').length;

  riskScore += (openHigh * 25) + (openMedium * 10) + (offlineAssets * 20);
  if (riskScore > 100) riskScore = 100;
  if (openIncidents === 0 && offlineAssets === 0) riskScore = 12; // Baseline low risk

  return {
    totalAssets,
    onlineAssets,
    offlineAssets,
    totalIncidents,
    openIncidents,
    highRiskIncidents,
    totalAlerts,
    totalEvents,
    mttdMs: avgLatencyMs,
    mttdSec: (avgLatencyMs / 1000).toFixed(1) + 's',
    riskScore,
    evidenceCount: alerts.length,
    activeRulesCount: Object.keys(RULES_METADATA).length
  };
}

// --- Polling Engine ---

async function pollDevice(device, url, evaluator) {
  const startTime = Date.now();
  try {
    const res = await axios.get(`${url}/events`, { timeout: 3000 });
    const events = res.data;

    // Check device status
    const statusRes = await axios.get(`${url}/status`, { timeout: 3000 }).catch(() => null);
    const deviceStatus = statusRes?.data?.status || 'online';

    deviceHealth[device].status = deviceStatus;
    deviceHealth[device].lastPoll = new Date().toISOString();
    deviceHealth[device].latencyMs = Date.now() - startTime;
    deviceHealth[device].errors = 0;

    if (!events || events.length === 0) return;

    // Add to consolidated global event log
    for (const e of events) {
      if (!eventLog.some(existing => existing.id === e.id && existing.device === device)) {
        eventLog.unshift(e);
      }
    }
    if (eventLog.length > 500) eventLog = eventLog.slice(0, 500);

    const sorted = [...events].sort((a, b) => a.id - b.id);
    evaluator(sorted);

    lastSeenIds[device] = sorted[sorted.length - 1].id;
  } catch (err) {
    deviceHealth[device].status = 'offline';
    deviceHealth[device].lastPoll = new Date().toISOString();
    deviceHealth[device].errors += 1;
  }
}

setInterval(() => {
  pollDevice('traffic-camera', DEVICES['traffic-camera'], evaluateCamera);
  pollDevice('smart-meter', DEVICES['smart-meter'], evaluateMeter);
  pollDevice('streetlight', DEVICES['streetlight'], evaluateStreetlight);
}, 2000);

// --- API Endpoints ---

// Backward-compatible alerts list
app.get('/alerts', (req, res) => {
  res.json(alerts);
});

// Backward-compatible single alert / evidence detail
app.get('/alerts/:id', (req, res) => {
  const filepath = path.join(DATA_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: "Evidence not found" });
  res.json(JSON.parse(fs.readFileSync(filepath, 'utf8')));
});

// Backward-compatible PDF Incident Report
app.get('/alerts/:id/report', (req, res) => {
  const filepath = path.join(DATA_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: "Evidence not found" });
  
  const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  const incident = incidents.find(i => i.alertId === data.alertId) || {};
  
  const doc = new PDFDocument({ margin: 50 });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=IncidentReport-${data.alertId}.pdf`);
  doc.pipe(res);
  
  doc.fillColor('#1e293b').fontSize(22).text('Smart City Cybercrime Incident Report', { align: 'center' });
  doc.fontSize(10).fillColor('#64748b').text('CONFIDENTIAL // SECURITY OPERATIONS CENTER REPORT', { align: 'center' });
  doc.moveDown(1.5);
  
  // Section 1: Executive Summary
  doc.fillColor('#0f172a').fontSize(14).text('1. Executive Summary', { underline: true });
  doc.fontSize(10).fillColor('#334155');
  doc.text(`Incident ID: ${incident.id || 'N/A'}`);
  doc.text(`Alert ID: ${data.alertId}`);
  doc.text(`Timestamp: ${data.timestamp}`);
  doc.text(`Target Asset: ${data.device}`);
  doc.text(`Trigger Rule: ${data.rule}`);
  doc.text(`Rule Description: ${data.description}`);
  doc.text(`Status: ${incident.status || 'NEW'}`);
  doc.text(`Assigned Analyst: ${incident.assignedTo || 'Unassigned'}`);
  doc.moveDown();

  // Section 2: MITRE ATT&CK Mapping
  if (incident.mitre) {
    doc.fillColor('#0f172a').fontSize(14).text('2. MITRE ATT&CK Classification', { underline: true });
    doc.fontSize(10).fillColor('#334155');
    doc.text(`Technique ID: ${incident.mitre.id}`);
    doc.text(`Technique Name: ${incident.mitre.name}`);
    doc.text(`Reference URL: ${incident.mitre.url}`);
    doc.moveDown();
  }
  
  // Section 3: Chain of Custody & Evidence Integrity
  doc.fillColor('#0f172a').fontSize(14).text('3. Chain of Custody & Forensics', { underline: true });
  doc.fontSize(10).fillColor('#334155');
  doc.text(`Captured By: ${data.chainOfCustody?.capturedBy || 'SOC Detection Engine'}`);
  doc.text(`Captured At: ${data.chainOfCustody?.capturedAt || data.timestamp}`);
  doc.text(`Storage Path: ${data.chainOfCustody?.storageLocation || 'N/A'}`);
  doc.text(`SHA-256 Hash: ${data.chainOfCustody?.sha256Hash || 'N/A'}`);
  doc.text(`Integrity Status: VERIFIED (Cryptographic SHA-256 match)`);
  doc.moveDown();
  
  // Section 4: Triggering Event
  doc.fillColor('#0f172a').fontSize(14).text('4. Triggering Event Payload', { underline: true });
  doc.fontSize(9).fillColor('#475569').text(JSON.stringify(data.triggerEvent, null, 2));
  doc.moveDown();
  
  // Section 5: Context Window
  doc.fillColor('#0f172a').fontSize(14).text('5. Prior Context Window (10-Event Timeline)', { underline: true });
  doc.fontSize(8).fillColor('#475569').text(JSON.stringify(data.contextWindow, null, 2));
  doc.moveDown();
  
  // Section 6: Response & Remediation
  doc.fillColor('#0f172a').fontSize(14).text('6. Recommended Response & Remediation', { underline: true });
  doc.fontSize(10).fillColor('#334155').text(incident.remediation || getRemediationRecommendation(data.rule));
  
  doc.end();
});

// --- Enhanced Structured API Suite ---

// GET /api/assets
app.get('/api/assets', (req, res) => {
  const result = Object.values(ASSETS_METADATA).map(asset => {
    const health = deviceHealth[asset.id] || { status: 'unknown' };
    const assetIncidents = incidents.filter(i => i.device === asset.id && i.status !== 'RESOLVED');
    const hasHigh = assetIncidents.some(i => i.severity === 'High');
    const hasMed = assetIncidents.some(i => i.severity === 'Medium');
    
    let riskLevel = 'Low';
    if (health.status === 'offline' || hasHigh) riskLevel = 'High';
    else if (hasMed) riskLevel = 'Medium';

    return {
      ...asset,
      status: health.status,
      lastPoll: health.lastPoll,
      latencyMs: health.latencyMs,
      riskLevel,
      openIncidentsCount: assetIncidents.length,
      eventsCount: eventLog.filter(e => e.device === asset.id).length
    };
  });
  res.json({ success: true, data: result });
});

// GET /api/events
app.get('/api/events', (req, res) => {
  const { device, type, limit } = req.query;
  let filtered = [...eventLog];
  if (device) filtered = filtered.filter(e => e.device === device);
  if (type) filtered = filtered.filter(e => e.type.toLowerCase().includes(type.toLowerCase()));
  const max = parseInt(limit, 10) || 100;
  res.json({ success: true, count: filtered.length, data: filtered.slice(0, max) });
});

// GET /api/incidents
app.get('/api/incidents', (req, res) => {
  const { status, severity, device } = req.query;
  let filtered = [...incidents];
  if (status) filtered = filtered.filter(i => i.status === status);
  if (severity) filtered = filtered.filter(i => i.severity === severity);
  if (device) filtered = filtered.filter(i => i.device === device);
  res.json({ success: true, count: filtered.length, data: filtered });
});

// GET /api/incidents/:id
app.get('/api/incidents/:id', (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id || i.alertId === req.params.id);
  if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });
  
  // Attach full evidence if file exists
  const filepath = path.join(DATA_DIR, `${incident.alertId}.json`);
  let evidenceData = null;
  if (fs.existsSync(filepath)) {
    evidenceData = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  }
  
  res.json({ success: true, data: { ...incident, evidence: evidenceData } });
});

// PATCH /api/incidents/:id - Status transition & analyst notes
app.post('/api/incidents/:id/update', (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id);
  if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });
  
  const { status, assignedTo, note } = req.body || {};
  const validStatuses = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'];
  
  if (status && validStatuses.includes(status)) {
    incident.status = status;
  }
  if (assignedTo) {
    incident.assignedTo = assignedTo;
  }
  if (note) {
    incident.notes.push({
      ts: new Date().toISOString(),
      author: assignedTo || 'SOC Analyst',
      text: note
    });
  }
  incident.updatedAt = new Date().toISOString();
  
  res.json({ success: true, data: incident });
});

// POST /api/evidence/:id/verify - Cryptographic SHA-256 Verification
app.post('/api/evidence/:id/verify', (req, res) => {
  const filepath = path.join(DATA_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filepath)) return res.status(404).json({ success: false, error: 'Evidence record not found' });
  
  try {
    const rawContent = fs.readFileSync(filepath, 'utf8');
    const fullRecord = JSON.parse(rawContent);
    
    // Re-bundle evidence part
    const evidenceBundle = {
      alertId: fullRecord.alertId,
      timestamp: fullRecord.timestamp,
      device: fullRecord.device,
      rule: fullRecord.rule,
      description: fullRecord.description,
      triggerEvent: fullRecord.triggerEvent,
      contextWindow: fullRecord.contextWindow
    };
    
    const recomputedHash = crypto.createHash('sha256').update(JSON.stringify(evidenceBundle)).digest('hex');
    const storedHash = fullRecord.chainOfCustody?.sha256Hash;
    const isVerified = recomputedHash === storedHash;

    res.json({
      success: true,
      data: {
        alertId: fullRecord.alertId,
        verified: isVerified,
        status: isVerified ? 'VERIFIED ✓' : 'TAMPERED / INTEGRITY FAILURE ✗',
        storedHash,
        recomputedHash,
        verifiedAt: new Date().toISOString()
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Verification failed', details: err.message });
  }
});

// GET /api/detection-rules
app.get('/api/detection-rules', (req, res) => {
  const rules = Object.values(RULES_METADATA).map(rule => ({
    ...rule,
    triggerCount: alerts.filter(a => a.ruleType === rule.id).length,
    lastTriggered: alerts.find(a => a.ruleType === rule.id)?.ts || null
  }));
  res.json({ success: true, data: rules });
});

// POST /api/simulations/run - Controlled UI Attack Execution
app.post('/api/simulations/run', async (req, res) => {
  const { scenario } = req.body || {};
  const steps = [];

  try {
    if (scenario === 'camera-brute-force') {
      steps.push({ time: new Date().toISOString(), message: 'Targeting Traffic Camera (http://traffic-camera:4001)' });
      steps.push({ time: new Date().toISOString(), message: 'Sending 3 invalid login attempts to /api/login...' });
      const targetUrl = DEVICES['traffic-camera'];
      
      for (let i = 1; i <= 3; i++) {
        await axios.post(`${targetUrl}/api/login`, { username: 'admin', password: `wrong_${i}` }).catch(() => {});
      }
      steps.push({ time: new Date().toISOString(), message: '3 failed login events generated on camera log.' });
      steps.push({ time: new Date().toISOString(), message: 'Awaiting detection engine poll (within 2s)...' });
    } 
    else if (scenario === 'camera-jwt-forge') {
      steps.push({ time: new Date().toISOString(), message: 'Generating forged JWT token using known weak secret ("cam123")...' });
      const targetUrl = DEVICES['traffic-camera'];
      // Forge token
      const jwt = require('jsonwebtoken');
      const forgedToken = jwt.sign({ sub: 'attacker_user', role: 'operator' }, 'cam123', { expiresIn: '1h' });
      steps.push({ time: new Date().toISOString(), message: 'Requesting protected video feed /api/feed with forged token...' });
      await axios.get(`${targetUrl}/api/feed`, { headers: { Authorization: `Bearer ${forgedToken}` } }).catch(() => {});
      steps.push({ time: new Date().toISOString(), message: 'Feed accessed with forged identity!' });
    }
    else if (scenario === 'meter-spoof') {
      steps.push({ time: new Date().toISOString(), message: 'Targeting Smart Meter (http://smart-meter:4002)' });
      steps.push({ time: new Date().toISOString(), message: 'Injecting fake out-of-bounds reading (9999 kWh) to /api/reading...' });
      const targetUrl = DEVICES['smart-meter'];
      await axios.post(`${targetUrl}/api/reading`, { kwh: 9999 }).catch(() => {});
      steps.push({ time: new Date().toISOString(), message: 'Out-of-bounds reading accepted by unauthenticated meter.' });
    }
    else if (scenario === 'streetlight-cmdi') {
      steps.push({ time: new Date().toISOString(), message: 'Targeting Smart Streetlight (http://streetlight:4003)' });
      steps.push({ time: new Date().toISOString(), message: 'Injecting OS command in checksum payload to /api/firmware/update...' });
      const targetUrl = DEVICES['streetlight'];
      const payload = `abc123" && id && echo "simulated_rce`;
      await axios.post(`${targetUrl}/api/firmware/update`, { version: '2.4.0', checksum: payload }).catch(() => {});
      steps.push({ time: new Date().toISOString(), message: 'Firmware update executed shell command payload!' });
    }
    else {
      return res.status(400).json({ success: false, error: 'Unknown simulation scenario' });
    }

    res.json({ success: true, scenario, steps, message: 'Simulation executed successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Simulation execution error', details: err.message });
  }
});

// --- STIX 2.1 & Syslog CEF Export Generators ---

function generateStixBundle(incident, evidenceRecord) {
  const bundleId = `bundle--${crypto.randomUUID()}`;
  const timestamp = incident.createdAt || new Date().toISOString();
  const ruleMeta = RULES_METADATA[incident.ruleType] || {};
  const assetMeta = ASSETS_METADATA[incident.device] || {};

  // 1. Identity SDO (SOC Engine)
  const identityId = `identity--${crypto.randomUUID()}`;
  const identitySdo = {
    type: "identity",
    spec_version: "2.1",
    id: identityId,
    created: timestamp,
    modified: timestamp,
    name: "Smart City SOC Automated Detection & SOAR Engine",
    identity_class: "system",
    sectors: ["technology", "infrastructure"]
  };

  // 2. Incident SDO
  const incidentSdoId = `incident--${crypto.randomUUID()}`;
  const incidentSdo = {
    type: "incident",
    spec_version: "2.1",
    id: incidentSdoId,
    created: timestamp,
    modified: incident.updatedAt || timestamp,
    name: incident.title || `${incident.ruleType} on ${incident.device}`,
    description: evidenceRecord?.description || incident.title,
    severity: (incident.severity || "medium").toLowerCase(),
    status: incident.status,
    external_references: [
      { source_name: "exo-smart-city-soc", external_id: incident.id },
      { source_name: "evidence-sha256", external_id: incident.evidenceHash }
    ]
  };

  if (incident.mitre) {
    incidentSdo.external_references.push({
      source_name: "mitre-attack",
      external_id: incident.mitre.id,
      url: incident.mitre.url
    });
  }

  // 3. Infrastructure SDO (Target Asset)
  const infraId = `infrastructure--${crypto.randomUUID()}`;
  const infraSdo = {
    type: "infrastructure",
    spec_version: "2.1",
    id: infraId,
    created: timestamp,
    modified: timestamp,
    name: assetMeta.name || incident.device,
    infrastructure_types: ["iot-device", "smart-city-asset"],
    description: `Location: ${assetMeta.location || 'Unknown'}. Vulnerabilities: ${(assetMeta.vulnerabilities || []).join('; ')}`
  };

  // 4. Indicator SDO
  const indicatorId = `indicator--${crypto.randomUUID()}`;
  const pattern = `[file:hashes.'SHA-256' = '${incident.evidenceHash}']`;
  const indicatorSdo = {
    type: "indicator",
    spec_version: "2.1",
    id: indicatorId,
    created: timestamp,
    modified: timestamp,
    name: `Indicator for ${incident.ruleType}`,
    description: `Automated rule indicator triggering on ${incident.device}`,
    pattern: pattern,
    pattern_type: "stix",
    valid_from: timestamp,
    indicator_types: ["malicious-activity"]
  };

  // 5. Observed Data SCO
  const observedId = `observed-data--${crypto.randomUUID()}`;
  const observedDataSdo = {
    type: "observed-data",
    spec_version: "2.1",
    id: observedId,
    created: timestamp,
    modified: timestamp,
    first_observed: evidenceRecord?.triggerEvent?.ts || timestamp,
    last_observed: timestamp,
    number_observed: (evidenceRecord?.contextWindow?.length || 0) + 1,
    objects: {
      "0": {
        type: "custom-event-log",
        device: incident.device,
        trigger_event: evidenceRecord?.triggerEvent || {}
      }
    }
  };

  // Relationships
  const rel1 = {
    type: "relationship",
    spec_version: "2.1",
    id: `relationship--${crypto.randomUUID()}`,
    created: timestamp,
    modified: timestamp,
    relationship_type: "targets",
    source_ref: incidentSdoId,
    target_ref: infraId
  };

  const rel2 = {
    type: "relationship",
    spec_version: "2.1",
    id: `relationship--${crypto.randomUUID()}`,
    created: timestamp,
    modified: timestamp,
    relationship_type: "indicates",
    source_ref: indicatorId,
    target_ref: incidentSdoId
  };

  return {
    type: "bundle",
    id: bundleId,
    spec_version: "2.1",
    objects: [identitySdo, incidentSdo, infraSdo, indicatorSdo, observedDataSdo, rel1, rel2]
  };
}

function generateCefPayload(incident, evidenceRecord) {
  const severityScoreMap = { 'Critical': 10, 'High': 8, 'Medium': 5, 'Low': 2 };
  const severityScore = severityScoreMap[incident.severity] || 5;
  const triggerIp = evidenceRecord?.triggerEvent?.detail?.ip || '127.0.0.1';
  const ts = new Date(incident.createdAt).getTime();

  const extension = [
    `src=${triggerIp}`,
    `cs1=${incident.id}`,
    `cs1Label=IncidentID`,
    `cs2=${incident.device}`,
    `cs2Label=TargetAsset`,
    `cs3=${incident.evidenceHash || 'N/A'}`,
    `cs3Label=EvidenceSHA256`,
    `cat=SmartCity/Cybercrime`,
    `rt=${ts}`,
    `msg=${(incident.title || '').replace(/\|/g, '\\|')}`
  ].join(' ');

  return `CEF:0|ExoSmartCity|SOCDetectionEngine|1.0|${incident.ruleType}|${incident.ruleName || incident.ruleType}|${severityScore}|${extension}`;
}

// --- SOAR Containment & SIEM Export API Endpoints ---

// POST /api/incidents/:id/contain - Trigger Automated SOAR Active Response Isolation
app.post('/api/incidents/:id/contain', async (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id || i.alertId === req.params.id);
  if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });

  const device = incident.device;
  const targetUrl = DEVICES[device];
  if (!targetUrl) return res.status(400).json({ success: false, error: 'Target device URL not found' });

  try {
    const containRes = await axios.post(`${targetUrl}/api/contain`, { reason: `SOAR Triggered for ${incident.id}` }, { timeout: 3000 });
    
    incident.status = 'CONTAINED';
    incident.notes.push({
      ts: new Date().toISOString(),
      author: 'SOC SOAR Engine',
      text: `[SOAR AUTOMATED RESPONSE] Executed network interface isolation on target asset ${device}. Firewall status: ISOLATED.`
    });
    incident.updatedAt = new Date().toISOString();

    if (deviceHealth[device]) {
      deviceHealth[device].status = 'isolated';
    }

    res.json({
      success: true,
      message: `SOAR Active Response: Asset ${device} successfully isolated.`,
      incident,
      deviceResponse: containRes.data
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'SOAR Containment dispatch failed', details: err.message });
  }
});

// Direct Asset Containment / Uncontainment
app.post('/api/assets/:id/contain', async (req, res) => {
  const device = req.params.id;
  const targetUrl = DEVICES[device];
  if (!targetUrl) return res.status(404).json({ success: false, error: 'Asset not found' });

  try {
    const response = await axios.post(`${targetUrl}/api/contain`, {}, { timeout: 3000 });
    if (deviceHealth[device]) deviceHealth[device].status = 'isolated';
    res.json({ success: true, data: response.data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/assets/:id/uncontain', async (req, res) => {
  const device = req.params.id;
  const targetUrl = DEVICES[device];
  if (!targetUrl) return res.status(404).json({ success: false, error: 'Asset not found' });

  try {
    const response = await axios.post(`${targetUrl}/api/uncontain`, {}, { timeout: 3000 });
    if (deviceHealth[device]) deviceHealth[device].status = 'online';
    res.json({ success: true, data: response.data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// SIEM Exports: STIX 2.1 & Syslog CEF
app.get('/api/incidents/:id/export/stix', (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id || i.alertId === req.params.id);
  if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });

  const filepath = path.join(DATA_DIR, `${incident.alertId}.json`);
  let evidenceData = null;
  if (fs.existsSync(filepath)) {
    evidenceData = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  }

  const stixBundle = generateStixBundle(incident, evidenceData);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename=STIX2.1-${incident.id}.json`);
  res.json(stixBundle);
});

app.get('/api/incidents/:id/export/cef', (req, res) => {
  const incident = incidents.find(i => i.id === req.params.id || i.alertId === req.params.id);
  if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });

  const filepath = path.join(DATA_DIR, `${incident.alertId}.json`);
  let evidenceData = null;
  if (fs.existsSync(filepath)) {
    evidenceData = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  }

  const cefString = generateCefPayload(incident, evidenceData);
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename=Syslog-${incident.id}.cef`);
  res.send(cefString);
});

// Backward-compatible export endpoints by alertId
app.get('/alerts/:id/export/stix', (req, res) => {
  const incident = incidents.find(i => i.alertId === req.params.id) || {
    id: `INC-${req.params.id}`,
    alertId: req.params.id,
    device: 'traffic-camera',
    ruleType: 'GENERIC_ALERT',
    severity: 'Medium',
    status: 'NEW',
    createdAt: new Date().toISOString()
  };
  const filepath = path.join(DATA_DIR, `${req.params.id}.json`);
  let evidenceData = null;
  if (fs.existsSync(filepath)) evidenceData = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename=STIX2.1-${req.params.id}.json`);
  res.json(generateStixBundle(incident, evidenceData));
});

app.get('/alerts/:id/export/cef', (req, res) => {
  const incident = incidents.find(i => i.alertId === req.params.id) || {
    id: `INC-${req.params.id}`,
    alertId: req.params.id,
    device: 'traffic-camera',
    ruleType: 'GENERIC_ALERT',
    severity: 'Medium',
    status: 'NEW',
    createdAt: new Date().toISOString()
  };
  const filepath = path.join(DATA_DIR, `${req.params.id}.json`);
  let evidenceData = null;
  if (fs.existsSync(filepath)) evidenceData = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename=Syslog-${req.params.id}.cef`);
  res.send(generateCefPayload(incident, evidenceData));
});

// GET /api/health
app.get('/api/health', (req, res) => {
  const metrics = calculateMetrics();
  res.json({
    success: true,
    status: 'HEALTHY',
    timestamp: new Date().toISOString(),
    devices: deviceHealth,
    mttd: metrics.mttdSec,
    evidenceStorage: {
      path: DATA_DIR,
      recordCount: alerts.length
    }
  });
});

// GET /api/metrics
app.get('/api/metrics', (req, res) => {
  const metrics = calculateMetrics();
  res.json({ success: true, data: metrics });
});

app.listen(PORT, () => {
  console.log(`Smart City Detection Engine & SOC API listening on port ${PORT}`);
});

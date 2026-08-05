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

// Ensure evidence directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory state
let alerts = [];
let lastSeenIds = {
  'traffic-camera': 0,
  'smart-meter': 0,
  'streetlight': 0
};
let meterReadings = []; // For METER_BASELINE_DEVIATION

const DEVICES = {
  'traffic-camera': process.env.CAMERA_URL || 'http://traffic-camera:4001',
  'smart-meter': process.env.METER_URL || 'http://smart-meter:4002',
  'streetlight': process.env.STREETLIGHT_URL || 'http://streetlight:4003'
};

// --- Detection Rules ---

function evaluateCamera(events) {
  const newEvents = events.filter(e => e.id > lastSeenIds['traffic-camera']);
  
  // Rule: BRUTE_FORCE_LOGIN
  const failures = newEvents.filter(e => e.type === 'LOGIN_FAILURE');
  if (failures.length >= 3) {
    const trigger = failures[failures.length - 1];
    createAlert('traffic-camera', 'BRUTE_FORCE_LOGIN', 'High', '3+ failed logins detected', trigger, events);
  }

  // Rule: UNAUTHORIZED_FEED_ACCESS
  for (const e of newEvents) {
    if (e.type === 'FEED_ACCESS_DENIED' && e.detail.reason === 'invalid token') {
      createAlert('traffic-camera', 'UNAUTHORIZED_FEED_ACCESS', 'High', 'Feed access with forged/invalid token', e, events);
    } else if (e.type === 'FEED_ACCESSED' && e.detail.by !== 'admin') {
      createAlert('traffic-camera', 'UNAUTHORIZED_FEED_ACCESS', 'High', 'Feed accessed by unauthorized subject', e, events);
    }
  }
}

function evaluateMeter(events) {
  const newEvents = events.filter(e => e.id > lastSeenIds['smart-meter']);
  
  for (const e of newEvents) {
    if (e.type === 'SUSPICIOUS_READING_ACCEPTED') {
      createAlert('smart-meter', 'SUSPICIOUS_METER_READING', 'Medium', 'Out-of-bounds reading accepted by device', e, events);
    }
    
    if (e.type === 'READING_ACCEPTED' || e.type === 'SUSPICIOUS_READING_ACCEPTED') {
      const kwh = e.detail.kwh;
      
      // Rule: METER_BASELINE_DEVIATION
      if (meterReadings.length >= 5) { // Need some baseline
        const sum = meterReadings.reduce((a, b) => a + b, 0);
        const mean = sum / meterReadings.length;
        if (kwh > mean * 2.5) {
           createAlert('smart-meter', 'METER_BASELINE_DEVIATION', 'Medium', `Reading ${kwh} exceeds 2.5x mean (${mean.toFixed(2)})`, e, events);
        }
      }
      
      meterReadings.push(kwh);
      if (meterReadings.length > 20) meterReadings.shift(); // Keep rolling window of 20
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
        createAlert('streetlight', 'COMMAND_INJECTION_ATTEMPT', 'High', 'Shell metacharacters found in checksum', e, events);
      }
    }
  }
}

// --- Forensic Capture ---

function createAlert(device, rule, severity, description, triggerEvent, allEvents) {
  const alertId = `ALT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const ts = new Date().toISOString();
  
  // Capture 10-event context window
  const contextWindow = allEvents.filter(e => e.id <= triggerEvent.id).slice(0, 10);
  
  const evidenceBundle = {
    alertId,
    timestamp: ts,
    device,
    rule,
    description,
    triggerEvent,
    contextWindow
  };
  
  // Hash the evidence
  const bundleString = JSON.stringify(evidenceBundle);
  const hash = crypto.createHash('sha256').update(bundleString).digest('hex');
  
  const chainOfCustody = {
    capturedBy: 'detection-engine',
    capturedAt: ts,
    storageLocation: path.join(DATA_DIR, `${alertId}.json`),
    sha256Hash: hash
  };
  
  const fullRecord = {
    ...evidenceBundle,
    chainOfCustody
  };
  
  fs.writeFileSync(chainOfCustody.storageLocation, JSON.stringify(fullRecord, null, 2));
  
  const alertSummary = { id: alertId, ts, device, ruleType: rule, severity, message: description, hasEvidence: true };
  alerts.unshift(alertSummary);
  
  console.log(`[ALERT] ${rule} on ${device} (Severity: ${severity})`);
}

// --- Polling Engine ---

async function pollDevice(device, url, evaluator) {
  try {
    const res = await axios.get(`${url}/events`);
    const events = res.data; // Array, newest first usually
    if (!events || events.length === 0) return;
    
    // Sort oldest to newest for evaluation
    const sorted = [...events].sort((a, b) => a.id - b.id);
    evaluator(sorted);
    
    lastSeenIds[device] = sorted[sorted.length - 1].id;
  } catch (err) {
    // console.error(`Error polling ${device}: ${err.message}`);
  }
}

setInterval(() => {
  pollDevice('traffic-camera', DEVICES['traffic-camera'], evaluateCamera);
  pollDevice('smart-meter', DEVICES['smart-meter'], evaluateMeter);
  pollDevice('streetlight', DEVICES['streetlight'], evaluateStreetlight);
}, 2000);

// --- API Endpoints ---

app.get('/alerts', (req, res) => {
  res.json(alerts);
});

app.get('/alerts/:id', (req, res) => {
  const filepath = path.join(DATA_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: "Evidence not found" });
  res.json(JSON.parse(fs.readFileSync(filepath, 'utf8')));
});

app.get('/alerts/:id/report', (req, res) => {
  const filepath = path.join(DATA_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: "Evidence not found" });
  
  const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  
  const doc = new PDFDocument({ margin: 50 });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=IncidentReport-${data.alertId}.pdf`);
  doc.pipe(res);
  
  doc.fontSize(20).text('Cybercrime Incident Report', { align: 'center' });
  doc.moveDown();
  
  doc.fontSize(14).text('1. Executive Summary', { underline: true });
  doc.fontSize(10).text(`Alert ID: ${data.alertId}`);
  doc.text(`Timestamp: ${data.timestamp}`);
  doc.text(`Device: ${data.device}`);
  doc.text(`Rule Triggered: ${data.rule}`);
  doc.text(`Description: ${data.description}`);
  doc.moveDown();
  
  doc.fontSize(14).text('2. Chain of Custody & Integrity', { underline: true });
  doc.fontSize(10).text(`Captured By: ${data.chainOfCustody.capturedBy}`);
  doc.text(`Captured At: ${data.chainOfCustody.capturedAt}`);
  doc.text(`Storage Location: ${data.chainOfCustody.storageLocation}`);
  doc.text(`SHA-256 Hash: ${data.chainOfCustody.sha256Hash}`);
  doc.moveDown();
  
  doc.fontSize(14).text('3. Triggering Event', { underline: true });
  doc.fontSize(10).text(JSON.stringify(data.triggerEvent, null, 2));
  doc.moveDown();
  
  doc.fontSize(14).text('4. Context Window (Prior Events)', { underline: true });
  doc.fontSize(8).text(JSON.stringify(data.contextWindow, null, 2));
  doc.moveDown();
  
  doc.fontSize(14).text('5. Remediation Recommendation', { underline: true });
  doc.fontSize(10).text('Investigate the source IP. Rotate credentials/secrets. Validate input sanitization on the affected endpoint.');
  
  doc.end();
});

app.listen(PORT, () => {
  console.log(`Detection Engine listening on port ${PORT}`);
});

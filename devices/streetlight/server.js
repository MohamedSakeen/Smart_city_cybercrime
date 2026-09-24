/**
 * MOCK DEVICE: Streetlight Controller
 * Deliberately vulnerable for an authorized academic CTF/forensics testbed.
 *
 * Baked-in vulnerability:
 *  V1 - /api/firmware/update passes a user-supplied "checksum" field into a
 *       shell command without sanitization -> OS command injection.
 *       Runs inside an isolated container with no privileges beyond it.
 */
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 4003;
const DEVICE_ID = "streetlight-14";

let state = { brightness: 80, mode: "auto" };
let events = [];
let eventCounter = 0;
function logEvent(type, detail) {
  eventCounter += 1;
  const e = { id: eventCounter, ts: new Date().toISOString(), device: DEVICE_ID, type, detail };
  events.unshift(e);
  events = events.slice(0, 200);
  console.log(`[${DEVICE_ID}]`, type, detail);
}

let isIsolated = false;

app.get("/status", (req, res) => {
  res.json({ device: DEVICE_ID, kind: "streetlight", status: isIsolated ? "isolated" : "online", isolated: isIsolated, vulnerable: true, state });
});

app.get("/events", (req, res) => res.json(events));

// SOAR Containment Controls
app.post("/api/contain", (req, res) => {
  isIsolated = true;
  logEvent("SOAR_ASSET_ISOLATED", { action: "ISOLATE", by: "SOC SOAR Engine", ip: req.ip });
  res.json({ ok: true, device: DEVICE_ID, isolated: true, message: "Asset network interface isolated by SOAR response action." });
});

app.post("/api/uncontain", (req, res) => {
  isIsolated = false;
  logEvent("SOAR_ASSET_RESTORED", { action: "UNCONTAIN", by: "SOC SOAR Engine", ip: req.ip });
  res.json({ ok: true, device: DEVICE_ID, isolated: false, message: "Asset network interface restored to online state." });
});

// Middleware for enforcing isolation
app.use((req, res, next) => {
  if (isIsolated && req.path.startsWith("/api/")) {
    logEvent("BLOCKED_BY_SOAR_FIREWALL", { path: req.path, ip: req.ip });
    return res.status(503).json({ error: "Asset is isolated by SOC SOAR active response firewall.", isolated: true });
  }
  next();
});

// Benign control endpoint
app.post("/api/brightness", (req, res) => {
  const { brightness } = req.body || {};
  state.brightness = brightness;
  logEvent("BRIGHTNESS_SET", { brightness, ip: req.ip });
  res.json({ ok: true, state });
});

// Vulnerable "firmware update" endpoint: checksum is concatenated into a
// shell command instead of being verified as a plain value. This mirrors a
// real class of bug seen in embedded device management panels.
app.post("/api/firmware/update", (req, res) => {
  const { version, checksum } = req.body || {};
  if (!version || !checksum) {
    return res.status(400).json({ error: "version and checksum required" });
  }
  const cmd = `echo "verifying firmware ${version} checksum: ${checksum}"`;
  exec(cmd, { timeout: 3000 }, (err, stdout, stderr) => {
    logEvent("FIRMWARE_UPDATE_ATTEMPT", { version, checksum, ip: req.ip });
    if (err) {
      logEvent("FIRMWARE_UPDATE_ERROR", { error: err.message });
      return res.status(500).json({ error: "verification failed" });
    }
    res.json({ ok: true, output: stdout.trim() });
  });
});

app.listen(PORT, () => console.log(`streetlight listening on ${PORT}`));

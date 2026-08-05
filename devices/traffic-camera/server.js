/**
 * MOCK DEVICE: Traffic Camera Controller
 * Deliberately vulnerable for an authorized academic CTF/forensics testbed.
 *
 * Baked-in vulnerabilities (documented, not accidental):
 *  V1 - Default hardcoded credentials on /api/login
 *  V2 - JWT signed with a weak, guessable secret -> forgeable without valid creds
 */
const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 4001;
const DEVICE_ID = "traffic-camera-01";

// V1: default creds baked into "firmware"
const DEFAULT_USER = "admin";
const DEFAULT_PASS = "admin1234";

// V2: weak secret, short + guessable, reused across "firmware versions"
const WEAK_JWT_SECRET = "cam123";

let events = []; // in-memory security-relevant event log for this device
let eventCounter = 0;
function logEvent(type, detail) {
  eventCounter += 1;
  const e = { id: eventCounter, ts: new Date().toISOString(), device: DEVICE_ID, type, detail };
  events.unshift(e);
  events = events.slice(0, 200);
  console.log(`[${DEVICE_ID}]`, type, detail);
}

app.get("/status", (req, res) => {
  res.json({ device: DEVICE_ID, kind: "traffic-camera", status: "online", vulnerable: true });
});

app.get("/events", (req, res) => res.json(events));

// Vulnerable login endpoint
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === DEFAULT_USER && password === DEFAULT_PASS) {
    const token = jwt.sign({ sub: username, role: "operator" }, WEAK_JWT_SECRET, { expiresIn: "1h" });
    logEvent("LOGIN_SUCCESS", { username, ip: req.ip });
    return res.json({ token });
  }
  logEvent("LOGIN_FAILURE", { username, ip: req.ip });
  return res.status(401).json({ error: "invalid credentials" });
});

// Protected feed endpoint - trusts JWT signed with weak secret
app.get("/api/feed", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) {
    logEvent("FEED_ACCESS_DENIED", { reason: "no token", ip: req.ip });
    return res.status(401).json({ error: "missing token" });
  }
  try {
    const payload = jwt.verify(token, WEAK_JWT_SECRET);
    logEvent("FEED_ACCESSED", { by: payload.sub, ip: req.ip });
    return res.json({
      device: DEVICE_ID,
      feed: "live_traffic_snapshot_base64_placeholder",
      intersection: "MG Road & Anna Salai",
      vehicleCount: Math.floor(Math.random() * 50)
    });
  } catch (e) {
    logEvent("FEED_ACCESS_DENIED", { reason: "invalid token", ip: req.ip });
    return res.status(403).json({ error: "invalid token" });
  }
});

app.listen(PORT, () => console.log(`traffic-camera listening on ${PORT}`));

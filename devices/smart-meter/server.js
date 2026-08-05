/**
 * MOCK DEVICE: Smart Utility Meter
 * Deliberately vulnerable for an authorized academic CTF/forensics testbed.
 *
 * Baked-in vulnerability:
 *  V1 - /api/reading accepts arbitrary readings with NO authentication and NO
 *       server-side sanity bounds -> allows sensor data spoofing / injection
 *       (e.g. reporting fake low usage to mask real consumption).
 */
const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 4002;
const DEVICE_ID = "smart-meter-07";

let readings = [
  { ts: new Date().toISOString(), kwh: 4.2, source: "device" }
];
let events = [];
let eventCounter = 0;
function logEvent(type, detail) {
  eventCounter += 1;
  const e = { id: eventCounter, ts: new Date().toISOString(), device: DEVICE_ID, type, detail };
  events.unshift(e);
  events = events.slice(0, 200);
  console.log(`[${DEVICE_ID}]`, type, detail);
}

app.get("/status", (req, res) => {
  res.json({ device: DEVICE_ID, kind: "smart-meter", status: "online", vulnerable: true });
});

app.get("/events", (req, res) => res.json(events));
app.get("/api/readings", (req, res) => res.json(readings.slice(0, 20)));

// Vulnerable: no auth, no plausibility check, no rate limit
app.post("/api/reading", (req, res) => {
  const { kwh } = req.body || {};
  if (typeof kwh !== "number") {
    return res.status(400).json({ error: "kwh must be a number" });
  }
  const reading = { ts: new Date().toISOString(), kwh, source: "external" };
  readings.unshift(reading);
  readings = readings.slice(0, 200);

  // naive heuristic just to flag it in the log, no enforcement (that's phase 3's job)
  const suspicious = kwh < 0 || kwh > 100;
  logEvent(suspicious ? "SUSPICIOUS_READING_ACCEPTED" : "READING_ACCEPTED", { kwh, ip: req.ip });

  res.status(201).json({ ok: true, reading });
});

app.listen(PORT, () => console.log(`smart-meter listening on ${PORT}`));

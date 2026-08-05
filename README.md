# Smart City Cybercrime Monitoring System

Full project for Cybercrime & Forensics: a simulated smart-city IoT network,
attacks against it, a detection engine, forensic evidence capture with
chain-of-custody, PDF incident reports, and a live dashboard tying it all
together. Entirely simulated — no physical hardware required.

## Architecture

```
devices/              Phase 1 — vulnerable mock IoT services
  traffic-camera/        :4001  default creds + weak JWT secret
  smart-meter/            :4002  unauthenticated sensor data injection
  streetlight/              :4003  OS command injection in firmware update

attacks/               Phase 2 — exploit scripts, one per vulnerability

detection-engine/      Phase 3 — rule + anomaly detection, forensic capture, PDF reports
  :4010

dashboard/              Phase 4 — live status, alerts, evidence viewer, report links
  :8080
```

### How data flows

1. Each device logs security-relevant actions to its own in-memory `/events`
   feed (logins, feed access, readings, firmware attempts), each with a
   unique incrementing ID.
2. The **detection engine** polls all three devices' `/events` every 2s,
   tracks the last-seen event ID per device, and evaluates only new events
   against its rule set (see table below).
3. On a match, it **creates an alert** and immediately builds a forensic
   evidence bundle: the triggering event + a 10-event context window from
   that device, hashed with SHA-256, plus a chain-of-custody record (who/
   what/when captured it, where it's stored). Both are persisted to
   `detection-engine/data/evidence/<alertId>.json` on your host machine
   (bind-mounted), so evidence survives container restarts.
4. `/alerts/:id/report` streams a generated PDF incident report (summary,
   triggering event, context timeline, chain of custody, recommended
   response) — this is your "SOC analyst deliverable."
5. The **dashboard** polls devices, alerts, and lets you open the raw
   evidence bundle or download the PDF report per alert.

## Detection rules implemented

| Device | Rule | Trigger | Severity |
|---|---|---|---|
| Traffic camera | `BRUTE_FORCE_LOGIN` | 3+ failed logins within 30s | High |
| Traffic camera | `UNAUTHORIZED_FEED_ACCESS` | Valid JWT, but subject isn't a known operator (catches forged tokens) | High |
| Smart meter | `SUSPICIOUS_METER_READING` | Device itself flags an out-of-bounds reading (<0 or >100 kWh) | Medium |
| Smart meter | `METER_BASELINE_DEVIATION` | New reading deviates >2.5x from the rolling mean of the last 20 readings | Medium |
| Streetlight | `COMMAND_INJECTION_ATTEMPT` | Shell metacharacters found in the firmware checksum field | High |

These are intentionally simple (this is a semester project, not a
production SIEM) — documenting this as a limitation/future-work item in
your report is expected and fine.

## Running it

Requires Docker Desktop running.

```bash
docker compose up --build
```

Then open:
- Dashboard: http://localhost:8080
- Detection engine API: http://localhost:4010/alerts
- Devices: http://localhost:4001/status, :4002/status, :4003/status

## Generating alerts

```bash
cd attacks
npm install
node attack-camera-creds.js
node attack-meter-spoof.js
node attack-streetlight-cmdi.js
```

Watch the dashboard: alerts appear within ~2s of each attack, with severity
color-coding. Click Evidence to view the raw forensic bundle + hash + chain
of custody in a modal, or Report PDF to download the generated incident
report.

## Project report mapping

This maps directly onto a typical cybercrime & forensics report structure:

- Methodology -> the rule table above + how evidence is captured/hashed
- Testbed design -> devices/ vulnerability table (see each device's server.js comments)
- Attack execution -> attacks/ scripts and their output
- Detection results -> alert list + timestamps (time-to-detect = alert ts minus attack script run time)
- Evidence integrity -> SHA-256 hash in each chain-of-custody record; recompute it from the stored JSON to demonstrate tamper-evidence
- Sample deliverable -> any generated PDF report

## Limitations / suggested future work (for your report's "future work" section)

- Detection is polling-based (2s interval), not a live packet-level IDS (Zeek/Suricata) — a real deployment would add network-layer capture alongside these application-layer events
- Rules are simple thresholds, not ML-based anomaly detection
- Evidence hashing covers the JSON bundle only, not raw network pcap (out of scope for the simulated device layer)
- No authentication on the detection engine or dashboard themselves (fine for a local demo, would need hardening for real deployment)

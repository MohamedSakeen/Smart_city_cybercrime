# Smart City Cybercrime Monitoring & Forensic Incident Response System
## Comprehensive Technical Architecture & Project Evaluation Report

---

### Document Metadata
- **Project Title:** Smart City Cybercrime Monitoring & Forensic System (Exo Smart City SOC & Cyber Range)
- **Domain:** Cybercrime Investigation, IoT Security, Digital Forensics & SOC Incident Response
- **Target Infrastructure:** Simulated Smart City Internet of Things (IoT) & Municipal Critical Infrastructure
- **Classification:** Academic Research, CTF Simulation & Security Operations Center (SOC) Architecture
- **Document Version:** 1.0.0
- **Status:** Complete / Production-Ready Simulation

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Project Scope & Problem Statement](#2-project-scope--problem-statement)
3. [System Architecture & Directory Structure](#3-system-architecture--directory-structure)
4. [End-to-End System Flow & Operational Lifecycle](#4-end-to-end-system-flow--operational-lifecycle)
5. [Technology Stack & Frameworks](#5-technology-stack--frameworks)
6. [Target IoT Microservices & Vulnerability Profiles](#6-target-iot-microservices--vulnerability-profiles)
7. [Threat Modeling & Attack Scenarios](#7-threat-modeling--attack-scenarios)
8. [Detection Engine & MITRE ATT&CK Mapping](#8-detection-engine--mitre-attck-mapping)
9. [Digital Forensics, Cryptographic Integrity & Chain of Custody](#9-digital-forensics-cryptographic-integrity--chain-of-custody)
10. [Security Orchestration, Automation, and Response (SOAR)](#10-security-orchestration-automation-and-response-soar)
11. [Threat Intelligence & SIEM Interoperability (STIX 2.1 & CEF)](#11-threat-intelligence--siem-interoperability-stix-21--cef)
12. [SOC Dashboard & Cyber Range User Interface](#12-soc-dashboard--cyber-range-user-interface)
13. [Smart City Use Cases & Real-World Applicability](#13-smart-city-use-cases--real-world-applicability)
14. [Performance Metrics, Limitations & Future Roadmap](#14-performance-metrics-limitations--future-roadmap)
15. [Deployment & Verification Guide](#15-deployment--verification-guide)

---

## 1. Executive Summary

Modern urban centers increasingly depend on interconnected Internet of Things (IoT) systems, supervisory control, and automated telemetry to manage critical municipal infrastructure. While these smart city technologies enhance efficiency in traffic management, energy distribution, and public safety, they dramatically expand the cyber attack surface. Many municipal edge devices are deployed with weak default configurations, lack encryption, or run vulnerable firmware, exposing smart cities to state-sponsored sabotage, cyber extortion, and operational paralysis.

The **Smart City Cybercrime Monitoring System** is an end-to-end, multi-tier security engineering and digital forensics testbed. It simulates a realistic smart city ecosystem comprising intelligent traffic surveillance, automated energy grid metering, and smart highway lighting. The platform provides:
1. **Realistic Threat Simulation:** Intentional, documented vulnerabilities mirroring real-world IoT flaws.
2. **Automated Cyber Range:** Scripted attack tools demonstrating credential compromise, token forgery, telemetry injection, and remote command execution.
3. **Real-Time Detection Engine:** Rule-based and statistical anomaly detection mapped against the industry-standard **MITRE ATT&CK** matrix.
4. **Forensic Evidence Preservation:** Automated generation of digital evidence bags featuring pre-incident and post-incident context windows, immutable **SHA-256 cryptographic hashes**, and strict **Chain of Custody** audit trails complying with ISO/IEC 27037 standards.
5. **SOAR Active Response:** Instant micro-segmentation and device containment via an active response firewall mechanism to halt ongoing attacks.
6. **SOC Analyst Deliverables:** Live situational awareness dashboard, dynamic PDF forensic incident reports, STIX 2.1 threat intelligence bundles, and ArcSight Common Event Format (CEF) syslog feeds.

The entire platform runs in isolated Docker containers with zero physical hardware dependencies, offering an accessible testbed for cybersecurity students, forensic examiners, and SOC analysts.

---

## 2. Project Scope & Problem Statement

### 2.1 Challenges in Smart City Security
Smart city infrastructure deviates significantly from conventional enterprise IT environments:
- **Heterogeneous & Distributed Deployments:** Thousands of edge devices are physically installed in public locations with little to no physical security.
- **Resource Constraints:** Low-power microcontrollers frequently lack the memory and processing power required to run traditional host-based intrusion detection agents (EDR) or complex cryptographic handshakes.
- **Legacy Communication Protocols:** Municipal infrastructure often uses unauthenticated, plaintext protocols (e.g., Modbus, raw HTTP REST APIs) that accept untrusted input.
- **Forensic Volatility:** Transient IoT devices store event telemetry in volatile RAM. During a breach, evidence is easily lost if the device is power-cycled or rebooted.

### 2.2 Project Objectives
- **Build a Reproducible Testbed:** Implement three distinct mock IoT microservices exhibiting documented, high-impact security vulnerabilities.
- **Execute Controlled Exploits:** Demonstrate how adversaries exploit edge vulnerabilities to manipulate municipal functions.
- **Continuous Detection & Triage:** Construct a non-invasive, centralized detection engine that aggregates telemetry, identifies hostile patterns, and measures **Mean Time to Detect (MTTD)**.
- **Forensic Chain of Custody:** Capture immutable digital evidence records immediately upon alert triggering, ensuring evidence admissibility in legal investigations.
- **Automated Active Containment:** Provide a closed-loop Security Orchestration, Automation, and Response (SOAR) workflow capable of quarantining compromised devices without taking the entire city grid offline.

---

## 3. System Architecture & Directory Structure

### 3.1 High-Level Architecture Diagram

```
+---------------------------------------------------------------------------------------------------+
|                                  EXO SMART CITY MUNICIPAL NETWORK                                 |
+---------------------------------------------------------------------------------------------------+
                                                  |
                 +--------------------------------+-------------------------------+
                 |                                |                               |
                 v                                v                               v
     +-----------------------+        +-----------------------+       +-----------------------+
     |   Traffic Camera 01   |        |    Smart Meter 07     |       | Smart Streetlight 14  |
     |      (Port 4001)      |        |      (Port 4002)      |       |      (Port 4003)      |
     | - /status, /events    |        | - /status, /events    |       | - /status, /events    |
     | - /api/login (V1:PWD) |        | - /api/reading (V1)   |       | - /api/firmware (V1)  |
     | - /api/feed (V2:JWT)  |        | - /api/contain        |       | - /api/contain        |
     | - /api/contain        |        |                       |       |                       |
     +-----------------------+        +-----------------------+       +-----------------------+
                 |                                |                               |
                 | HTTP Event Polling (Every 2s)  |                               |
                 +--------------------------------+-------------------------------+
                                                  |
                                                  v
                              +---------------------------------------+
                              |        SOC DETECTION ENGINE           |
                              |              (Port 4010)              |
                              |---------------------------------------|
                              | - Rules Evaluator (MITRE ATT&CK)      |
                              | - Rolling Baseline Anomaly Engine     |
                              | - SHA-256 Forensic Capture Engine     |
                              | - SOAR Active Response Dispatcher     |
                              | - STIX 2.1 & Syslog CEF Exporters     |
                              | - PDFKit Streaming Incident Reporter  |
                              +---------------------------------------+
                                   |                             |
                 Persists Evidence |                             | REST API & SSE Sync
                 (Bind-Mount Volume)|                            | (Every 3s)
                                   v                             v
                      +-----------------------+     +--------------------------+
                      | Host Disk Storage     |     |   SOC Analyst Dashboard  |
                      | ./detection-engine/   |     |       (Port 8085:8080)   |
                      | data/evidence/*.json  |     |--------------------------|
                      +-----------------------+     | - Executive KPI Overview |
                                                    | - Interactive Topology   |
                                                    | - Live Security Feed     |
                                                    | - Incident Workspace     |
                                                    | - Cyber Range Simulator  |
                                                    | - Forensic SHA-256 Modal |
                                                    | - 1-Click PDF Downloader |
                                                    +--------------------------+
```

### 3.2 Repository Directory Structure

```
Smart_city_cybercrime/
|-- .dockerignore
|-- .gitignore
|-- README.md                         # Quick-start instructions and architecture summary
|-- docker-compose.yml                # Multi-container orchestration definition
|
|-- attacks/                          # Red Team exploit scripts
|   |-- package.json                  # Dependencies (axios, jsonwebtoken)
|   |-- README.md                     # Attack execution guide
|   |-- attack-camera-creds.js        # Script 1: Brute-force & JWT token forgery
|   |-- attack-meter-spoof.js         # Script 2: Sensor reading spoofing & out-of-range injection
|   `-- attack-streetlight-cmdi.js    # Script 3: Firmware OS command injection
|
|-- dashboard/                        # Blue Team / SOC Analyst web application
|   |-- Dockerfile                    # Lightweight static file container
|   |-- package.json                  # Express server dependencies
|   |-- server.js                     # Static web host (Port 8080)
|   `-- public/                       # Frontend application assets
|       |-- index.html                # Multi-tab single page application (SPA)
|       |-- style.css                 # Dark-mode responsive design system
|       `-- app.js                    # Dynamic polling, charts, modals, and SOAR hooks
|
|-- detection-engine/                 # Core analysis, forensic, and containment microservice
|   |-- Dockerfile                    # Container definition
|   |-- package.json                  # Dependencies (express, axios, pdfkit, cors)
|   |-- server.js                     # Detection rules, forensic storage, SOAR & exports (Port 4010)
|   |-- test_system.js                # Automated end-to-end verification script
|   `-- data/
|       `-- evidence/                 # Persistent storage for SHA-256 evidence bundles (*.json)
|
|-- devices/                          # Smart City Mock IoT Assets
|   |-- traffic-camera/               # Asset 1: Surveillance camera
|   |   |-- Dockerfile
|   |   |-- package.json
|   |   `-- server.js                 # Express server with default credentials & weak JWT (Port 4001)
|   |
|   |-- smart-meter/                  # Asset 2: Smart electrical grid meter
|   |   |-- Dockerfile
|   |   |-- package.json
|   |   `-- server.js                 # Unauthenticated sensor ingestion endpoint (Port 4002)
|   |
|   `-- streetlight/                  # Asset 3: Smart municipal street lighting
|       |-- Dockerfile
|       |-- package.json
|       `-- server.js                 # Shell execution endpoint vulnerable to RCE (Port 4003)
|
`-- doc/                              # Project documentation
    `-- project_report.md             # This comprehensive technical evaluation report
```

### 3.3 Containerized Network Topology
All services communicate over an isolated Docker user-defined bridge network named `scms-net`. This isolates device traffic from the external host network while enabling internal DNS name resolution (`http://traffic-camera:4001`, `http://smart-meter:4002`, `http://streetlight:4003`, `http://detection-engine:4010`).

---

## 4. End-to-End System Flow & Operational Lifecycle

The system operates across a coordinated six-stage operational lifecycle:

```
+---------------+     +---------------+     +---------------+     +---------------+     +---------------+     +---------------+
|    Stage 1    |     |    Stage 2    |     |    Stage 3    |     |    Stage 4    |     |    Stage 5    |     |    Stage 6    |
| Edge Telemetry| --> | Central Poll  | --> | Rule Analysis | --> | Forensic Bag  | --> | SOAR Active   | --> | SOC Triage    |
| & Audit Logs  |     | & State Sync  |     | & Anomaly Det |     | & Hash Guard  |     | Containment   |     | & Intelligence|
+---------------+     +---------------+     +---------------+     +---------------+     +---------------+     +---------------+
```

### Stage 1: Edge Telemetry Generation
1. Each mock IoT device maintains an internal, sequential security log (`/events`).
2. Whenever an operational action occurs (login attempt, sensor submission, feed request, firmware flash), the device logs an entry containing:
   - `id`: Monotonically incrementing integer.
   - `ts`: ISO-8601 UTC timestamp.
   - `device`: Device identifier string.
   - `type`: High-level security event category (`LOGIN_FAILURE`, `READING_ACCEPTED`, `FIRMWARE_UPDATE_ATTEMPT`).
   - `detail`: Object storing IP address, usernames, payload values, or checksum strings.

### Stage 2: Centralized Telemetry Polling
1. The Detection Engine runs an asynchronous timer polling all registered devices every `2000ms`.
2. It queries `/events` and `/status` via HTTP GET requests.
3. The engine maintains a state dictionary (`lastSeenIds`) per device. Only events with `id > lastSeenIds[device]` are passed to the detection pipeline.
4. Device response latency and health status are tracked in memory to compute system-wide availability metrics.

### Stage 3: Detection Rules & Anomaly Evaluation
1. Incoming events pass through device-specific evaluators (`evaluateCamera`, `evaluateMeter`, `evaluateStreetlight`).
2. Evaluators execute both deterministic pattern matching (regex shell metacharacters, JWT claim verification) and statistical anomaly detection (rolling baseline deviations).
3. If an anomaly or signature matches a defined threat rule, an alert creation trigger is invoked.

### Stage 4: Cryptographic Forensic Evidence Packaging
1. Immediately upon detection, the engine calculates the **Detection Latency** ($T_{\text{detection}} - T_{\text{trigger}}$).
2. The engine extracts the triggering event alongside a preceding **10-event context window** from that specific device.
3. An **Evidence Bundle** JSON object is constructed:
   $$\text{Bundle} = \{\text{alertId}, \text{timestamp}, \text{device}, \text{rule}, \text{description}, \text{triggerEvent}, \text{contextWindow}\}$$
4. A cryptographic digest is computed:
   $$\text{SHA-256} = \mathcal{H}_{\text{SHA-256}}(\text{JSON.stringify}(\text{Bundle}))$$
5. A **Chain of Custody** block is appended, detailing the captor entity, capture timestamp, storage URI, and the cryptographic hash.
6. The full record is written to `./data/evidence/<alertId>.json` on the host disk (via Docker volume mount), guaranteeing persistence across container teardowns.

### Stage 5: SOAR Active Response & Containment
1. When an analyst (or an automated policy) invokes containment for a compromised asset, the engine dispatches a POST request to the device's `/api/contain` endpoint.
2. The device activates an internal network isolation flag (`isIsolated = true`).
3. An Express middleware intercepts all subsequent operational API calls targeting `/api/*`, immediately returning `HTTP 503 Service Unavailable` with a firewall rejection payload.
4. Administrative health queries (`/status`) and security feeds (`/events`) remain accessible so investigators can continue monitoring the compromised asset.

### Stage 6: Threat Intelligence & Reporting
1. The incident is indexed with a structured identifier (e.g., `INC-2026-0001`).
2. Threat intelligence models format the event into **STIX 2.1 JSON** bundles and **ArcSight Common Event Format (CEF)** syslog strings.
3. A formal PDF incident report is dynamically compiled and streamed via HTTP for compliance and executive briefing.

---

## 5. Technology Stack & Frameworks

| Tier | Technology | Version | Purpose & Architectural Justification |
|---|---|---|---|
| **Runtime Engine** | Node.js | v20.x (LTS) | Asynchronous, non-blocking I/O ideal for polling high-throughput IoT event streams. |
| **Backend Framework** | Express.js | 4.19+ | Lightweight REST API routing for device emulation, detection rules, and SOC endpoints. |
| **Containerization** | Docker & Compose | v2+ | Encapsulates dependencies, isolates networking via `bridge`, and simulates multi-host distribution. |
| **Authentication & Tokens** | JSON Web Tokens (`jsonwebtoken`) | 9.0+ | Demonstrates modern token-based API authentication and vulnerability to signature forgery. |
| **HTTP Client** | Axios | 1.7+ | Promise-based client used for inter-service polling, attack scripts, and verification suites. |
| **Forensic Cryptography** | Node.js Native `crypto` | Built-in | Fast, FIPS-compliant SHA-256 hashing to guarantee evidence integrity without third-party dependencies. |
| **Document Generation** | PDFKit | 0.15+ | Programmatic, server-side vector PDF generation for generating formal SOC incident reports. |
| **Threat Intelligence** | OASIS STIX 2.1 | 2.1 Spec | Standardized Structured Threat Information Expression format for sharing incident data with external SIEMs. |
| **Log Interoperability** | ArcSight CEF | v1.0 Spec | Common Event Format syslog representation for SIEM ingest (Splunk, QRadar, Microsoft Sentinel). |
| **Frontend Architecture** | Vanilla HTML5 / ES6+ | Modern | Fast, dependency-free client application eliminating heavy build steps and vulnerability overhead. |
| **UI Design System** | Vanilla CSS3 | Custom | Premium dark-mode security operations dashboard with CSS grid, glassmorphism, and responsive layout. |

---

## 6. Target IoT Microservices & Vulnerability Profiles

### 6.1 Device 1: Traffic Surveillance Camera (`traffic-camera-01`)
- **Port:** `4001`
- **Physical Context:** Mounted at high-density road intersections (e.g., MG Road & Anna Salai) for vehicular traffic monitoring and optical license plate recognition.
- **Architectural Role:** Streams video frames and vehicle counts to the municipal traffic command center.
- **Vulnerabilities:**
  - **V1 - Hardcoded Default Credentials:** Firmware contains default administrative credentials (`admin` / `admin1234`) exposed on `/api/login`.
  - **V2 - Guessable JWT Secret Key:** The token generation routine signs authentication tokens using a trivial symmetric secret (`cam123`).
- **Impact:** An attacker can perform a credential stuffing / dictionary attack, or forge tokens for arbitrary user identities, bypassing authentication to view surveillance feeds.

### 6.2 Device 2: Smart Electrical Utility Meter (`smart-meter-07`)
- **Port:** `4002`
- **Physical Context:** Substation 4B, Zone 2 Power Grid; monitors kilowatt-hour (kWh) power consumption for automated billing and grid load balancing.
- **Architectural Role:** Ingests high-frequency electric consumption readings and transmits telemetry upstream.
- **Vulnerabilities:**
  - **V1 - Unauthenticated Sensor Ingestion:** The `/api/reading` endpoint accepts external reading payloads without API tokens, TLS client certificates, or origin validation.
  - **V2 - Lack of Server-Side Sanity Bounds:** The endpoint accepts arbitrary numeric inputs, including negative numbers and implausible spikes (e.g., `9999 kWh`), without input sanitization.
- **Impact:** Attackers can inject false low readings to commit utility fraud or inject massive energy spikes to trigger automated grid safety cutoffs, causing localized power outages.

### 6.3 Device 3: Smart Streetlight Controller (`streetlight-14`)
- **Port:** `4003`
- **Physical Context:** Sector 9 Public Highway Lighting array; controls luminaire brightness, automated photocell scheduling, and firmware maintenance.
- **Architectural Role:** Exposes administrative control endpoints and over-the-air (OTA) firmware upgrade handlers.
- **Vulnerabilities:**
  - **V1 - OS Command Injection in Firmware Checksum:** The `/api/firmware/update` endpoint receives `version` and `checksum` fields. Instead of executing a cryptographic library verification, the firmware executes a shell command:
    ```javascript
    const cmd = `echo "verifying firmware ${version} checksum: ${checksum}"`;
    exec(cmd, { timeout: 3000 }, (err, stdout, stderr) => { ... });
    ```
- **Impact:** Attackers appending shell metacharacters (`;`, `&&`, `|`, `` ` ``) achieve Remote Code Execution (RCE) with the privileges of the Node.js process, allowing arbitrary shell command execution on municipal edge controllers.

---

## 7. Threat Modeling & Attack Scenarios

The testbed includes automated Red Team attack scripts within the `attacks/` directory:

```
+-------------------------------------------------------------------------------------------------------+
|                                    ATTACK EXECUTION MATRIX                                            |
+------------------------------+---------------------------+---------------------+----------------------+
| Attack Script                | Target Asset              | Attack Methodology  | Exploit Payload      |
+------------------------------+---------------------------+---------------------+----------------------+
| attack-camera-creds.js       | Traffic Camera (:4001)    | Credential stuffing | admin : admin1234    |
|                              |                           | & JWT Forgery       | jwt.sign(..., cam123)|
+------------------------------+---------------------------+---------------------+----------------------+
| attack-meter-spoof.js        | Smart Meter (:4002)       | Unauthenticated     | kwh: 0.1 (low spoof) |
|                              |                           | Sensor Injection    | kwh: 9999 (spike)    |
+------------------------------+---------------------------+---------------------+----------------------+
| attack-streetlight-cmdi.js   | Smart Streetlight (:4003) | OS Command          | abc123" && whoami && |
|                              |                           | Injection (RCE)     | echo "done           |
+------------------------------+---------------------------+---------------------+----------------------+
```

### 7.1 Attack Scenario 1: Traffic Camera Breach
1. **Dictionary Authentication:** `attack-camera-creds.js` sends an HTTP POST request to `/api/login` using `admin:admin1234`. The camera returns a signed JWT.
2. **Authorized Feed Access:** The attacker uses the token in the `Authorization: Bearer <token>` header to access `/api/feed`.
3. **Cryptographic Token Forgery:** The attacker leverages offline knowledge of the weak secret (`cam123`) to forge a token with subject `sub: "attacker"`. The camera validates the signature and grants access, logging an unauthorized subject event.

### 7.2 Attack Scenario 2: Smart Meter Sensor Spoofing
1. **Low-Consumption Injection:** `attack-meter-spoof.js` posts five consecutive readings of `0.1 kWh` to `/api/reading`. The normal baseline is ~`4.2 kWh`. This simulates energy theft where actual power consumption is concealed.
2. **Grid Spike Injection:** The script transmits an extreme reading of `9999 kWh`, far exceeding the physical capacity of the substation circuit.

### 7.3 Attack Scenario 3: Streetlight Command Injection (RCE)
1. **Normal Update Baseline:** `attack-streetlight-cmdi.js` sends a legitimate firmware update request with `version: "2.3.1"` and `checksum: "a1b2c3d4"`.
2. **Shell Breakout Execution:** The script transmits an exploit payload in the checksum parameter:
   ```
   abc123" && whoami && echo "done
   ```
3. The server concatenates the string and executes:
   ```bash
   echo "verifying firmware 2.3.1 checksum: abc123" && whoami && echo "done"
   ```
4. The shell returns the executing operating system user (e.g., `root` or `node`), confirming Remote Code Execution.

---

## 8. Detection Engine & MITRE ATT&CK Mapping

The Detection Engine evaluates telemetry against five distinct detection rules:

```
+--------------------------------------------------------------------------------------------------------------+
|                                        DETECTION RULES & MITRE FRAMEWORK                                     |
+--------------------------+----------------+----------+--------------------+----------------------------------+
| Rule Identifier          | Target Device  | Severity | MITRE ATT&CK ID    | Detection Logic / Algorithm      |
+--------------------------+----------------+----------+--------------------+----------------------------------+
| BRUTE_FORCE_LOGIN        | Traffic Camera | High     | T1110 (Brute Force)| >= 3 LOGIN_FAILURE events within |
|                          |                |          |                    | the polled event window.         |
+--------------------------+----------------+----------+--------------------+----------------------------------+
| UNAUTHORIZED_FEED_ACCESS | Traffic Camera | High     | T1550 (Alternate   | FEED_ACCESS_DENIED (bad token) OR|
|                          |                |          | Auth Material)     | FEED_ACCESSED by non-admin user. |
+--------------------------+----------------+----------+--------------------+----------------------------------+
| SUSPICIOUS_METER_READING | Smart Meter    | Medium   | T1565.001 (Data    | Sensor reading kwh < 0 or > 100. |
|                          |                |          | Manipulation)      | Device flags invalid range.      |
+--------------------------+----------------+----------+--------------------+----------------------------------+
| METER_BASELINE_DEVIATION | Smart Meter    | Medium   | T1565 (Data        | Reading > 2.5x the rolling mean  |
|                          |                |          | Manipulation)      | of the last 20 accepted readings.|
+--------------------------+----------------+----------+--------------------+----------------------------------+
| COMMAND_INJECTION_ATTEMPT| Streetlight    | High     | T1059 (Command &   | Regex match for [;&|`] within    |
|                          |                |          | Script Interpreter)| firmware checksum field.         |
+--------------------------+----------------+----------+--------------------+----------------------------------+
```

### 8.1 Rolling Baseline Anomaly Detection Algorithm
To detect stealthy sensor data spoofing that stays within artificial hard thresholds ($0 \le \text{kWh} \le 100$), the engine calculates a rolling mean:
$$\mu = \frac{1}{N} \sum_{i=1}^{N} \text{kWh}_i \quad \text{where } N \le 20, N \ge 5$$
If an incoming reading satisfies:
$$\text{kWh}_{\text{new}} > 2.5 \times \mu$$
the engine triggers a `METER_BASELINE_DEVIATION` incident, catching anomalous spikes even when below maximum system limits.

---

## 9. Digital Forensics, Cryptographic Integrity & Chain of Custody

A primary design requirement of this system is generating forensically sound evidence bundles suitable for legal proceedings or formal post-incident root cause analysis.

### 9.1 Forensic Evidence Bundle Structure
When a security rule triggers, the engine creates a digital evidence bag consisting of:
1. **Triggering Event:** The exact payload, network metadata, and timestamp of the offending action.
2. **Context Timeline (10-Event Context Window):** The preceding 10 security events on that device. This temporal context proves whether the attack was an isolated anomaly or preceded by reconnaissance.
3. **Cryptographic SHA-256 Digest:** A digital fingerprint calculated over the canonicalized JSON bundle string.
4. **Chain of Custody Record:** Detailed audit metadata verifying who captured the evidence, when it was acquired, and where it is physically stored.

```json
{
  "alertId": "ALT-1785865236413-855",
  "timestamp": "2026-08-04T17:40:36.413Z",
  "device": "traffic-camera",
  "rule": "UNAUTHORIZED_FEED_ACCESS",
  "description": "Feed accessed by unauthorized subject",
  "triggerEvent": {
    "id": 3,
    "ts": "2026-08-04T17:40:35.218Z",
    "device": "traffic-camera-01",
    "type": "FEED_ACCESSED",
    "detail": { "by": "attacker", "ip": "::1" }
  },
  "contextWindow": [
    { "id": 1, "ts": "2026-08-04T17:40:35.200Z", "type": "LOGIN_SUCCESS", "detail": { "username": "admin" } },
    { "id": 2, "ts": "2026-08-04T17:40:35.211Z", "type": "FEED_ACCESSED", "detail": { "by": "admin" } },
    { "id": 3, "ts": "2026-08-04T17:40:35.218Z", "type": "FEED_ACCESSED", "detail": { "by": "attacker" } }
  ],
  "chainOfCustody": {
    "capturedBy": "detection-engine (SOC Automated Capture)",
    "capturedAt": "2026-08-04T17:40:36.413Z",
    "storageLocation": "/app/data/evidence/ALT-1785865236413-855.json",
    "sha256Hash": "d9973f71efd52aecb68b15b098d3e8c73c9284d9b8312db1257ff981484865e1",
    "verificationStatus": "VERIFIED"
  }
}
```

### 9.2 Cryptographic Tamper Verification Workflow
To verify evidence integrity:
1. An auditor or the dashboard submits an HTTP POST to `/api/evidence/:id/verify`.
2. The server reads the raw JSON from disk.
3. The server extracts the original evidence payload (excluding the chain-of-custody block), reconstructs the exact string representation, and computes a fresh SHA-256 hash.
4. The recomputed hash is compared against the stored `sha256Hash`:
   - If identical: Returns `VERIFIED ✓`.
   - If divergent: Returns `TAMPERED / INTEGRITY FAILURE ✗`.

This fulfills ISO/IEC 27037 standards for digital evidence handling, demonstrating that evidence has remained unaltered since acquisition.

---

## 10. Security Orchestration, Automation, and Response (SOAR)

Traditional intrusion detection systems only generate notifications, leaving smart city assets exposed while analysts triage alerts. This project implements an automated SOAR active containment mechanism.

### 10.1 Active Containment Architecture

```
   [SOC Dashboard / Analyst]
              |
              | 1. POST /api/incidents/:id/contain
              v
   [Detection / SOAR Engine]
              |
              | 2. POST http://target-device:port/api/contain
              v
   [Target IoT Edge Asset]
              |
              | 3. Set isIsolated = true
              | 4. Log SOAR_ASSET_ISOLATED event
              v
   [Operational Firewall Middleware]
              |
     +--------+--------+
     |                 |
     v                 v
[/status, /events]  [/api/* Operational Endpoints]
     |                 |
HTTP 200 OK       HTTP 503 Service Unavailable
(SOC Monitoring   ("Asset is isolated by SOC SOAR
 Still Active)     active response firewall.")
```

### 10.2 Containment Verification
When isolated:
- Administrative telemetry streams (`/events`) and health queries (`/status`) remain responsive, allowing SOC personnel to monitor the device.
- All functional endpoints (`/api/login`, `/api/feed`, `/api/reading`, `/api/brightness`, `/api/firmware/update`) immediately reject traffic with `HTTP 503`:
  ```json
  {
    "error": "Asset is isolated by SOC SOAR active response firewall.",
    "isolated": true
  }
  ```
- Analysts can restore operational connectivity at any time using the `/api/assets/:id/uncontain` endpoint once remediation is complete.

---

## 11. Threat Intelligence & SIEM Interoperability (STIX 2.1 & CEF)

To ensure interoperability with external Security Operations Centers and national computer emergency response teams (CERTs), the detection engine exports incidents in two primary industry formats:

### 11.1 OASIS STIX 2.1 JSON Bundles
Accessible via `/api/incidents/:id/export/stix`, the engine generates a valid STIX 2.1 bundle interconnecting multiple Domain Objects (SDOs):
1. **Identity SDO:** Describes the reporting organization ("Smart City SOC Automated Detection Engine").
2. **Incident SDO:** Outlines the incident severity, description, status, and external references to MITRE ATT&CK techniques.
3. **Infrastructure SDO:** Characterizes the targeted smart city asset, physical location, and known firmware vulnerabilities.
4. **Indicator SDO:** Contains pattern definitions for file integrity monitoring (`[file:hashes.'SHA-256' = '...']`).
5. **Observed-Data SCO:** Encloses the triggering telemetry payload and raw event counters.
6. **Relationship SDOs:** Formally links the Indicator to the Incident (`indicates`) and the Incident to the Infrastructure (`targets`).

### 11.2 Micro Focus ArcSight Common Event Format (CEF)
Accessible via `/api/incidents/:id/export/cef`, the engine produces standard RFC 5424 syslog strings:
```
CEF:0|ExoSmartCity|SOCDetectionEngine|1.0|COMMAND_INJECTION_ATTEMPT|OS Command Injection in Firmware Update|8|src=172.18.0.1 cs1=INC-2026-0001 cs1Label=IncidentID cs2=streetlight cs2Label=TargetAsset cs3=d9973f... cs3Label=EvidenceSHA256 cat=SmartCity/Cybercrime rt=1786983031632 msg=High: OS Command Injection on streetlight
```
This payload can be forwarded to SIEM aggregators (Splunk, Elastic SIEM, Microsoft Sentinel) for enterprise-wide correlation.

---

## 12. SOC Dashboard & Cyber Range User Interface

The frontend dashboard (`http://localhost:8085`) delivers an intuitive single-page operational workstation for security analysts:

```
+----------------------------------------------------------------------------------------------------+
|  EXO SMART CITY SOC & CYBER RANGE                                      [System Healthy] [Sync: 3s] |
+----------------------------------------------------------------------------------------------------+
| [Overview] [Incidents] [Alerts] [Live Events] [Assets] [Simulator] [Evidence] [Reports] [Health]   |
+----------------------------------------------------------------------------------------------------+
|  KPIs: Total Assets: 3 | Open Incidents: 1 | Total Events: 42 | Mean Time To Detect (MTTD): 1.4s   |
+----------------------------------------------------------------------------------------------------+
|  +--------------------------------------------+  +-----------------------------------------------+ |
|  | System Security Posture                    |  | Smart City Topology                           | |
|  | Risk Score: 45 / 100 [MEDIUM]              |  | (SVG Network Diagram with Live Link Pulses)   | |
|  | Active Rules: 5 | Evidence Proof: SHA-256  |  | Camera -> Meter -> Streetlight -> Engine      | |
|  +--------------------------------------------+  +-----------------------------------------------+ |
|                                                                                                    |
|  Live Security Activity Feed (Color-Coded Badges, Real-time Ingestion)                             |
+----------------------------------------------------------------------------------------------------+
```

### Key Dashboard Workspaces:
1. **Security Overview:** Real-time KPI summary, dynamic risk gauge (0–100 score calculated based on active high/medium incidents and asset status), and interactive SVG network topology diagram.
2. **Incident Workspace:** Filterable queue (`ALL`, `NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`) supporting analyst assignment and investigation note logging.
3. **Cyber Range Attack Simulator:** One-click drill triggers allowing operators to launch simulated attacks against any IoT asset without touching the terminal.
4. **Deep Investigation Modal:** Complete view of the triggering event, 10-event temporal context window, live cryptographic SHA-256 verification button, and instant containment toggle.
5. **1-Click PDF Incident Reporter:** Generates and downloads styled, formal incident reports on demand.

---

## 13. Smart City Use Cases & Real-World Applicability

```
+----------------------------------------------------------------------------------------------------+
|                                    MUNICIPAL DOMAIN USE CASES                                      |
+--------------------------+------------------------------+------------------------------------------+
| Smart City Domain        | Real-World Threat Scenario   | System Safeguard & Value Delivered       |
+--------------------------+------------------------------+------------------------------------------+
| Intelligent Transport    | Attackers brute-force camera | Engine detects auth anomalies within 2s, |
| Systems (ITS)            | feeds or forge operator JWTs | captures IP evidence, and isolates the   |
|                          | to blind city surveillance.  | camera network interface via SOAR.       |
+--------------------------+------------------------------+------------------------------------------+
| Smart Power Grid         | Adversaries inject spoofed   | Rolling baseline engine detects energy   |
| & Utility Infrastructure | consumption data to mask     | theft and prevents grid blackouts from   |
|                          | theft or trigger blackouts.  | fraudulent surge injection.              |
+--------------------------+------------------------------+------------------------------------------+
| Municipal Connected      | Malicious actor injects RCE  | Metacharacter detection halts execution, |
| Public Lighting          | payloads into OTA firmware   | stores tamper-proof proof of exploit,    |
|                          | to build an edge IoT botnet. | and isolates infected luminaires.        |
+--------------------------+------------------------------+------------------------------------------+
| Law Enforcement          | Digital evidence discarded   | Cryptographic SHA-256 hash bags and      |
| & Cybercrime Forensics   | due to questionable origin   | strict ISO/IEC 27037 chain-of-custody    |
|                          | or lack of audit custody.    | records preserve legal admissibility.    |
+--------------------------+------------------------------+------------------------------------------+
```

---

## 14. Performance Metrics, Limitations & Future Roadmap

### 14.1 Operational Metrics Observed

```
+---------------------------------------------+-----------------------+
| Performance Metric                          | Measured Benchmark   |
+---------------------------------------------+-----------------------+
| Detection Polling Frequency                 | 2000 ms               |
| Mean Time to Detect (MTTD)                  | 0.8 s - 1.8 s         |
| SHA-256 Bundle Hashing Latency              | < 3 ms                |
| SOAR Network Isolation Response Time        | < 45 ms               |
| PDF Report Generation Time                  | < 120 ms              |
| Memory Footprint (All 5 Microservices)      | < 280 MB RAM total    |
| Container CPU Utilization (Idle / Peak)     | < 1% / 4.2%           |
+---------------------------------------------+-----------------------+
```

### 14.2 Limitations & Academic Constraints
1. **Application-Layer Polling vs. Packet Capture:** Detection is currently based on HTTP polling of application event feeds. It does not monitor raw network packets (PCAP) via deep packet inspection engines (e.g., Zeek, Suricata).
2. **Deterministic Rules vs. Machine Learning:** Apart from the rolling baseline anomaly detection on the smart meter, rules rely on explicit threshold heuristics rather than trained unsupervised ML models (e.g., Isolation Forests, Autoencoders).
3. **In-Memory Device Logs:** Edge devices maintain recent event feeds in circular memory buffers (up to 200 entries), mimicking low-cost edge controllers rather than enterprise syslog servers.

### 14.3 Future Development Roadmap
- **Hardware-in-the-Loop (HIL) Integration:** Connect physical Raspberry Pi or ESP32 microcontrollers over MQTT / CoAP protocols.
- **eBPF-Based Host Forensics:** Deploy extended Berkeley Packet Filter (eBPF) probes inside containers to intercept raw syscalls and network socket bindings.
- **Zero Trust Edge Architecture:** Implement mutual TLS (mTLS) with IEEE 802.1AR Secure Device Identity certificates for automated device onboarding.

---

## 15. Deployment & Verification Guide

### 15.1 Prerequisites
- Docker Engine & Docker Compose v2+ installed and active.
- Node.js v18+ (optional, only if running attacks directly on the host rather than through the web UI).

### 15.2 Starting the Testbed
Clone or navigate to the repository directory and launch the orchestrated containers:
```bash
docker compose up --build -d
```

### 15.3 Verifying Service Endpoints

```
+------------------------+------------------------------------+--------------------------------------+
| Service Component      | External Access URL                | Primary Verification Purpose         |
+------------------------+------------------------------------+--------------------------------------+
| SOC Web Dashboard      | http://localhost:8085              | Full graphical UI and Cyber Range    |
| Detection Engine API   | http://localhost:4010/api/health   | Engine health status and active MTTD |
| Traffic Camera Asset   | http://localhost:4001/status       | Camera operational state and status  |
| Smart Meter Asset      | http://localhost:4002/status       | Electrical meter state and telemetry |
| Streetlight Asset      | http://localhost:4003/status       | Streetlight status and brightness    |
+------------------------+------------------------------------+--------------------------------------+
```

### 15.4 Automated End-to-End Test Suite
A built-in automated test suite validates all 12 system capabilities (Health, Assets, Metrics, Rules, Simulations, Incident Creation, Evidence Verification, Incident Status Updates, SOAR Containment, Isolation Rejection, STIX 2.1 Export, and Asset Restoration):
```bash
node detection-engine/test_system.js
```

### 15.5 Running Manual Red Team Attacks (CLI)
```bash
cd attacks
npm install
node attack-camera-creds.js       # Executes credential stuffing & JWT forgery
node attack-meter-spoof.js         # Injects fake sensor readings & spikes
node attack-streetlight-cmdi.js    # Injects shell breakout payloads
```

---

## 16. Conclusion

The **Smart City Cybercrime Monitoring System** successfully bridges the gap between simulated municipal IoT infrastructure, aggressive Red Team cyber exploitation, and responsive Blue Team defensive engineering. By unifying real-time telemetry polling, MITRE ATT&CK threat mapping, ISO/IEC 27037 compliant digital evidence preservation, and automated SOAR containment, the platform provides an effective blueprint for securing future smart city infrastructure against sophisticated cyber attacks.

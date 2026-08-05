# Attack scripts (Phase 2)

Each script targets exactly one vulnerability baked into a Phase 1 device.
Run devices first (`docker compose up`), then from this folder:

    npm install
    node attack-camera-creds.js
    node attack-meter-spoof.js
    node attack-streetlight-cmdi.js

These are for your own local testbed only. Every action a script performs
is also written to that device's /events log, which the dashboard reads.

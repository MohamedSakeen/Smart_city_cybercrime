// Static file server for the dashboard. All device polling happens client-side.
const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, "0.0.0.0", () => console.log(`dashboard listening on ${PORT}`));

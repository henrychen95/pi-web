#!/usr/bin/env node
"use strict";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { spawn } = require("node:child_process");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const path = require("node:path");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getUnsupportedNodeVersionMessage, isNodeVersionSupported } = require("./node-version");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getNextNodeArgs } = require("./pi-web-node-args");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { wireChildProcessLifecycle } = require("./process-lifecycle");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { prepareRemoteAccess } = require("./remote-access");

if (!isNodeVersionSupported(process.versions.node)) {
  console.error(getUnsupportedNodeVersionMessage(process.versions.node));
  process.exit(1);
}

const [mode, hostname, ...unexpected] = process.argv.slice(2);
if ((mode !== "dev" && mode !== "start") || !hostname || unexpected.length > 0) {
  console.error("Usage: node bin/pi-web-script.js <dev|start> <hostname>");
  process.exit(1);
}

const pkgDir = path.join(__dirname, "..");
const nextBin = require.resolve("next/dist/bin/next", { paths: [pkgDir] });
let prepared;
try {
  prepared = prepareRemoteAccess(hostname);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
for (const notice of prepared.notices) console.warn(notice);

const child = spawn(
  process.execPath,
  getNextNodeArgs(nextBin, [mode, "-H", hostname, "-p", "30141"]),
  { cwd: pkgDir, stdio: "inherit", env: prepared.env },
);
wireChildProcessLifecycle(child);

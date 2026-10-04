"use strict";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const crypto = require("node:crypto");

const loopbackHostnames = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

function prepareRemoteAccess(
  hostname,
  sourceEnv = process.env,
  randomBytes = crypto.randomBytes,
) {
  const env = { ...sourceEnv, PI_WEB_HOSTNAME: hostname };
  const notices = [];
  const loopback = loopbackHostnames.has(String(hostname).toLowerCase());
  const trustProxy = sourceEnv.PI_WEB_TRUST_PROXY === "1";
  if (loopback && !trustProxy) {
    return { env, notices, generatedPassword: false };
  }

  let password = sourceEnv.PI_WEB_PASSWORD;
  const allowInsecure = sourceEnv.PI_WEB_ALLOW_INSECURE_LAN === "1";
  if (!loopback && !allowInsecure) {
    throw new Error(
      "Refusing non-loopback HTTP access. Bind pi-web to loopback behind a same-host HTTPS proxy, "
      + "or explicitly accept plaintext transport with PI_WEB_ALLOW_INSECURE_LAN=1.",
    );
  }

  if (allowInsecure) {
    notices.push(password
      ? `Warning: pi-web is listening on ${hostname} with password authentication over plaintext HTTP (PI_WEB_ALLOW_INSECURE_LAN=1).`
      : `Warning: pi-web is listening on ${hostname} without authentication (PI_WEB_ALLOW_INSECURE_LAN=1).`);
  }

  let generatedPassword = false;
  if (!password && trustProxy && loopback) {
    password = randomBytes(16).toString("hex");
    generatedPassword = true;
    notices.push("================================================================================");
    notices.push(`[Security Alert] pi-web trusts a same-host HTTPS proxy on loopback address "${hostname}".`);
    notices.push("[Security Alert] A temporary access password has been generated:");
    notices.push("");
    notices.push(`    Password: ${password}`);
    notices.push("");
    notices.push("Please enter this password on login, or set PI_WEB_PASSWORD in your environment.");
    notices.push("================================================================================");
  }

  if (password) env.PI_WEB_PASSWORD = password;
  return { env, notices, generatedPassword };
}

module.exports = { prepareRemoteAccess };

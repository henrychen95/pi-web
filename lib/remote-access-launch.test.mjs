import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import test from "node:test";

const require = createRequire(import.meta.url);
const { prepareRemoteAccess } = require("../bin/remote-access.js");

test("all package launch scripts use the shared guarded launcher", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.scripts.dev, "node bin/pi-web-script.js dev 127.0.0.1");
  assert.equal(pkg.scripts["dev:lan"], "node bin/pi-web-script.js dev 0.0.0.0");
  assert.equal(pkg.scripts.start, "node bin/pi-web-script.js start 127.0.0.1");
  assert.equal(pkg.scripts["start:lan"], "node bin/pi-web-script.js start 0.0.0.0");
});

test("loopback launch does not require a remote transport policy", () => {
  const result = prepareRemoteAccess("127.0.0.1", {});
  assert.equal(result.env.PI_WEB_HOSTNAME, "127.0.0.1");
  assert.equal(result.env.PI_WEB_PASSWORD, undefined);
});

test("remote launch refuses plaintext access unless explicitly allowed", () => {
  assert.throws(
    () => prepareRemoteAccess("0.0.0.0", { PI_WEB_PASSWORD: "secret" }),
    /Refusing non-loopback HTTP access/,
  );
  const result = prepareRemoteAccess("0.0.0.0", {
    PI_WEB_PASSWORD: "secret",
    PI_WEB_ALLOW_INSECURE_LAN: "1",
  });
  assert.equal(result.env.PI_WEB_PASSWORD, "secret");
  assert.match(result.notices.join("\n"), /plaintext HTTP/);
});

test("trusted HTTPS proxy mode stays on loopback and generates a password when needed", () => {
  const result = prepareRemoteAccess(
    "127.0.0.1",
    { PI_WEB_TRUST_PROXY: "1" },
    () => Buffer.from("a".repeat(32), "hex"),
  );
  assert.equal(result.env.PI_WEB_PASSWORD, "a".repeat(32));
  assert.equal(result.generatedPassword, true);
  assert.throws(
    () => prepareRemoteAccess("0.0.0.0", { PI_WEB_TRUST_PROXY: "1" }),
    /Bind pi-web to loopback/,
  );
});

import assert from "node:assert/strict";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const { isSafeModelUrl, isSafeWebPushEndpoint } = await jiti.import("./ssrf-protection.ts");

test("isSafeModelUrl blocks cloud metadata addresses", () => {
  assert.equal(isSafeModelUrl("http://169.254.169.254/latest/meta-data/").safe, false);
  assert.equal(isSafeModelUrl("http://169.254.169.253").safe, false);
  assert.equal(isSafeModelUrl("http://metadata.google.internal/computeMetadata/v1/").safe, false);
  assert.equal(isSafeModelUrl("http://instance-data/latest/meta-data/").safe, false);
});

test("isSafeModelUrl blocks private network IPs by default", () => {
  assert.equal(isSafeModelUrl("http://10.0.0.1:8080/v1").safe, false);
  assert.equal(isSafeModelUrl("http://172.16.1.1:8080/v1").safe, false);
  assert.equal(isSafeModelUrl("http://192.168.1.1:8080/v1").safe, false);
});

test("isSafeModelUrl blocks dangerous ports on loopback while allowing standard local LLMs", () => {
  // Common local LLM ports allowed
  assert.equal(isSafeModelUrl("http://127.0.0.1:11434/v1").safe, true);
  assert.equal(isSafeModelUrl("http://localhost:1234/v1").safe, true);
  assert.equal(isSafeModelUrl("http://127.0.0.1:8080/v1").safe, true);

  // Dangerous/internal ports blocked on loopback
  assert.equal(isSafeModelUrl("http://127.0.0.1:22/").safe, false);
  assert.equal(isSafeModelUrl("http://127.0.0.1:6379/").safe, false);
  assert.equal(isSafeModelUrl("http://127.0.0.1:27017/").safe, false);
  assert.equal(isSafeModelUrl("http://localhost:25/").safe, false);
});

test("isSafeModelUrl allows legitimate public LLM APIs", () => {
  assert.equal(isSafeModelUrl("https://api.openai.com/v1").safe, true);
  assert.equal(isSafeModelUrl("https://api.anthropic.com/v1").safe, true);
  assert.equal(isSafeModelUrl("https://openrouter.ai/api/v1").safe, true);
});

test("isSafeWebPushEndpoint allows legitimate push services and blocks unauthorized ones", () => {
  assert.equal(isSafeWebPushEndpoint("https://fcm.googleapis.com/fcm/send/test-sub").safe, true);
  assert.equal(isSafeWebPushEndpoint("https://updates.push.services.mozilla.com/wpush/v1/test").safe, true);
  assert.equal(isSafeWebPushEndpoint("https://web.push.apple.com/test-endpoint").safe, true);

  // Blocked
  assert.equal(isSafeWebPushEndpoint("http://fcm.googleapis.com/fcm/send").safe, false); // Not https
  assert.equal(isSafeWebPushEndpoint("https://127.0.0.1:8080/webhook").safe, false); // IP / internal
  assert.equal(isSafeWebPushEndpoint("https://malicious-attacker.com/steal").safe, false); // Unknown domain
});

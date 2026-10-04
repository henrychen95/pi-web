import assert from "node:assert/strict";
import test from "node:test";

async function loadSubject() {
  return import("./web-auth.ts");
}

function authorization(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`;
}

test("enables password authentication only for a non-empty configured password", async () => {
  const { isWebPasswordEnabled } = await loadSubject();
  assert.equal(isWebPasswordEnabled(undefined), false);
  assert.equal(isWebPasswordEnabled(""), false);
  assert.equal(isWebPasswordEnabled("secret"), true);
});

test("accepts only the fixed pi username and configured password", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  assert.equal(isValidBasicAuthorization(authorization("pi", "secret"), "secret"), true);
  assert.equal(isValidBasicAuthorization(authorization("admin", "secret"), "secret"), false);
  assert.equal(isValidBasicAuthorization(authorization("pi", "wrong"), "secret"), false);
});

test("supports UTF-8 passwords and colons in the password", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  const password = "口令:with:colons";
  assert.equal(isValidBasicAuthorization(authorization("pi", password), password), true);
});

test("rejects missing, malformed, and non-canonical authorization values", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  const valid = authorization("pi", "secret");

  assert.equal(isValidBasicAuthorization(null, "secret"), false);
  assert.equal(isValidBasicAuthorization("Bearer token", "secret"), false);
  assert.equal(isValidBasicAuthorization("Basic !!!", "secret"), false);
  assert.equal(isValidBasicAuthorization(`${valid}!`, "secret"), false);
  assert.equal(isValidBasicAuthorization(
    `Basic ${Buffer.from("missing-separator", "utf8").toString("base64")}`,
    "secret",
  ), false);
});

test("does not authenticate when password protection is disabled", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  assert.equal(isValidBasicAuthorization(authorization("pi", ""), ""), false);
  assert.equal(isValidBasicAuthorization(authorization("pi", "secret"), undefined), false);
});

test("creates signed sessions that expire and cannot be altered", async () => {
  const {
    createWebSessionToken,
    isValidWebSessionToken,
    PI_WEB_SESSION_MAX_AGE,
  } = await loadSubject();
  const now = Date.UTC(2026, 8, 7);
  const token = createWebSessionToken("secret", now, "a".repeat(32));

  assert.equal(isValidWebSessionToken(token, "secret", now), true);
  assert.equal(isValidWebSessionToken(token, "wrong", now), false);
  assert.equal(isValidWebSessionToken(`${token.slice(0, -1)}0`, "secret", now), false);
  assert.equal(isValidWebSessionToken(token, "secret", now + PI_WEB_SESSION_MAX_AGE * 1000), false);
});

test("trusts forwarded HTTPS only when proxy trust is explicit", async () => {
  const { isSecureWebRequest } = await loadSubject();
  const request = new Request("http://localhost/", { headers: { "x-forwarded-proto": "https" } });
  assert.equal(isSecureWebRequest(request, false), false);
  assert.equal(isSecureWebRequest(request, true), true);
  assert.equal(isSecureWebRequest(new Request("https://localhost/"), false), true);
});

test("remote bindings require authentication and secure transport unless explicitly waived", async () => {
  const { remoteAccessRefusal } = await loadSubject();
  const http = new Request("http://localhost/");
  const https = new Request("https://localhost/");

  assert.deepEqual(remoteAccessRefusal(http, { hostname: undefined }), {
    status: 503,
    message: "Remote HTTPS proxy mode requires a loopback Pi Web binding",
  });
  assert.equal(remoteAccessRefusal(http, { hostname: "127.0.0.1" }), null);
  assert.deepEqual(remoteAccessRefusal(http, { hostname: "0.0.0.0" }), {
    status: 503,
    message: "Remote HTTPS proxy mode requires a loopback Pi Web binding",
  });
  assert.deepEqual(remoteAccessRefusal(http, { hostname: "0.0.0.0", password: "secret" }), {
    status: 503,
    message: "Remote HTTPS proxy mode requires a loopback Pi Web binding",
  });
  assert.deepEqual(remoteAccessRefusal(https, { hostname: "0.0.0.0", password: "secret" }), {
    status: 503,
    message: "Remote HTTPS proxy mode requires a loopback Pi Web binding",
  });
  assert.equal(remoteAccessRefusal(http, { hostname: "0.0.0.0", allowInsecure: true }), null);

  const forwardedHttps = new Request("http://localhost/", { headers: { "x-forwarded-proto": "https" } });
  assert.deepEqual(remoteAccessRefusal(http, { hostname: "127.0.0.1", trustProxy: true }), {
    status: 503,
    message: "Remote access requires password authentication",
  });
  assert.deepEqual(remoteAccessRefusal(http, {
    hostname: "127.0.0.1", password: "secret", trustProxy: true,
  }), {
    status: 426,
    message: "Remote password authentication requires HTTPS",
  });
  assert.equal(remoteAccessRefusal(forwardedHttps, {
    hostname: "127.0.0.1", password: "secret", trustProxy: true,
  }), null);
});

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import { createJiti } from "jiti";

const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
const testAgentDir = await mkdtemp(join(tmpdir(), "pi-web-models-config-route-"));
process.env.PI_CODING_AGENT_DIR = testAgentDir;

const jiti = createJiti(import.meta.url, {
  alias: { "@": process.cwd() },
  interopDefault: true,
  moduleCache: false,
});
const { GET, PUT } = await jiti.import("./route.ts");
const modelsPath = join(testAgentDir, "models.json");

after(async () => {
  if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
  await rm(testAgentDir, { recursive: true, force: true });
});

function put(body) {
  return new Request("http://localhost/api/models-config", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Host: "localhost" },
    body: JSON.stringify(body),
  });
}

function get() {
  return new Request("http://localhost/api/models-config", {
    headers: { Host: "localhost" },
  });
}

test("a models.json with a syntax error is reported instead of read as empty, and a save cannot replace it", async () => {
  const original = '{ "providers": { "acme": { "models": [ } } }';
  await writeFile(modelsPath, original);

  let response = await GET(get());
  assert.equal(response.status, 422);
  assert.match((await response.json()).error, /models\.json/);

  response = await PUT(put({ providers: {} }));
  assert.equal(response.status, 409);
  assert.match((await response.json()).error, /models\.json/);
  assert.equal(await readFile(modelsPath, "utf8"), original);
});

test("a commented models.json loads with its providers", async () => {
  await writeFile(modelsPath, '{\n  // local models\n  "providers": { "acme": { "models": [{ "id": "a" },] } },\n}\n');

  const response = await GET(get());
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { providers: { acme: { models: [{ id: "a" }] } } });
});

test("provider rename envelopes preserve secrets that the browser only saw masked", async () => {
  await writeFile(modelsPath, JSON.stringify({
    providers: { oldName: { apiKey: "super-secret-key", models: [{ id: "a" }] } },
  }));

  const loaded = await GET(get());
  const masked = await loaded.json();
  assert.notEqual(masked.providers.oldName.apiKey, "super-secret-key");

  const response = await PUT(put({
    config: { providers: { newName: masked.providers.oldName } },
    providerRenames: [{ from: "oldName", to: "newName" }],
  }));
  assert.equal(response.status, 200);

  const saved = JSON.parse(await readFile(modelsPath, "utf8"));
  assert.equal(saved.providers.newName.apiKey, "super-secret-key");
  assert.equal(saved.providers.oldName, undefined);
});

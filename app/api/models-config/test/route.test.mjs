import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import { createJiti } from "jiti";

const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
const agentDir = await mkdtemp(join(tmpdir(), "pi-web-model-test-route-"));
process.env.PI_CODING_AGENT_DIR = agentDir;
const jiti = createJiti(import.meta.url, { alias: { "@": process.cwd() } });
const { POST } = await jiti.import("./route.ts");

after(async () => {
  if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  await rm(agentDir, { recursive: true, force: true });
});

test("model-level Base URL overrides cannot bypass SSRF validation", async () => {
  const response = await POST(new Request("http://localhost/api/models-config/test", {
    method: "POST",
    headers: { host: "localhost", "content-type": "application/json" },
    body: JSON.stringify({
      providerName: "custom",
      provider: { baseUrl: "https://api.example.com/v1", apiKey: "test-key" },
      model: { id: "unsafe", baseUrl: "http://169.254.169.254/latest" },
    }),
  }));
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /metadata|forbidden/i);
});

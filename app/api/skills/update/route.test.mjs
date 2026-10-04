import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import { createJiti } from "jiti";

const root = await mkdtemp(join(tmpdir(), "pi-web-skill-update-route-"));
const agentDir = join(root, "agent");
const cwd = join(root, "project");
const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
process.env.PI_CODING_AGENT_DIR = agentDir;
await mkdir(join(cwd, ".pi"), { recursive: true });
await mkdir(agentDir, { recursive: true });
await writeFile(join(cwd, ".pi", "settings.json"), JSON.stringify({ packages: [] }));

const jiti = createJiti(import.meta.url, { alias: { "@": process.cwd() } });
const { allowFileRoot } = await jiti.import("../../../../lib/file-access.ts");
const { POST } = await jiti.import("./route.ts");
allowFileRoot(cwd);

after(async () => {
  if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  await rm(root, { recursive: true, force: true });
});

function update(body) {
  return POST(new Request("http://localhost/api/skills/update", {
    method: "POST",
    headers: { host: "localhost", "content-type": "application/json" },
    body: JSON.stringify({ cwd, package: "owner/repository", ...body }),
  }));
}

test("global skill updates require explicit lifecycle-script confirmation", async () => {
  const response = await update({ scope: "global" });
  const body = await response.json();
  assert.equal(response.status, 409);
  assert.equal(body.reason, "code-execution-confirmation-required");
});

test("project skill updates require project trust", async () => {
  const response = await update({ scope: "project" });
  assert.equal(response.status, 403);
  assert.match((await response.json()).error, /must be trusted/);
});

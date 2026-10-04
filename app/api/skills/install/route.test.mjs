import assert from "node:assert/strict";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url, { alias: { "@": process.cwd() } });
const { POST } = await jiti.import("./route.ts");

test("global skill install requires explicit lifecycle-script confirmation", async () => {
  const response = await POST(new Request("http://localhost/api/skills/install", {
    method: "POST",
    headers: { host: "localhost", "content-type": "application/json" },
    body: JSON.stringify({ package: "owner/repository", scope: "global" }),
  }));
  const body = await response.json();
  assert.equal(response.status, 409);
  assert.equal(body.reason, "code-execution-confirmation-required");
});

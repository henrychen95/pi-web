import assert from "node:assert/strict";
import test from "node:test";
import { homedir } from "node:os";
import path from "node:path";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const { isRestrictedWorkspaceDirectory, isRestrictedBrowseDirectory } = await jiti.import("./path-security.ts");

test("isRestrictedWorkspaceDirectory refuses root directories", () => {
  assert.equal(isRestrictedWorkspaceDirectory("/").restricted, true);
  if (process.platform === "win32") {
    assert.equal(isRestrictedWorkspaceDirectory("C:\\").restricted, true);
    assert.equal(isRestrictedWorkspaceDirectory("c:/").restricted, true);
  }
});

test("isRestrictedWorkspaceDirectory refuses user home root", () => {
  assert.equal(isRestrictedWorkspaceDirectory(homedir()).restricted, true);
});

test("isRestrictedWorkspaceDirectory refuses sensitive dot directories", () => {
  assert.equal(isRestrictedWorkspaceDirectory(path.join(homedir(), ".ssh")).restricted, true);
  assert.equal(isRestrictedWorkspaceDirectory(path.join(homedir(), ".aws")).restricted, true);
  assert.equal(isRestrictedWorkspaceDirectory(path.join(homedir(), ".pi")).restricted, true);
});

test("isRestrictedWorkspaceDirectory refuses system directories", () => {
  if (process.platform === "win32") {
    const sysRoot = process.env.SystemRoot || "C:\\Windows";
    assert.equal(isRestrictedWorkspaceDirectory(sysRoot).restricted, true);
    assert.equal(isRestrictedWorkspaceDirectory(path.join(sysRoot, "System32")).restricted, true);
  } else {
    assert.equal(isRestrictedWorkspaceDirectory("/etc").restricted, true);
    assert.equal(isRestrictedWorkspaceDirectory("/var").restricted, true);
    assert.equal(isRestrictedWorkspaceDirectory("/usr/bin").restricted, true);
  }
});

test("isRestrictedWorkspaceDirectory accepts valid project subdirectories", () => {
  const safeProjectDir = path.join(homedir(), "projects", "my-app");
  assert.equal(isRestrictedWorkspaceDirectory(safeProjectDir).restricted, false);
});

test("isRestrictedBrowseDirectory protects sensitive directories", () => {
  assert.equal(isRestrictedBrowseDirectory(path.join(homedir(), ".ssh")).restricted, true);
  if (process.platform === "win32") {
    const sysRoot = process.env.SystemRoot || "C:\\Windows";
    assert.equal(isRestrictedBrowseDirectory(sysRoot).restricted, true);
  } else {
    assert.equal(isRestrictedBrowseDirectory("/etc").restricted, true);
  }
});

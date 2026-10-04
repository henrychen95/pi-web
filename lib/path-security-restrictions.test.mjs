import assert from "node:assert/strict";
import test from "node:test";
import { homedir, tmpdir } from "node:os";
import { access, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import path from "node:path";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const {
  isBrowseDirectoryAllowed,
  isRestrictedWorkspaceDirectory,
  isRestrictedBrowseDirectory,
} = await jiti.import("./path-security.ts");

test("isRestrictedWorkspaceDirectory refuses root directories", () => {
  assert.equal(isRestrictedWorkspaceDirectory("/").restricted, true);
  if (process.platform === "win32") {
    assert.equal(isRestrictedWorkspaceDirectory("C:\\").restricted, true);
    assert.equal(isRestrictedWorkspaceDirectory("c:/").restricted, true);
    assert.equal(isRestrictedWorkspaceDirectory("\\\\?\\C:\\").restricted, true);
  }
});

test("Windows namespace paths cannot bypass home or system restrictions", () => {
  if (process.platform !== "win32") return;
  assert.equal(isRestrictedWorkspaceDirectory(`\\\\?\\${homedir()}`).restricted, true);
  const sysRoot = process.env.SystemRoot || "C:\\Windows";
  assert.equal(isRestrictedWorkspaceDirectory(`\\\\?\\${sysRoot}`).restricted, true);
  assert.equal(isRestrictedWorkspaceDirectory("\\\\.\\C:\\Windows").restricted, true);
  assert.equal(isRestrictedWorkspaceDirectory("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1").restricted, true);
  assert.equal(isRestrictedWorkspaceDirectory("\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\").restricted, true);
  assert.equal(isRestrictedWorkspaceDirectory("\\??\\C:\\Windows").restricted, true);
  const shortProgramFiles = "C:\\PROGRA~1";
  return access(shortProgramFiles).then(() => {
    assert.equal(isRestrictedWorkspaceDirectory(shortProgramFiles).restricted, true);
  }).catch(() => {});
});

test("isRestrictedWorkspaceDirectory refuses user home root", () => {
  assert.equal(isRestrictedWorkspaceDirectory(homedir()).restricted, true);
  assert.equal(isRestrictedWorkspaceDirectory(path.dirname(homedir())).restricted, true);
});

test("isRestrictedWorkspaceDirectory resolves directory links before deciding", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "pi-web-path-restriction-"));
  const link = path.join(root, "workspace-link");
  t.after(() => rm(root, { recursive: true, force: true }));
  await symlink(homedir(), link, process.platform === "win32" ? "junction" : "dir");
  assert.equal(isRestrictedWorkspaceDirectory(link).restricted, true);
});

test("comparison roots are canonicalized before sensitive path checks", async (t) => {
  if (process.platform !== "win32") return;
  const root = await mkdtemp(path.join(tmpdir(), "pi-web-system-root-"));
  const realSystemDirectory = path.join(root, "real-system-directory");
  const systemLink = path.join(root, "system-link");
  const previousProgramData = process.env.ProgramData;
  t.after(async () => {
    if (previousProgramData === undefined) delete process.env.ProgramData;
    else process.env.ProgramData = previousProgramData;
    await rm(root, { recursive: true, force: true });
  });
  await mkdir(realSystemDirectory);
  await symlink(realSystemDirectory, systemLink, "junction");
  process.env.ProgramData = systemLink;

  assert.equal(isRestrictedWorkspaceDirectory(realSystemDirectory).restricted, true);
  assert.equal(isRestrictedBrowseDirectory(realSystemDirectory).restricted, true);
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

test("browse scope traverses to allowed roots but writes only inside a destination", () => {
  const pathApi = process.platform === "win32" ? path.win32 : path.posix;
  const base = process.platform === "win32" ? "D:\\projects" : "/srv/projects";
  const allowed = pathApi.resolve(base, "pi-web");
  const sibling = pathApi.resolve(base, "other");
  const roots = new Set([allowed]);

  assert.equal(isBrowseDirectoryAllowed(base, roots).restricted, false);
  assert.equal(isBrowseDirectoryAllowed(base, roots, { write: true }).restricted, true);
  assert.equal(isBrowseDirectoryAllowed(allowed, roots, { write: true }).restricted, false);
  assert.equal(isBrowseDirectoryAllowed(sibling, roots).restricted, true);
});

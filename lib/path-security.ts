import { realpathSync } from "fs";
import { homedir } from "os";
import path from "path";
import { isWindowsAbsolutePath } from "./paths";

/**
 * Lexical containment check. Accepts either canonical form on both sides: it
 * re-resolves through path.win32/path.posix and case-folds on Windows, so
 * separator style and drive-letter case never decide the answer.
 */
export function isPathWithinRoots(target: string, roots: Set<string>): boolean {
  for (const root of roots) {
    const useWindowsRules = isWindowsAbsolutePath(target) || isWindowsAbsolutePath(root);
    const resolver = useWindowsRules ? path.win32 : path;
    const sep = useWindowsRules ? "\\" : path.sep;
    const normalized = resolver.resolve(target);
    const normalizedRoot = resolver.resolve(root);
    const comparable = useWindowsRules ? normalized.toLowerCase() : normalized;
    const comparableRoot = useWindowsRules ? normalizedRoot.toLowerCase() : normalizedRoot;
    const rootWithSep = comparableRoot.endsWith(sep) ? comparableRoot : comparableRoot + sep;
    if (comparable === comparableRoot || comparable.startsWith(rootWithSep)) return true;
  }
  return false;
}

/** The roots after resolving symbolic links, for comparing canonical paths. */
export function resolveRealRoots(roots: Set<string>): Set<string> {
  const realRoots = new Set<string>();
  for (const root of roots) {
    try {
      realRoots.add(realpathSync(root));
    } catch {
      // Ignore stale roots derived from removed sessions or worktrees.
    }
  }
  return realRoots;
}

/**
 * Whether `target` has a `..` segment. Node's realpathSync collapses `..`
 * before it follows links, while the filesystem applies it after, so
 * `root/link/..` authorizes as `root` but opens the directory holding the
 * link's target, outside the roots (#748). A backslash separates segments only
 * in Windows paths; elsewhere it is part of a file name.
 */
export function hasParentDirectorySegment(target: string): boolean {
  const separator = process.platform === "win32" || isWindowsAbsolutePath(target) ? /[\\/]/ : "/";
  return target.split(separator).includes("..");
}

export function isExistingPathWithinRoots(target: string, roots: Set<string>): boolean {
  if (hasParentDirectorySegment(target)) return false;
  let realTarget: string;
  try {
    realTarget = realpathSync(target);
  } catch {
    return false;
  }
  return isPathWithinRoots(realTarget, resolveRealRoots(roots));
}

export interface PathRestrictionResult {
  restricted: boolean;
  reason?: string;
}

export function isRestrictedWorkspaceDirectory(target: string): PathRestrictionResult {
  if (!target) return { restricted: true, reason: "Path is required" };

  const isWindows = process.platform === "win32" || isWindowsAbsolutePath(target);
  const resolver = isWindows ? path.win32 : path.posix;
  let normalized: string;
  try {
    normalized = resolver.resolve(target);
  } catch {
    return { restricted: true, reason: "Invalid path" };
  }

  const parsed = resolver.parse(normalized);
  const cmp = isWindows ? normalized.toLowerCase() : normalized;
  const cmpRoot = isWindows ? parsed.root.toLowerCase() : parsed.root;

  // 1. Filesystem root check (/ or C:\ or \\server\share)
  if (cmp === cmpRoot || cmp === "/" || /^[a-zA-Z]:[\\/]?$/.test(normalized)) {
    return { restricted: true, reason: "Filesystem root cannot be used as a workspace" };
  }

  // 2. User home directory root check
  const home = resolver.resolve(homedir());
  const cmpHome = isWindows ? home.toLowerCase() : home;
  if (cmp === cmpHome) {
    return { restricted: true, reason: "User home directory cannot be used directly as a workspace" };
  }

  // 3. User sensitive subdirectories (~/.ssh, ~/.aws, ~/.gnupg, ~/.azure, ~/.kube, ~/.pi)
  const sensitiveHomeDirs = [".ssh", ".aws", ".gnupg", ".azure", ".kube", ".pi"];
  for (const sub of sensitiveHomeDirs) {
    const full = resolver.resolve(home, sub);
    const cmpFull = isWindows ? full.toLowerCase() : full;
    const fullWithSep = cmpFull.endsWith(resolver.sep) ? cmpFull : cmpFull + resolver.sep;
    if (cmp === cmpFull || cmp.startsWith(fullWithSep)) {
      return { restricted: true, reason: `Sensitive directory "${sub}" cannot be used as a workspace` };
    }
  }

  // 4. System directories check
  const systemDirs: string[] = [];
  if (isWindows) {
    const sysRoot = process.env.SystemRoot || process.env.WINDIR || "C:\\Windows";
    const progFiles = process.env.ProgramFiles || "C:\\Program Files";
    const progFilesX86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";
    const progData = process.env.ProgramData || "C:\\ProgramData";
    systemDirs.push(sysRoot, progFiles, progFilesX86, progData);
  } else {
    systemDirs.push("/etc", "/var", "/sys", "/proc", "/dev", "/boot", "/root", "/bin", "/sbin", "/usr");
  }

  for (const sysDir of systemDirs) {
    const resolvedSys = resolver.resolve(sysDir);
    const cmpSys = isWindows ? resolvedSys.toLowerCase() : resolvedSys;
    const sysWithSep = cmpSys.endsWith(resolver.sep) ? cmpSys : cmpSys + resolver.sep;
    if (cmp === cmpSys || cmp.startsWith(sysWithSep)) {
      return { restricted: true, reason: `System directory "${sysDir}" cannot be used as a workspace` };
    }
  }

  return { restricted: false };
}

export function isRestrictedBrowseDirectory(target: string): PathRestrictionResult {
  if (!target) return { restricted: false };

  const isWindows = process.platform === "win32" || isWindowsAbsolutePath(target);
  const resolver = isWindows ? path.win32 : path.posix;
  let normalized: string;
  try {
    normalized = resolver.resolve(target);
  } catch {
    return { restricted: true, reason: "Invalid path" };
  }

  const cmp = isWindows ? normalized.toLowerCase() : normalized;
  const home = resolver.resolve(homedir());

  // Browsing into sensitive home dirs is forbidden
  const sensitiveHomeDirs = [".ssh", ".aws", ".gnupg", ".azure", ".kube", ".pi"];
  for (const sub of sensitiveHomeDirs) {
    const full = resolver.resolve(home, sub);
    const cmpFull = isWindows ? full.toLowerCase() : full;
    const fullWithSep = cmpFull.endsWith(resolver.sep) ? cmpFull : cmpFull + resolver.sep;
    if (cmp === cmpFull || cmp.startsWith(fullWithSep)) {
      return { restricted: true, reason: `Access to sensitive directory "${sub}" is forbidden` };
    }
  }

  // Browsing into system directories is forbidden
  const systemDirs: string[] = [];
  if (isWindows) {
    const sysRoot = process.env.SystemRoot || process.env.WINDIR || "C:\\Windows";
    const progFiles = process.env.ProgramFiles || "C:\\Program Files";
    const progFilesX86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";
    const progData = process.env.ProgramData || "C:\\ProgramData";
    systemDirs.push(sysRoot, progFiles, progFilesX86, progData);
  } else {
    systemDirs.push("/etc", "/var", "/sys", "/proc", "/dev", "/boot", "/root", "/bin", "/sbin", "/usr");
  }

  for (const sysDir of systemDirs) {
    const resolvedSys = resolver.resolve(sysDir);
    const cmpSys = isWindows ? resolvedSys.toLowerCase() : resolvedSys;
    const sysWithSep = cmpSys.endsWith(resolver.sep) ? cmpSys : cmpSys + resolver.sep;
    if (cmp === cmpSys || cmp.startsWith(sysWithSep)) {
      return { restricted: true, reason: `Access to system directory "${sysDir}" is forbidden` };
    }
  }

  return { restricted: false };
}


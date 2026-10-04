import { lstatSync, realpathSync } from "fs";
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

function pathApiFor(target: string): typeof path.posix | typeof path.win32 {
  return process.platform === "win32" || isWindowsAbsolutePath(target) ? path.win32 : path.posix;
}

function normalizeWindowsNamespace(value: string): string {
  if (/^\\\\\?\\UNC\\/i.test(value)) return `\\\\${value.slice(8)}`;
  if (/^\\\\\?\\[a-zA-Z]:\\/.test(value)) return value.slice(4);
  if (
    value.startsWith("\\\\?\\")
    || value.startsWith("\\\\.\\")
    || value.startsWith("\\??\\")
  ) {
    throw new Error("Windows device paths are not allowed");
  }
  return value;
}

function comparablePath(value: string, resolver: typeof path.posix | typeof path.win32): string {
  const normalized = resolver === path.win32
    ? normalizeWindowsNamespace(resolver.resolve(value))
    : resolver.resolve(value);
  return resolver === path.win32 ? normalized.toLowerCase() : normalized;
}

function sameOrWithin(
  target: string,
  root: string,
  resolver: typeof path.posix | typeof path.win32,
): boolean {
  const comparableTarget = comparablePath(target, resolver);
  const comparableRoot = comparablePath(root, resolver);
  const rootWithSep = comparableRoot.endsWith(resolver.sep)
    ? comparableRoot
    : comparableRoot + resolver.sep;
  return comparableTarget === comparableRoot || comparableTarget.startsWith(rootWithSep);
}

/**
 * Resolve links before deciding whether an existing runtime path is sensitive.
 * Foreign path syntax is kept lexical so cross-platform unit tests can still
 * exercise Windows rules on Unix and vice versa.
 */
function canonicalRestrictionPath(
  target: string,
  resolver: typeof path.posix | typeof path.win32,
): string {
  const namespaceNormalized = resolver === path.win32 ? normalizeWindowsNamespace(target) : target;
  const normalized = resolver.resolve(namespaceNormalized);
  const nativeSyntax = process.platform === "win32"
    ? resolver === path.win32
    : resolver === path.posix;
  if (!nativeSyntax) return resolver === path.win32 ? normalizeWindowsNamespace(normalized) : normalized;
  try {
    let canonical: string;
    if (process.platform === "win32") {
      try {
        // The native implementation expands DOS 8.3 aliases, which is needed
        // before comparing a path with Program Files and other protected roots.
        canonical = realpathSync.native(normalized);
      } catch {
        // Some managed Windows environments deny the native handle query while
        // Node's regular resolver can still canonicalize the same directory.
        canonical = realpathSync(normalized);
      }
    } else {
      canonical = realpathSync(normalized);
    }
    return resolver === path.win32 ? normalizeWindowsNamespace(canonical) : canonical;
  } catch (error) {
    // An existing path whose canonical target cannot be inspected must fail
    // closed. Missing paths stay lexical so callers can validate prospective
    // child locations before creating them.
    try {
      lstatSync(normalized);
      throw error;
    } catch (lstatError) {
      if (
        typeof lstatError === "object"
        && lstatError !== null
        && "code" in lstatError
        && lstatError.code !== "ENOENT"
      ) throw error;
    }
    return resolver === path.win32 ? normalizeWindowsNamespace(normalized) : normalized;
  }
}

function systemDirectories(isWindows: boolean): string[] {
  if (isWindows) {
    return [
      process.env.SystemRoot || process.env.WINDIR || "C:\\Windows",
      process.env.ProgramFiles || "C:\\Program Files",
      process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)",
      process.env.ProgramData || "C:\\ProgramData",
    ];
  }
  return ["/etc", "/var", "/sys", "/proc", "/dev", "/boot", "/root", "/bin", "/sbin", "/usr"];
}

/** Canonicalize trusted comparison roots, retaining their lexical form only
 * when the host denies inspection. Candidate paths still fail closed. */
function canonicalComparisonRoot(
  target: string,
  resolver: typeof path.posix | typeof path.win32,
): string {
  try {
    return canonicalRestrictionPath(target, resolver);
  } catch {
    return resolver.resolve(target);
  }
}

export function isRestrictedWorkspaceDirectory(target: string): PathRestrictionResult {
  if (!target) return { restricted: true, reason: "Path is required" };

  const isWindows = process.platform === "win32" || isWindowsAbsolutePath(target);
  const resolver = isWindows ? path.win32 : path.posix;
  let normalized: string;
  try {
    normalized = canonicalRestrictionPath(target, resolver);
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
  const home = canonicalComparisonRoot(homedir(), resolver);
  if (sameOrWithin(home, normalized, resolver)) {
    return { restricted: true, reason: "A directory containing the user home cannot be used as a workspace" };
  }

  // 3. User sensitive subdirectories (~/.ssh, ~/.aws, ~/.gnupg, ~/.azure, ~/.kube, ~/.pi)
  const sensitiveHomeDirs = [".ssh", ".aws", ".gnupg", ".azure", ".kube", ".pi"];
  for (const sub of sensitiveHomeDirs) {
    const full = canonicalComparisonRoot(resolver.resolve(home, sub), resolver);
    if (sameOrWithin(normalized, full, resolver) || sameOrWithin(full, normalized, resolver)) {
      return { restricted: true, reason: `Sensitive directory "${sub}" cannot be used as a workspace` };
    }
  }

  // 4. System directories check
  for (const sysDir of systemDirectories(isWindows)) {
    const resolvedSys = canonicalComparisonRoot(sysDir, resolver);
    if (sameOrWithin(normalized, resolvedSys, resolver) || sameOrWithin(resolvedSys, normalized, resolver)) {
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
    normalized = canonicalRestrictionPath(target, resolver);
  } catch {
    return { restricted: true, reason: "Invalid path" };
  }

  const home = canonicalComparisonRoot(homedir(), resolver);

  // Browsing into sensitive home dirs is forbidden
  const sensitiveHomeDirs = [".ssh", ".aws", ".gnupg", ".azure", ".kube", ".pi"];
  for (const sub of sensitiveHomeDirs) {
    const full = canonicalComparisonRoot(resolver.resolve(home, sub), resolver);
    if (sameOrWithin(normalized, full, resolver)) {
      return { restricted: true, reason: `Access to sensitive directory "${sub}" is forbidden` };
    }
  }

  // Browsing into system directories is forbidden
  for (const sysDir of systemDirectories(isWindows)) {
    const resolvedSys = canonicalComparisonRoot(sysDir, resolver);
    if (sameOrWithin(normalized, resolvedSys, resolver)) {
      return { restricted: true, reason: `Access to system directory "${sysDir}" is forbidden` };
    }
  }

  return { restricted: false };
}

/**
 * The directory picker may browse inside the home folder and existing allowed
 * roots. It may also traverse ancestors needed to reach one of those places,
 * but writes are limited to the places themselves.
 */
export function isBrowseDirectoryAllowed(
  target: string,
  allowedRoots: Set<string>,
  options: { write?: boolean } = {},
): PathRestrictionResult {
  const restricted = isRestrictedBrowseDirectory(target);
  if (restricted.restricted) return restricted;

  const resolver = pathApiFor(target);
  let canonicalTarget: string;
  try {
    canonicalTarget = canonicalRestrictionPath(target, resolver);
  } catch {
    return { restricted: true, reason: "Invalid path" };
  }

  const destinations: string[] = [];
  for (const entry of [homedir(), ...allowedRoots]) {
    try {
      const canonical = canonicalRestrictionPath(entry, pathApiFor(entry));
      if (pathApiFor(canonical) === resolver) destinations.push(canonical);
    } catch {
      // Ignore stale or inaccessible roots instead of widening browse scope.
    }
  }

  if (destinations.some((destination) => sameOrWithin(canonicalTarget, destination, resolver))) {
    return { restricted: false };
  }
  if (!options.write && destinations.some((destination) => sameOrWithin(destination, canonicalTarget, resolver))) {
    return { restricted: false };
  }
  return { restricted: true, reason: "Directory is outside the browsable workspace scope" };
}

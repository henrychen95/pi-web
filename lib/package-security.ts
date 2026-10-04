/**
 * Security validation helpers for external package and skill installations.
 */

const DANGEROUS_CHAR_REGEX = /[\s;`$|&<>\\"']/;

/**
 * Validates a skill package name / URL passed to `npx skills add`.
 * Rejects leading dashes, shell metacharacters, and malformed inputs.
 */
export function isValidSkillPackageName(pkg: string): boolean {
  if (!pkg || typeof pkg !== "string") return false;
  const trimmed = pkg.trim();
  if (!trimmed || trimmed.startsWith("-")) return false;
  if (DANGEROUS_CHAR_REGEX.test(trimmed)) return false;

  // 1. npm package: [@scope/]name[@version]
  const npmPattern = /^(@[a-zA-Z0-9~][a-zA-Z0-9_.~-]*\/)?[a-zA-Z0-9~][a-zA-Z0-9_.~-]*(@[a-zA-Z0-9^~>=<._+-]+)?$/;
  // 2. github repo shorthand: [github:|gh:]owner/repo[#ref]
  const gitPattern = /^(github:|gh:)?[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(#.+)?$/;
  // 3. https URL
  const httpsPattern = /^https:\/\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.~#%+?=&/-]+$/;

  return npmPattern.test(trimmed) || gitPattern.test(trimmed) || httpsPattern.test(trimmed);
}

/**
 * Validates an extension / plugin source passed to plugin manager.
 */
export function isValidPluginSource(source: string): boolean {
  if (!source || typeof source !== "string") return false;
  const trimmed = source.trim();
  if (!trimmed || trimmed.startsWith("-")) return false;
  if (DANGEROUS_CHAR_REGEX.test(trimmed)) return false;

  // 1. npm package pattern
  const npmPattern = /^(@[a-zA-Z0-9~][a-zA-Z0-9_.~-]*\/)?[a-zA-Z0-9~][a-zA-Z0-9_.~-]*(@[a-zA-Z0-9^~>=<._+-]+)?$/;
  // 2. git repo pattern
  const gitPattern = /^(github:|gh:)?[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(#.+)?$/;
  // 3. https or git URL
  const urlPattern = /^(https|git):\/\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.~#%+?=&/-]+$/;
  // 4. relative or local path
  const localPattern = /^(\.{1,2}[\\/]|[a-zA-Z]:[\\/]|(?!\/)[a-zA-Z0-9_.-]+[\\/])[a-zA-Z0-9_.~@/\\-]+$/;

  return npmPattern.test(trimmed) || gitPattern.test(trimmed) || urlPattern.test(trimmed) || localPattern.test(trimmed);
}

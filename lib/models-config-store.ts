import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { writePrivateFileAtomicSync } from "./atomic-file";
import { stripJsonComments } from "./jsonc";
import { invalidateModelsCache } from "./models-cache";

const MODEL_COST_KEYS = ["input", "output", "cacheRead", "cacheWrite"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeModelCost(value: unknown): Record<string, unknown> | undefined {
  if (!isRecord(value)) return undefined;
  const providedKeys = MODEL_COST_KEYS.filter((key) => value[key] !== undefined);
  if (providedKeys.length === 0) return undefined;
  if (providedKeys.some((key) => (
    typeof value[key] !== "number" || !Number.isFinite(value[key])
  ))) return undefined;

  return Object.fromEntries([
    ...Object.entries(value),
    ...MODEL_COST_KEYS.map((key) => [key, value[key] ?? 0]),
  ]);
}

/** Complete partial cost groups with zero; omit a cost group only when it is empty. */
export function normalizeModelsConfigCosts(
  data: Record<string, unknown>,
): Record<string, unknown> {
  const normalized = structuredClone(data);
  if (!isRecord(normalized.providers)) return normalized;

  for (const provider of Object.values(normalized.providers)) {
    if (!isRecord(provider) || !Array.isArray(provider.models)) continue;
    for (const model of provider.models) {
      if (!isRecord(model) || !("cost" in model)) continue;
      const cost = normalizeModelCost(model.cost);
      if (cost) model.cost = cost;
      else delete model.cost;
    }
  }
  return normalized;
}

function sanitizeModelsConfig(data: Record<string, unknown>): Record<string, unknown> {
  if (!isRecord(data.providers)) return data;

  const providers = Object.fromEntries(Object.entries(data.providers).map(([providerId, provider]) => {
    if (!isRecord(provider) || !Array.isArray(provider.models)) return [providerId, provider];
    const models = provider.models.filter((model) => (
      !isRecord(model) || typeof model.id !== "string" || model.id.trim().length > 0
    ));
    return [providerId, { ...provider, models }];
  }));

  return { ...data, providers };
}

export function getModelsConfigPath(): string {
  return join(getAgentDir(), "models.json");
}

/** models.json exists but its contents cannot be used, so it must not be replaced. */
export class ModelsConfigReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ModelsConfigReadError";
  }
}

/**
 * Reads models.json with the same leniency as pi's loader (BOM, `//` comments,
 * trailing commas). `stripJsonComments` also drops block comments, which pi
 * rejects, and returns pi's own result for every file pi accepts. A file pi
 * accepts must never read as empty here: the panel saves its whole draft, so
 * an empty read would delete every provider on the next save. Unusable
 * contents throw instead.
 */
export function readModelsConfig(
  modelsPath = getModelsConfigPath(),
): Record<string, unknown> {
  if (!existsSync(modelsPath)) return { providers: {} };
  let parsed: unknown;
  try {
    const content = readFileSync(modelsPath, "utf8").replace(/^\uFEFF/, "");
    if (!content.trim()) return { providers: {} };
    parsed = JSON.parse(stripJsonComments(content));
  } catch (error) {
    throw new ModelsConfigReadError(
      `Failed to read ${modelsPath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!isRecord(parsed)) {
    throw new ModelsConfigReadError(`Failed to read ${modelsPath}: expected a JSON object`);
  }
  return parsed;
}

export const SECRET_MASK_CHARS = "••••";

export function isMaskedSecret(value: unknown): boolean {
  return typeof value === "string" && value.includes(SECRET_MASK_CHARS);
}

export function maskSecretValue(value: string): string {
  if (!value || typeof value !== "string") return value;
  if (value.startsWith("!") || /^[A-Z0-9_]+$/.test(value)) return value;
  if (value.length > 8) {
    return `${value.slice(0, 4)}${SECRET_MASK_CHARS}${value.slice(-4)}`;
  }
  return `${SECRET_MASK_CHARS}${SECRET_MASK_CHARS}`;
}

export function maskModelsConfig(data: Record<string, unknown>): Record<string, unknown> {
  const cloned = structuredClone(data);
  if (!isRecord(cloned.providers)) return cloned;

  for (const provider of Object.values(cloned.providers)) {
    if (!isRecord(provider)) continue;
    if (typeof provider.apiKey === "string") {
      provider.apiKey = maskSecretValue(provider.apiKey);
    }
    if (isRecord(provider.headers)) {
      for (const [headerKey, headerVal] of Object.entries(provider.headers)) {
        const lowerKey = headerKey.toLowerCase();
        if ((lowerKey.includes("auth") || lowerKey.includes("key") || lowerKey.includes("token")) && typeof headerVal === "string") {
          if (headerVal.toLowerCase().startsWith("bearer ")) {
            provider.headers[headerKey] = `Bearer ${maskSecretValue(headerVal.slice(7))}`;
          } else {
            provider.headers[headerKey] = maskSecretValue(headerVal);
          }
        }
      }
    }
  }

  return cloned;
}

export function mergeModelsConfigSecrets(
  incoming: Record<string, unknown>,
  existing: Record<string, unknown>,
): Record<string, unknown> {
  const result = structuredClone(incoming);
  if (!isRecord(result.providers) || !isRecord(existing.providers)) return result;

  for (const [providerId, incomingProvider] of Object.entries(result.providers)) {
    if (!isRecord(incomingProvider)) continue;
    const existingProvider = existing.providers[providerId];
    if (!isRecord(existingProvider)) continue;

    if (isMaskedSecret(incomingProvider.apiKey) && typeof existingProvider.apiKey === "string") {
      incomingProvider.apiKey = existingProvider.apiKey;
    }

    if (isRecord(incomingProvider.headers) && isRecord(existingProvider.headers)) {
      for (const [key, val] of Object.entries(incomingProvider.headers)) {
        if (isMaskedSecret(val) && typeof existingProvider.headers[key] === "string") {
          incomingProvider.headers[key] = existingProvider.headers[key];
        }
      }
    }
  }

  return result;
}

export function writeModelsConfig(
  data: Record<string, unknown>,
  modelsPath = getModelsConfigPath(),
): void {
  // Refuse to replace a file this panel could not read: the draft being saved
  // was not built from it, so writing would silently discard its contents.
  let existing: Record<string, unknown> = { providers: {} };
  try {
    existing = readModelsConfig(modelsPath);
  } catch {
    // If reading throws ModelsConfigReadError, let it throw unless file doesn't exist
    if (existsSync(modelsPath)) throw new ModelsConfigReadError(`Cannot overwrite unreadable models config: ${modelsPath}`);
  }

  const withSecretsMerged = mergeModelsConfigSecrets(data, existing);
  const dir = dirname(modelsPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const normalized = normalizeModelsConfigCosts(sanitizeModelsConfig(withSecretsMerged));
  writePrivateFileAtomicSync(modelsPath, JSON.stringify(normalized, null, 2));
  invalidateModelsCache();
}


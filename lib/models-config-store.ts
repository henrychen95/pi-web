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
  if (/^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})$/.test(value)) return value;
  if (value.startsWith("!")) return `${SECRET_MASK_CHARS}${SECRET_MASK_CHARS}`;
  if (value.length > 8) {
    return `${value.slice(0, 4)}${SECRET_MASK_CHARS}${value.slice(-4)}`;
  }
  return `${SECRET_MASK_CHARS}${SECRET_MASK_CHARS}`;
}

function maskHeaderRecord(value: unknown): void {
  if (!isRecord(value)) return;
  for (const [key, headerValue] of Object.entries(value)) {
    if (typeof headerValue === "string") value[key] = maskSecretValue(headerValue);
  }
}

function forEachModelConfig(provider: Record<string, unknown>, visit: (model: Record<string, unknown>) => void): void {
  if (Array.isArray(provider.models)) {
    for (const model of provider.models) {
      if (isRecord(model)) visit(model);
    }
  }
  if (isRecord(provider.modelOverrides)) {
    for (const model of Object.values(provider.modelOverrides)) {
      if (isRecord(model)) visit(model);
    }
  }
}

export function maskModelsConfig(data: Record<string, unknown>): Record<string, unknown> {
  const cloned = structuredClone(data);
  if (!isRecord(cloned.providers)) return cloned;

  for (const provider of Object.values(cloned.providers)) {
    if (!isRecord(provider)) continue;
    if (typeof provider.apiKey === "string") {
      provider.apiKey = maskSecretValue(provider.apiKey);
    }
    maskHeaderRecord(provider.headers);
    forEachModelConfig(provider, (model) => maskHeaderRecord(model.headers));
  }

  return cloned;
}

function mergeHeaderSecrets(incoming: unknown, existing: unknown): void {
  if (!isRecord(incoming) || !isRecord(existing)) return;
  for (const [key, value] of Object.entries(incoming)) {
    if (isMaskedSecret(value) && typeof existing[key] === "string") incoming[key] = existing[key];
  }
}

function mergeModelConfigSecrets(
  incomingProvider: Record<string, unknown>,
  existingProvider: Record<string, unknown>,
): void {
  if (Array.isArray(incomingProvider.models) && Array.isArray(existingProvider.models)) {
    for (let index = 0; index < incomingProvider.models.length; index += 1) {
      const incomingModel = incomingProvider.models[index];
      if (!isRecord(incomingModel)) continue;
      const modelId = typeof incomingModel.id === "string" ? incomingModel.id : undefined;
      const existingById = modelId
        ? existingProvider.models.find((candidate) => isRecord(candidate) && candidate.id === modelId)
        : undefined;
      // A model rename keeps its row position in the editor. Fall back to that
      // position so an unchanged masked header is not written as mask glyphs.
      const existingModel = existingById ?? existingProvider.models[index];
      if (isRecord(existingModel)) mergeHeaderSecrets(incomingModel.headers, existingModel.headers);
    }
  }
  if (isRecord(incomingProvider.modelOverrides) && isRecord(existingProvider.modelOverrides)) {
    for (const [modelId, incomingModel] of Object.entries(incomingProvider.modelOverrides)) {
      const existingModel = existingProvider.modelOverrides[modelId];
      if (isRecord(incomingModel) && isRecord(existingModel)) {
        mergeHeaderSecrets(incomingModel.headers, existingModel.headers);
      }
    }
  }
}

export function mergeModelsConfigSecrets(
  incoming: Record<string, unknown>,
  existing: Record<string, unknown>,
  providerRenames: ReadonlyArray<{ from: string; to: string }> = [],
): Record<string, unknown> {
  const result = structuredClone(incoming);
  if (!isRecord(result.providers) || !isRecord(existing.providers)) return result;

  for (const [providerId, incomingProvider] of Object.entries(result.providers)) {
    if (!isRecord(incomingProvider)) continue;
    const sourceProviderId = providerRenames.find((rename) => rename.to === providerId)?.from ?? providerId;
    const existingProvider = existing.providers[sourceProviderId];
    if (!isRecord(existingProvider)) continue;

    if (isMaskedSecret(incomingProvider.apiKey) && typeof existingProvider.apiKey === "string") {
      incomingProvider.apiKey = existingProvider.apiKey;
    }

    mergeHeaderSecrets(incomingProvider.headers, existingProvider.headers);
    mergeModelConfigSecrets(incomingProvider, existingProvider);
  }

  return result;
}

export function restoreModelsConfigRequestSecrets({
  providerName,
  sourceProviderName = providerName,
  provider,
  model,
  sourceModelId,
}: {
  providerName: string;
  sourceProviderName?: string;
  provider: Record<string, unknown>;
  model?: Record<string, unknown>;
  sourceModelId?: string;
}, existing = readModelsConfig()): { provider: Record<string, unknown>; model?: Record<string, unknown> } {
  const merged = mergeModelsConfigSecrets(
    { providers: { [providerName]: provider } },
    existing,
    sourceProviderName === providerName ? [] : [{ from: sourceProviderName, to: providerName }],
  );
  const mergedProvider = isRecord(merged.providers) && isRecord(merged.providers[providerName])
    ? merged.providers[providerName]
    : structuredClone(provider);
  if (!model) return { provider: mergedProvider };

  const restoredModel = structuredClone(model);
  const existingProvider = isRecord(existing.providers) ? existing.providers[sourceProviderName] : undefined;
  if (isRecord(existingProvider) && Array.isArray(existingProvider.models)) {
    const currentModelId = typeof model.id === "string" ? model.id : undefined;
    const existingModel = existingProvider.models.find((candidate) => isRecord(candidate) && (
      (sourceModelId && candidate.id === sourceModelId)
      || (!sourceModelId && currentModelId && candidate.id === currentModelId)
    ));
    if (isRecord(existingModel)) mergeHeaderSecrets(restoredModel.headers, existingModel.headers);
  }
  return { provider: mergedProvider, model: restoredModel };
}

export function writeModelsConfig(
  data: Record<string, unknown>,
  modelsPath = getModelsConfigPath(),
  providerRenames: ReadonlyArray<{ from: string; to: string }> = [],
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

  const withSecretsMerged = mergeModelsConfigSecrets(data, existing, providerRenames);
  const dir = dirname(modelsPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const normalized = normalizeModelsConfigCosts(sanitizeModelsConfig(withSecretsMerged));
  writePrivateFileAtomicSync(modelsPath, JSON.stringify(normalized, null, 2));
  invalidateModelsCache();
}

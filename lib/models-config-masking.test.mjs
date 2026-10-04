import assert from "node:assert/strict";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const {
  maskModelsConfig,
  mergeModelsConfigSecrets,
  isMaskedSecret,
} = await jiti.import("./models-config-store.ts");

test("maskModelsConfig masks literal API keys and authorization headers", () => {
  const config = {
    providers: {
      custom: {
        baseUrl: "https://api.custom.ai/v1",
        apiKey: "sk-proj-1234567890abcdef",
        headers: {
          Authorization: "Bearer sec-secret-token-1234",
          "Custom-Header": "regular-value",
        },
      },
      envRef: {
        apiKey: "OPENAI_API_KEY",
      },
      commandRef: {
        apiKey: "!1password get token",
      },
    },
  };

  const masked = maskModelsConfig(config);

  // Literal key should be masked
  assert.equal(isMaskedSecret(masked.providers.custom.apiKey), true);
  assert.equal(masked.providers.custom.apiKey.includes("1234567890"), false);

  // Authorization header should be masked
  assert.equal(isMaskedSecret(masked.providers.custom.headers.Authorization), true);
  assert.equal(masked.providers.custom.headers.Authorization.includes("sec-secret-token"), false);

  // Non-sensitive header preserved
  assert.equal(masked.providers.custom.headers["Custom-Header"], "regular-value");

  // Env var references and !commands are preserved unchanged
  assert.equal(masked.providers.envRef.apiKey, "OPENAI_API_KEY");
  assert.equal(masked.providers.commandRef.apiKey, "!1password get token");
});

test("mergeModelsConfigSecrets restores real secrets when client sends back masked values", () => {
  const existing = {
    providers: {
      custom: {
        apiKey: "sk-real-secret-key-9999",
        headers: {
          Authorization: "Bearer real-token-8888",
        },
      },
    },
  };

  const incomingMasked = {
    providers: {
      custom: {
        baseUrl: "https://api.custom.ai/v2",
        apiKey: "sk-r••••9999",
        headers: {
          Authorization: "Bearer ••••••••",
        },
      },
    },
  };

  const merged = mergeModelsConfigSecrets(incomingMasked, existing);
  assert.equal(merged.providers.custom.apiKey, "sk-real-secret-key-9999");
  assert.equal(merged.providers.custom.headers.Authorization, "Bearer real-token-8888");
  assert.equal(merged.providers.custom.baseUrl, "https://api.custom.ai/v2");
});

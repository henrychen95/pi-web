import assert from "node:assert/strict";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const {
  maskModelsConfig,
  mergeModelsConfigSecrets,
  isMaskedSecret,
  restoreModelsConfigRequestSecrets,
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
        models: [{ id: "nested", headers: { "X-Model-Secret": "model-secret-value" } }],
        modelOverrides: {
          nested: { headers: { "X-Override": "override-secret-value" } },
        },
      },
      envRef: {
        apiKey: "$OPENAI_API_KEY",
      },
      uppercaseLiteral: {
        apiKey: "UPPERCASELITERALSECRET",
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

  // Header names are user-controlled, so every literal header value is masked.
  assert.equal(isMaskedSecret(masked.providers.custom.headers["Custom-Header"]), true);
  assert.equal(isMaskedSecret(masked.providers.custom.models[0].headers["X-Model-Secret"]), true);
  assert.equal(isMaskedSecret(masked.providers.custom.modelOverrides.nested.headers["X-Override"]), true);

  // Only the SDK's exact environment-reference form is safe to display.
  assert.equal(masked.providers.envRef.apiKey, "$OPENAI_API_KEY");
  assert.equal(isMaskedSecret(masked.providers.uppercaseLiteral.apiKey), true);
  assert.equal(masked.providers.uppercaseLiteral.apiKey.includes("UPPERCASELITERAL"), false);
  assert.equal(masked.providers.commandRef.apiKey, "••••••••");
});

test("mergeModelsConfigSecrets restores real secrets when client sends back masked values", () => {
  const existing = {
    providers: {
      custom: {
        apiKey: "sk-real-secret-key-9999",
        headers: {
          Authorization: "Bearer real-token-8888",
        },
        models: [{ id: "model-a", headers: { "X-Model": "model-real-secret" } }],
        modelOverrides: {
          "model-a": { headers: { "X-Override": "override-real-secret" } },
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
        models: [{ id: "model-a", headers: { "X-Model": "mode••••cret" } }],
        modelOverrides: {
          "model-a": { headers: { "X-Override": "over••••cret" } },
        },
      },
    },
  };

  const merged = mergeModelsConfigSecrets(incomingMasked, existing);
  assert.equal(merged.providers.custom.apiKey, "sk-real-secret-key-9999");
  assert.equal(merged.providers.custom.headers.Authorization, "Bearer real-token-8888");
  assert.equal(merged.providers.custom.models[0].headers["X-Model"], "model-real-secret");
  assert.equal(merged.providers.custom.modelOverrides["model-a"].headers["X-Override"], "override-real-secret");
  assert.equal(merged.providers.custom.baseUrl, "https://api.custom.ai/v2");
});

test("renaming a model preserves its masked headers by row", () => {
  const existing = {
    providers: {
      custom: { models: [{ id: "old-id", headers: { Authorization: "secret-token" } }] },
    },
  };
  const incoming = {
    providers: {
      custom: { models: [{ id: "new-id", headers: { Authorization: "secr••••oken" } }] },
    },
  };

  const merged = mergeModelsConfigSecrets(incoming, existing);
  assert.equal(merged.providers.custom.models[0].id, "new-id");
  assert.equal(merged.providers.custom.models[0].headers.Authorization, "secret-token");
});

test("provider rename mappings preserve every masked secret", () => {
  const existing = {
    providers: {
      old: {
        apiKey: "provider-secret",
        headers: { "X-Provider": "header-secret" },
        models: [{ id: "model", headers: { "X-Model": "model-secret" } }],
      },
    },
  };
  const incoming = {
    providers: {
      renamed: {
        apiKey: "prov••••cret",
        headers: { "X-Provider": "head••••cret" },
        models: [{ id: "model", headers: { "X-Model": "mode••••cret" } }],
      },
    },
  };
  const merged = mergeModelsConfigSecrets(incoming, existing, [{ from: "old", to: "renamed" }]);
  assert.equal(merged.providers.renamed.apiKey, "provider-secret");
  assert.equal(merged.providers.renamed.headers["X-Provider"], "header-secret");
  assert.equal(merged.providers.renamed.models[0].headers["X-Model"], "model-secret");
});

test("Discover and Test requests restore masked provider and renamed-model secrets", () => {
  const existing = {
    providers: {
      old: {
        apiKey: "provider-secret",
        headers: { "X-Provider": "header-secret" },
        models: [{ id: "old-model", headers: { "X-Model": "model-secret" } }],
      },
    },
  };
  const restored = restoreModelsConfigRequestSecrets({
    providerName: "renamed",
    sourceProviderName: "old",
    provider: { apiKey: "prov••••cret", headers: { "X-Provider": "head••••cret" } },
    model: { id: "new-model", headers: { "X-Model": "mode••••cret" } },
    sourceModelId: "old-model",
  }, existing);
  assert.equal(restored.provider.apiKey, "provider-secret");
  assert.equal(restored.provider.headers["X-Provider"], "header-secret");
  assert.equal(restored.model.headers["X-Model"], "model-secret");
});

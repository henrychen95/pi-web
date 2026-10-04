import { NextResponse } from "next/server";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { completeSimple, type AssistantMessage } from "@earendil-works/pi-ai/compat";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { hasJsonContentType, isApiRequestAllowed } from "@/lib/request-security";
import { createSafeModelFetch, isSafeModelUrl } from "@/lib/ssrf-protection";
import { restoreModelsConfigRequestSecrets } from "@/lib/models-config-store";

export const dynamic = "force-dynamic";

const TEST_TIMEOUT_MS = 20_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function getAssistantText(message: AssistantMessage): string {
  return message.content
    .filter((block) => block.type === "text")
    .map((block) => block.text)
    .join("");
}

export async function POST(req: Request) {
  if (!isApiRequestAllowed(req)) {
    return NextResponse.json({ ok: false, error: "Untrusted API request" }, { status: 403 });
  }
  if (!hasJsonContentType(req)) {
    return NextResponse.json(
      { ok: false, error: "Content-Type must be application/json" },
      { status: 415 },
    );
  }

  let tempDir: string | undefined;

  try {
    const body = await req.json() as {
      providerName?: unknown;
      providerSourceName?: unknown;
      modelSourceId?: unknown;
      provider?: unknown;
      model?: unknown;
    };
    const providerName = typeof body.providerName === "string" ? body.providerName.trim() : "";
    if (!providerName) return NextResponse.json({ ok: false, error: "providerName is required" }, { status: 400 });
    if (!isRecord(body.provider)) return NextResponse.json({ ok: false, error: "provider is required" }, { status: 400 });
    if (!isRecord(body.model)) return NextResponse.json({ ok: false, error: "model is required" }, { status: 400 });
    const providerSourceName = typeof body.providerSourceName === "string" && body.providerSourceName.trim()
      ? body.providerSourceName.trim()
      : providerName;
    const modelSourceId = typeof body.modelSourceId === "string" && body.modelSourceId.trim()
      ? body.modelSourceId.trim()
      : undefined;
    const restored = restoreModelsConfigRequestSecrets({
      providerName,
      sourceProviderName: providerSourceName,
      provider: body.provider,
      model: body.model,
      sourceModelId: modelSourceId,
    });
    const provider = restored.provider;
    const modelConfig = restored.model ?? body.model;

    const modelId = typeof modelConfig.id === "string" ? modelConfig.id.trim() : "";
    if (!modelId) return NextResponse.json({ ok: false, error: "Model ID is required" }, { status: 400 });

    const configuredBaseUrl = typeof provider.baseUrl === "string" ? provider.baseUrl.trim() : "";
    if (configuredBaseUrl) {
      const safety = isSafeModelUrl(configuredBaseUrl);
      if (!safety.safe) {
        return NextResponse.json({ ok: false, error: safety.reason || "Base URL is not allowed" }, { status: 400 });
      }
    }
    const configuredModelBaseUrl = typeof modelConfig.baseUrl === "string" ? modelConfig.baseUrl.trim() : "";
    if (configuredModelBaseUrl) {
      const safety = isSafeModelUrl(configuredModelBaseUrl);
      if (!safety.safe) {
        return NextResponse.json({ ok: false, error: safety.reason || "Model Base URL is not allowed" }, { status: 400 });
      }
    }

    tempDir = mkdtempSync(join(tmpdir(), "pi-web-model-test-"));
    const modelsPath = join(tempDir, "models.json");
    writeFileSync(modelsPath, JSON.stringify({
      providers: {
        [providerName]: {
          ...provider,
          models: [{ ...modelConfig, id: modelId }],
        },
      },
    }, null, 2), "utf8");

    const modelRuntime = await ModelRuntime.create({ modelsPath });
    const loadError = modelRuntime.getError();
    if (loadError) return NextResponse.json({ ok: false, error: loadError });

    const model = modelRuntime.getModel(providerName, modelId);
    if (!model) return NextResponse.json({ ok: false, error: `Model not found: ${providerName}/${modelId}` });
    const resolvedUrlSafety = isSafeModelUrl(model.baseUrl);
    if (!resolvedUrlSafety.safe) {
      return NextResponse.json({
        ok: false,
        error: resolvedUrlSafety.reason || "Resolved model Base URL is not allowed",
      }, { status: 400 });
    }

    const resolved = await modelRuntime.getAuth(model);
    if (!resolved?.auth.apiKey) {
      return NextResponse.json({ ok: false, error: `No API key found for "${providerName}"` });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TEST_TIMEOUT_MS);
    const safeTransport = createSafeModelFetch();
    let status: number | undefined;
    const startedAt = Date.now();

    try {
      const message = await completeSimple(model, {
        messages: [{
          role: "user",
          content: "Reply with OK only.",
          timestamp: Date.now(),
        }],
      }, {
        apiKey: resolved.auth.apiKey,
        headers: resolved.auth.headers,
        maxTokens: 16,
        timeoutMs: TEST_TIMEOUT_MS,
        maxRetries: 0,
        fetch: safeTransport.fetch,
        cacheRetention: "none",
        signal: controller.signal,
        onResponse: (response) => { status = response.status; },
      });

      const latencyMs = Date.now() - startedAt;
      if (message.stopReason === "error" || message.stopReason === "aborted") {
        return NextResponse.json({
          ok: false,
          error: message.errorMessage ?? (controller.signal.aborted ? "Test timed out" : "Model returned an error"),
          latencyMs,
          status,
        });
      }

      return NextResponse.json({
        ok: true,
        latencyMs,
        status,
        responseText: getAssistantText(message).slice(0, 300),
      });
    } finally {
      clearTimeout(timeout);
      await safeTransport.close();
    }
  } catch (error) {
    return NextResponse.json({ ok: false, error: errorMessage(error) }, { status: 500 });
  } finally {
    if (tempDir) rmSync(tempDir, { recursive: true, force: true });
  }
}

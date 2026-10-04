import { NextResponse } from "next/server";
import {
  maskModelsConfig,
  ModelsConfigReadError,
  readModelsConfig,
  writeModelsConfig,
} from "@/lib/models-config-store";
import { hasJsonContentType, isApiRequestAllowed } from "@/lib/request-security";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  if (!isApiRequestAllowed(req)) {
    return NextResponse.json({ error: "Untrusted API request" }, { status: 403 });
  }

  try {
    return NextResponse.json(maskModelsConfig(readModelsConfig()));
  } catch (error) {
    if (error instanceof ModelsConfigReadError) {
      return NextResponse.json({ error: error.message }, { status: 422 });
    }
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}

export async function PUT(req: Request) {
  if (!isApiRequestAllowed(req)) {
    return NextResponse.json({ error: "Untrusted API request" }, { status: 403 });
  }
  if (!hasJsonContentType(req)) {
    return NextResponse.json({ error: "Content-Type must be application/json" }, { status: 415 });
  }

  try {
    const body = await req.json() as Record<string, unknown>;
    let config = body;
    let providerRenames: Array<{ from: string; to: string }> = [];
    if (body.config !== undefined || body.providerRenames !== undefined) {
      if (!isRecord(body.config) || !Array.isArray(body.providerRenames)) {
        return NextResponse.json({ error: "config and providerRenames are required" }, { status: 400 });
      }
      const validRenames = body.providerRenames.every((value): value is { from: string; to: string } => (
        isRecord(value)
        && typeof value.from === "string"
        && value.from.length > 0
        && typeof value.to === "string"
        && value.to.length > 0
      ));
      if (!validRenames) {
        return NextResponse.json({ error: "Invalid provider rename mapping" }, { status: 400 });
      }
      config = body.config;
      providerRenames = body.providerRenames;
    }
    writeModelsConfig(config, undefined, providerRenames);
    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof ModelsConfigReadError) {
      return NextResponse.json({ error: error.message }, { status: 409 });
    }
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

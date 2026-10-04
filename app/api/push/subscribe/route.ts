import { addSubscription, type PushSubscriptionRecord } from "@/lib/web-push";
import { hasJsonContentType, isApiRequestAllowed } from "@/lib/request-security";
import { isSafeWebPushEndpoint } from "@/lib/ssrf-protection";

export const dynamic = "force-dynamic";

interface SubscribeRequestBody {
  subscription?: Partial<PushSubscriptionRecord>;
  locale?: string;
}

function isValidSubscription(subscription: Partial<PushSubscriptionRecord> | undefined): subscription is PushSubscriptionRecord {
  if (typeof subscription !== "object" || subscription === null) return false;
  if (typeof subscription.endpoint !== "string") return false;
  if (!isSafeWebPushEndpoint(subscription.endpoint).safe) return false;
  const keys = subscription.keys;
  if (typeof keys !== "object" || keys === null) return false;
  return typeof keys.p256dh === "string" && keys.p256dh.length > 0
    && typeof keys.auth === "string" && keys.auth.length > 0;
}

// POST /api/push/subscribe - register a browser push subscription. Upserts by
// endpoint, so the client can safely re-send its subscription on every load.
export async function POST(req: Request): Promise<Response> {
  if (!isApiRequestAllowed(req)) {
    return Response.json({ error: "Untrusted API request" }, { status: 403 });
  }
  if (!hasJsonContentType(req)) {
    return Response.json({ error: "Content-Type must be application/json" }, { status: 415 });
  }

  let body: SubscribeRequestBody;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (!isValidSubscription(body.subscription)) {
    return Response.json({ error: "Invalid push subscription" }, { status: 400 });
  }

  const locale = body.locale === "zh-CN" ? "zh-CN" : "en";
  await addSubscription({
    endpoint: body.subscription.endpoint,
    keys: body.subscription.keys,
    locale,
  });
  return Response.json({ ok: true });
}

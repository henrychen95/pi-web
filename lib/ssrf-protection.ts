import { lookup as dnsLookup, type LookupAddress, type LookupAllOptions } from "node:dns";
import { isIP } from "node:net";
import { Agent, Pool, buildConnector, fetch as undiciFetch } from "undici";

export interface UrlSafetyResult {
  safe: boolean;
  reason?: string;
}

const ALLOWED_LOCAL_MODEL_PORTS = new Set([
  "11434", // Ollama
  "1234",  // LM Studio
  "8080",  // llama.cpp / LocalAI
  "8000",  // vLLM
  "5000",  // text-generation-webui
  "3000",  // Open WebUI / local proxy
  "4000",  // LiteLLM proxy
]);

type ModelUrlSafetyOptions = {
  allowLocalLlm?: boolean;
  allowPrivateIps?: boolean;
};

function effectivePort(parsed: URL): string {
  if (parsed.port) return parsed.port;
  return parsed.protocol === "https:" ? "443" : "80";
}

function normalizedHostname(parsed: URL): string {
  return parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function isPrivateIpv4(a: number, b: number): boolean {
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function isNonPublicIpv4(a: number, b: number, c: number): boolean {
  return a === 0
    || a >= 224
    || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 192 && b === 0 && (c === 0 || c === 2))
    || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
    || (a === 203 && b === 0 && c === 113);
}

function isCloudMetadataHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (lower === "metadata.google.internal" || lower === "instance-data") return true;
  if (lower === "169.254.169.254" || lower === "169.254.169.253" || lower === "100.100.100.200") return true;
  return false;
}

/**
 * Validates whether an external model URL (e.g. baseUrl in models-config) is safe from SSRF.
 */
export function isSafeModelUrl(
  urlStr: string,
  options: ModelUrlSafetyOptions = {},
): UrlSafetyResult {
  const {
    allowLocalLlm = true,
    allowPrivateIps = process.env.PI_WEB_ALLOW_PRIVATE_MODELS === "1",
  } = options;

  if (!urlStr || typeof urlStr !== "string") {
    return { safe: false, reason: "URL is required" };
  }

  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { safe: false, reason: "Invalid URL format" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { safe: false, reason: `Unsupported protocol "${parsed.protocol}". Only http: and https: are allowed` };
  }

  if (parsed.username || parsed.password) {
    return { safe: false, reason: "Embedded credentials in URL authority are not allowed" };
  }

  const hostname = normalizedHostname(parsed);
  const port = effectivePort(parsed);

  if (isCloudMetadataHost(hostname)) {
    return { safe: false, reason: "Access to cloud metadata endpoints is forbidden" };
  }

  const ipVersion = isIP(hostname);

  if (ipVersion === 4) {
    const parts = hostname.split(".").map(Number);
    const [a, b, c] = parts;

    // 0.0.0.0 or broadcast
    if (a === 0 || a === 255) {
      return { safe: false, reason: "Broadcast or unroutable IP addresses are forbidden" };
    }

    // Link-local / Cloud metadata range 169.254.0.0/16
    if (a === 169 && b === 254) {
      return { safe: false, reason: "Link-local addresses (169.254.0.0/16) are forbidden" };
    }

    // Multicast 224.0.0.0/4
    if (a >= 224 && a <= 239) {
      return { safe: false, reason: "Multicast IP addresses are forbidden" };
    }

    // Loopback 127.0.0.0/8
    if (a === 127) {
      if (!allowLocalLlm) {
        return { safe: false, reason: "Loopback addresses are not permitted" };
      }
      if (!ALLOWED_LOCAL_MODEL_PORTS.has(port)) {
        return { safe: false, reason: `Port ${port} on loopback is not an allowed local LLM port` };
      }
      return { safe: true };
    }

    // Private IP (RFC 1918)
    if (isPrivateIpv4(a, b)) {
      if (!allowPrivateIps) {
        return { safe: false, reason: "Private network IP addresses (RFC 1918) are forbidden" };
      }
    }

    if (isNonPublicIpv4(a, b, c)) {
      return { safe: false, reason: "Non-public IP addresses are forbidden" };
    }

    return { safe: true };
  }

  if (ipVersion === 6) {
    if (hostname === "::") {
      return { safe: false, reason: "Unspecified IPv6 addresses are forbidden" };
    }
    if (hostname === "::1") {
      if (!allowLocalLlm) {
        return { safe: false, reason: "Loopback addresses are not permitted" };
      }
      if (!ALLOWED_LOCAL_MODEL_PORTS.has(port)) {
        return { safe: false, reason: `Port ${port} on loopback is not an allowed local LLM port` };
      }
      return { safe: true };
    }

    // Link-local fe80::/10
    if (hostname.startsWith("fe8") || hostname.startsWith("fe9") || hostname.startsWith("fea") || hostname.startsWith("feb")) {
      return { safe: false, reason: "Link-local IPv6 addresses are forbidden" };
    }

    // Unique local fc00::/7
    if (hostname.startsWith("fc") || hostname.startsWith("fd")) {
      if (!allowPrivateIps) {
        return { safe: false, reason: "Private IPv6 addresses are forbidden" };
      }
      return { safe: true };
    }

    // IPv4-mapped IPv6 ::ffff:a.b.c.d
    if (hostname.startsWith("::ffff:")) {
      const ipv4Part = hostname.slice(7);
      return isSafeModelUrl(`http://${ipv4Part}:${parsed.port || 80}`, options);
    }

    if (hostname.startsWith("ff") || (!hostname.startsWith("2") && !hostname.startsWith("3"))
      || hostname.startsWith("2001:db8")) {
      return { safe: false, reason: "Non-public IPv6 addresses are forbidden" };
    }

    return { safe: true };
  }

  // Hostname validation
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    if (!allowLocalLlm) {
      return { safe: false, reason: "Localhost access is not permitted" };
    }
    if (!ALLOWED_LOCAL_MODEL_PORTS.has(port)) {
      return { safe: false, reason: `Port ${port} on localhost is not an allowed local LLM port` };
    }
    return { safe: true };
  }

  return { safe: true };
}

function isExplicitLoopbackHost(hostname: string): boolean {
  if (hostname === "localhost" || hostname.endsWith(".localhost")) return true;
  if (hostname === "::1") return true;
  if (isIP(hostname) === 4) return Number(hostname.split(".")[0]) === 127;
  return false;
}

function isSafeResolvedModelAddress(
  address: string,
  parsed: URL,
  options: ModelUrlSafetyOptions,
): UrlSafetyResult {
  const ipVersion = isIP(address);
  if (ipVersion === 4) {
    const [a, b, c] = address.split(".").map(Number);
    if (a === 127) {
      const localAllowed = options.allowLocalLlm !== false
        && isExplicitLoopbackHost(normalizedHostname(parsed))
        && ALLOWED_LOCAL_MODEL_PORTS.has(effectivePort(parsed));
      return localAllowed
        ? { safe: true }
        : { safe: false, reason: `Hostname resolved to loopback address ${address}` };
    }
    if (isPrivateIpv4(a, b) && !(options.allowPrivateIps ?? process.env.PI_WEB_ALLOW_PRIVATE_MODELS === "1")) {
      return { safe: false, reason: `Hostname resolved to private address ${address}` };
    }
    if (isNonPublicIpv4(a, b, c)) {
      return { safe: false, reason: `Resolved address ${address} is not publicly routable` };
    }
    return { safe: true };
  }

  if (ipVersion === 6) {
    const lower = address.toLowerCase();
    if (lower === "::" || lower.startsWith("ff") || lower.startsWith("fe8")
      || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) {
      return { safe: false, reason: `Resolved address ${address} is not publicly routable` };
    }
    if (lower.startsWith("::ffff:")) {
      return { safe: false, reason: `IPv4-mapped resolved address ${address} is forbidden` };
    }
    if (lower === "::1") {
      const localAllowed = options.allowLocalLlm !== false
        && isExplicitLoopbackHost(normalizedHostname(parsed))
        && ALLOWED_LOCAL_MODEL_PORTS.has(effectivePort(parsed));
      return localAllowed
        ? { safe: true }
        : { safe: false, reason: `Hostname resolved to loopback address ${address}` };
    }
    if (lower.startsWith("fc") || lower.startsWith("fd")) {
      return (options.allowPrivateIps ?? process.env.PI_WEB_ALLOW_PRIVATE_MODELS === "1")
        ? { safe: true }
        : { safe: false, reason: `Hostname resolved to private address ${address}` };
    }
    if (!lower.startsWith("2") && !lower.startsWith("3")) {
      return { safe: false, reason: `Resolved address ${address} is not publicly routable` };
    }
    if (lower.startsWith("2001:db8")) {
      return { safe: false, reason: `Resolved address ${address} is not publicly routable` };
    }
    return { safe: true };
  }

  return { safe: false, reason: `DNS returned an invalid address for ${parsed.hostname}` };
}

export function validateResolvedModelAddresses(
  urlStr: string,
  addresses: readonly string[],
  options: ModelUrlSafetyOptions = {},
): UrlSafetyResult {
  const initial = isSafeModelUrl(urlStr, options);
  if (!initial.safe) return initial;
  if (addresses.length === 0) return { safe: false, reason: "Hostname did not resolve to an address" };
  const parsed = new URL(urlStr);
  for (const address of addresses) {
    const result = isSafeResolvedModelAddress(address, parsed, options);
    if (!result.safe) return result;
  }
  return { safe: true };
}

/**
 * A fetch implementation whose DNS result is validated in the connector that
 * consumes it. Undici reuses this dispatcher for redirects and creates a new
 * pool for each new origin, so every redirect host is checked before connect.
 */
export function createSafeModelFetch(options: ModelUrlSafetyOptions = {}): {
  fetch: typeof globalThis.fetch;
  close: () => Promise<void>;
} {
  const dispatcher = new Agent({
    factory(origin) {
      const parsed = new URL(origin);
      const initial = isSafeModelUrl(parsed.toString(), options);
      if (!initial.safe) throw new Error(initial.reason || "Model endpoint is not allowed");

      const safeLookup = (
        hostname: string,
        lookupOptions: LookupAllOptions,
        callback: (...args: unknown[]) => void,
      ) => {
        dnsLookup(hostname, { ...lookupOptions, all: true }, (error, addresses: LookupAddress[]) => {
          if (error) {
            callback(error);
            return;
          }
          const safety = validateResolvedModelAddresses(
            parsed.toString(),
            addresses.map((entry) => entry.address),
            options,
          );
          if (!safety.safe) {
            callback(new Error(safety.reason || "Resolved model endpoint is not allowed"));
            return;
          }
          if (lookupOptions.all) callback(null, addresses);
          else callback(null, addresses[0]?.address, addresses[0]?.family);
        });
      };
      const connector = buildConnector({ lookup: safeLookup as unknown as typeof dnsLookup });
      return new Pool(origin, { connections: 1, connect: connector });
    },
  });

  return {
    fetch: ((input: Parameters<typeof globalThis.fetch>[0], init?: Parameters<typeof globalThis.fetch>[1]) => {
      return undiciFetch(input as Parameters<typeof undiciFetch>[0], {
        ...(init as Parameters<typeof undiciFetch>[1]),
        // Provider keys may live in arbitrary headers, which Fetch does not
        // necessarily strip on a cross-origin redirect. Callers handle 3xx as
        // an upstream response instead of forwarding credentials to a new URL.
        redirect: "manual",
        dispatcher,
      }) as unknown as Promise<Response>;
    }) as typeof globalThis.fetch,
    close: () => dispatcher.close(),
  };
}

const ALLOWED_PUSH_DOMAINS = [
  "fcm.googleapis.com",
  "services.mozilla.com",
  "web.push.apple.com",
  "notify.windows.com",
  "push.opera.com",
];

/**
 * Validates Web Push endpoint URLs to ensure they only connect to approved push services.
 */
export function isSafeWebPushEndpoint(endpoint: string): UrlSafetyResult {
  if (!endpoint || typeof endpoint !== "string") {
    return { safe: false, reason: "Push endpoint is required" };
  }

  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return { safe: false, reason: "Invalid push endpoint URL" };
  }

  if (parsed.protocol !== "https:") {
    return { safe: false, reason: "Push endpoint must use HTTPS" };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Reject raw IP addresses
  if (isIP(hostname)) {
    return { safe: false, reason: "Push endpoint hostname cannot be an IP address" };
  }

  const isAllowedDomain = ALLOWED_PUSH_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );

  if (!isAllowedDomain) {
    return { safe: false, reason: `Push endpoint domain "${hostname}" is not recognized as a legitimate push service` };
  }

  return { safe: true };
}

import { isIP } from "node:net";

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

function isPrivateIpv4(a: number, b: number): boolean {
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
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
  options: { allowLocalLlm?: boolean; allowPrivateIps?: boolean } = {},
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

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (isCloudMetadataHost(hostname)) {
    return { safe: false, reason: "Access to cloud metadata endpoints is forbidden" };
  }

  const ipVersion = isIP(hostname);

  if (ipVersion === 4) {
    const parts = hostname.split(".").map(Number);
    const [a, b] = parts;

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
      if (parsed.port && !ALLOWED_LOCAL_MODEL_PORTS.has(parsed.port)) {
        return { safe: false, reason: `Port ${parsed.port} on loopback is not an allowed local LLM port` };
      }
      return { safe: true };
    }

    // Private IP (RFC 1918)
    if (isPrivateIpv4(a, b)) {
      if (!allowPrivateIps) {
        return { safe: false, reason: "Private network IP addresses (RFC 1918) are forbidden" };
      }
    }

    return { safe: true };
  }

  if (ipVersion === 6) {
    if (hostname === "::1") {
      if (!allowLocalLlm) {
        return { safe: false, reason: "Loopback addresses are not permitted" };
      }
      if (parsed.port && !ALLOWED_LOCAL_MODEL_PORTS.has(parsed.port)) {
        return { safe: false, reason: `Port ${parsed.port} on loopback is not an allowed local LLM port` };
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
    }

    // IPv4-mapped IPv6 ::ffff:a.b.c.d
    if (hostname.startsWith("::ffff:")) {
      const ipv4Part = hostname.slice(7);
      return isSafeModelUrl(`http://${ipv4Part}:${parsed.port || 80}`, options);
    }

    return { safe: true };
  }

  // Hostname validation
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    if (!allowLocalLlm) {
      return { safe: false, reason: "Localhost access is not permitted" };
    }
    if (parsed.port && !ALLOWED_LOCAL_MODEL_PORTS.has(parsed.port)) {
      return { safe: false, reason: `Port ${parsed.port} on localhost is not an allowed local LLM port` };
    }
    return { safe: true };
  }

  return { safe: true };
}

const ALLOWED_PUSH_DOMAINS = [
  "googleapis.com",
  "google.com",
  "services.mozilla.com",
  "mozilla.com",
  "push.apple.com",
  "apple.com",
  "notify.windows.com",
  "microsoft.com",
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

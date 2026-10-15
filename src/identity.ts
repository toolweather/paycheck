import { SCORE } from "./policy";
import type { PaycheckStore } from "./store";
import { sha256Hex, safeEqual } from "./text";

export type SubjectKind = "anonymous" | "api_key" | "bundle_hex" | "bundle_anon" | "bundle_other";

export type Identity =
  | { ok: true; subject: string; kind: SubjectKind; limit: number }
  | { ok: false; status: number; error: string; message: string };

export function clientIp(headers: Headers): string {
  const cf = headers.get("cf-connecting-ip")?.trim();
  if (cf) return cf.slice(0, 128);
  const forwarded = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (forwarded) return forwarded.slice(0, 128);
  return "local";
}

export function bundleTier(client: string): { kind: SubjectKind; limit: number; subject: string } | null {
  const trimmed = client.trim();
  if (!trimmed) return null;
  const normalized = trimmed.toLowerCase();
  if (normalized === "anon" || normalized.startsWith("anon:")) {
    return { kind: "bundle_anon", limit: SCORE.bundleAnonDaily, subject: `bundle:${normalized}` };
  }
  if (/^[0-9a-f]{16,128}$/i.test(trimmed)) {
    return { kind: "bundle_hex", limit: SCORE.bundleHexDaily, subject: `bundle:${normalized}` };
  }
  return { kind: "bundle_other", limit: SCORE.bundleAnonDaily, subject: `bundle:${normalized.slice(0, 128)}` };
}

export async function resolveIdentity(input: {
  store: PaycheckStore;
  ip: string;
  apiKey: string | null;
  bundleSecretHeader: string | null;
  bundleClientHeader: string | null;
  configuredBundleSecret: string | undefined;
}): Promise<Identity> {
  if (input.bundleSecretHeader !== null && input.bundleSecretHeader !== undefined && input.bundleSecretHeader !== "") {
    const configured = input.configuredBundleSecret?.trim();
    if (!configured || !safeEqual(input.bundleSecretHeader, configured)) {
      return {
        ok: false,
        status: 401,
        error: "invalid_bundle_secret",
        message: "x-tw-bundle-secret does not match BUNDLE_PROXY_SECRET.",
      };
    }
    const client = input.bundleClientHeader?.trim() ?? "";
    if (!client) {
      return {
        ok: false,
        status: 400,
        error: "missing_bundle_client",
        message: "x-tw-bundle-client is required when x-tw-bundle-secret is sent.",
      };
    }
    const tier = bundleTier(client);
    if (!tier) {
      return { ok: false, status: 400, error: "missing_bundle_client", message: "x-tw-bundle-client is empty." };
    }
    return { ok: true, subject: tier.subject, kind: tier.kind, limit: tier.limit };
  }

  const key = input.apiKey?.trim() ?? "";
  if (key) {
    if (!key.startsWith("pc_live_")) {
      return { ok: false, status: 401, error: "invalid_api_key", message: "API keys start with pc_live_." };
    }
    const hash = await sha256Hex(key);
    const known = await input.store.hasKeyHash(hash);
    if (!known) {
      return { ok: false, status: 401, error: "invalid_api_key", message: "Unknown API key." };
    }
    return { ok: true, subject: `key:${hash}`, kind: "api_key", limit: SCORE.keyDaily };
  }

  return { ok: true, subject: `ip:${input.ip}`, kind: "anonymous", limit: SCORE.anonDaily };
}

export function readApiKey(headers: Headers, bodyKey: unknown): string | null {
  if (typeof bodyKey === "string" && bodyKey.trim()) return bodyKey.trim();
  const headerKey = headers.get("x-api-key")?.trim();
  if (headerKey) return headerKey;
  const auth = headers.get("authorization")?.trim() ?? "";
  const match = /^Bearer\s+(\S+)$/i.exec(auth);
  if (match?.[1]) return match[1];
  return null;
}

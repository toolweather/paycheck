import { X402 } from "./policy";
import type { PaycheckStore } from "./store";
import { base64ToString, jsonBase64 } from "./text";

export interface PaymentChallenge {
  status: 402;
  body: Record<string, unknown>;
  headers: Record<string, string>;
}

export function paymentNotConfigured(quota: { limit: number; used: number; remaining: number; resets_at: string }): PaymentChallenge {
  return {
    status: 402,
    body: {
      error: "payment_not_configured",
      message: "Free quota is exhausted and this deployment has no PAY_TO address, so x402 overage cannot be settled.",
      quota,
    },
    headers: {},
  };
}

export function paymentRequirements(payTo: string) {
  return {
    scheme: X402.scheme,
    network: X402.network,
    amount: X402.amountAtomic,
    asset: X402.asset,
    payTo,
    maxTimeoutSeconds: X402.maxTimeoutSeconds,
    extra: { name: X402.assetName, version: X402.assetVersion },
  };
}

export function challenge(resourceUrl: string, payTo: string, error = "PAYMENT-SIGNATURE header is required"): PaymentChallenge {
  const body = {
    x402Version: X402.version,
    error,
    resource: {
      url: resourceUrl,
      description: "PayCheck merchant trust check for one target",
      mimeType: "application/json",
    },
    accepts: [paymentRequirements(payTo)],
    extensions: {},
  };
  return {
    status: 402,
    body,
    headers: {
      "PAYMENT-REQUIRED": jsonBase64(body),
    },
  };
}

export interface SettledPayment {
  ok: true;
  payer: string;
  transaction: string;
  responseHeader: string;
}

export interface RejectedPayment {
  ok: false;
  challenge: PaymentChallenge;
}

export async function settlePayment(input: {
  payTo: string;
  resourceUrl: string;
  paymentSignatureHeader: string | null;
  xPaymentHeader: string | null;
  store: PaycheckStore;
  fetchFn: typeof fetch;
  now: Date;
}): Promise<SettledPayment | RejectedPayment> {
  const header = input.paymentSignatureHeader || input.xPaymentHeader;
  if (!header) return { ok: false, challenge: challenge(input.resourceUrl, input.payTo) };

  let payload: unknown;
  try {
    payload = JSON.parse(decodePaymentHeader(header));
  } catch {
    return { ok: false, challenge: challenge(input.resourceUrl, input.payTo, "Payment header is not valid JSON.") };
  }
  if (!payload || typeof payload !== "object") {
    return { ok: false, challenge: challenge(input.resourceUrl, input.payTo, "Payment payload is empty.") };
  }

  const record = payload as Record<string, unknown>;
  const version = Number(record.x402Version ?? 2);
  const requirements = version === 1 ? v1Requirements(input.payTo, input.resourceUrl) : paymentRequirements(input.payTo);
  const localError = validatePayload(record, input.payTo, version);
  if (localError) return { ok: false, challenge: challenge(input.resourceUrl, input.payTo, localError) };

  const nonce = readNonce(record);
  if (!nonce) return { ok: false, challenge: challenge(input.resourceUrl, input.payTo, "Payment payload is missing an authorization nonce.") };
  if (await input.store.hasNonce(nonce)) {
    return { ok: false, challenge: challenge(input.resourceUrl, input.payTo, "Payment nonce was already used.") };
  }

  const verifyBody = { x402Version: version, paymentPayload: record, paymentRequirements: requirements };
  let verifyJson: { isValid?: boolean; invalidReason?: string; payer?: string };
  try {
    const verifyRes = await input.fetchFn(`${X402.facilitator}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "PayCheck/1.0" },
      body: JSON.stringify(verifyBody),
      signal: AbortSignal.timeout(8000),
    });
    verifyJson = (await verifyRes.json()) as { isValid?: boolean; invalidReason?: string; payer?: string };
    if (!verifyRes.ok || verifyJson.isValid !== true) {
      return {
        ok: false,
        challenge: challenge(input.resourceUrl, input.payTo, verifyJson.invalidReason || "Payment verification failed."),
      };
    }
  } catch {
    return { ok: false, challenge: challenge(input.resourceUrl, input.payTo, "facilitator_unavailable") };
  }

  try {
    const settleRes = await input.fetchFn(`${X402.facilitator}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "PayCheck/1.0" },
      body: JSON.stringify(verifyBody),
      signal: AbortSignal.timeout(15000),
    });
    const settled = (await settleRes.json()) as { success?: boolean; errorReason?: string; payer?: string; transaction?: string; network?: string };
    if (!settleRes.ok || settled.success !== true) {
      return {
        ok: false,
        challenge: challenge(input.resourceUrl, input.payTo, settled.errorReason || "Payment settlement failed."),
      };
    }
    const payer = settled.payer || verifyJson.payer || "";
    const transaction = settled.transaction || "";
    await input.store.putNonce(nonce, payer, input.now.getTime(), transaction);
    const response = { success: true, transaction, network: X402.network, payer };
    return { ok: true, payer, transaction, responseHeader: jsonBase64(response) };
  } catch {
    return { ok: false, challenge: challenge(input.resourceUrl, input.payTo, "facilitator_unavailable") };
  }
}

function decodePaymentHeader(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith("{")) return trimmed;
  return base64ToString(trimmed);
}

function readNonce(record: Record<string, unknown>): string | null {
  const payload = record.payload;
  if (!payload || typeof payload !== "object") return null;
  const authorization = (payload as { authorization?: unknown }).authorization;
  if (!authorization || typeof authorization !== "object") return null;
  const nonce = (authorization as { nonce?: unknown }).nonce;
  return typeof nonce === "string" && nonce.trim() ? nonce.trim() : null;
}

function validatePayload(record: Record<string, unknown>, payTo: string, version: number): string | null {
  const accepted = (version === 1 ? record : record.accepted) as Record<string, unknown> | undefined;
  const scheme = String(accepted?.scheme ?? record.scheme ?? "");
  const network = String(accepted?.network ?? record.network ?? "");
  const asset = String(accepted?.asset ?? record.asset ?? "").toLowerCase();
  const to = String(accepted?.payTo ?? record.payTo ?? "");
  if (scheme && scheme !== "exact") return "Unsupported payment scheme.";
  const networkOk = network === X402.network || (version === 1 && network === "base");
  if (network && !networkOk) return "Unsupported payment network.";
  if (asset && asset !== X402.asset.toLowerCase()) return "Unsupported payment asset.";
  if (to && to.toLowerCase() !== payTo.toLowerCase()) return "Payment recipient does not match PAY_TO.";

  const payload = record.payload;
  if (!payload || typeof payload !== "object") return "Payment payload is missing.";
  const authorization = (payload as { authorization?: unknown }).authorization;
  if (!authorization || typeof authorization !== "object") return "Payment authorization is missing.";
  const auth = authorization as { to?: unknown; value?: unknown };
  if (typeof auth.to === "string" && auth.to.toLowerCase() !== payTo.toLowerCase()) {
    return "Authorization recipient does not match PAY_TO.";
  }
  if (typeof auth.value === "string") {
    try {
      if (BigInt(auth.value) < BigInt(X402.amountAtomic)) return "Payment amount is below 0.001 USDC.";
    } catch {
      return "Payment amount is not an integer.";
    }
  }
  return null;
}

function v1Requirements(payTo: string, resourceUrl: string) {
  return {
    scheme: "exact",
    network: "base",
    maxAmountRequired: X402.amountAtomic,
    resource: resourceUrl,
    description: "PayCheck merchant trust check for one target",
    mimeType: "application/json",
    payTo,
    maxTimeoutSeconds: X402.maxTimeoutSeconds,
    asset: X402.asset,
    extra: { name: X402.assetName, version: X402.assetVersion },
  };
}

import { needsDomainAge, scorePayee, type AgeInput, type CheckResult } from "./score";
import { parseTarget } from "./parse";
import { SCORE } from "./policy";
import { lookupDomainAge } from "./rdap";
import type { PaycheckStore } from "./store";
import { resolveIdentity, type Identity } from "./identity";
import { nextUtcMidnight, randomHex, sha256Hex, startOfUtcDay, utcDay } from "./text";
import { paymentNotConfigured, settlePayment, type PaymentChallenge } from "./x402";
import { POLICY_VERSION } from "./version";

export interface QuotaBody {
  subject_kind: Identity extends { ok: true } ? Identity["kind"] : string;
  limit: number;
  used: number;
  remaining: number;
  resets_at: string;
  billed: false;
  policy_version: typeof POLICY_VERSION;
}

export type ServiceFailure = {
  type: "error";
  status: number;
  body: Record<string, unknown>;
};

export type ServicePayment = {
  type: "payment";
  challenge: PaymentChallenge;
};

export type CheckOutcome =
  | { type: "ok"; body: CheckResult; paymentResponseHeader?: string }
  | ServiceFailure
  | ServicePayment;

export interface CheckRequest {
  store: PaycheckStore;
  target: unknown;
  amountUsd: unknown;
  category: unknown;
  apiKey: string | null;
  bundleSecretHeader: string | null;
  bundleClientHeader: string | null;
  ip: string;
  payTo: string | undefined;
  bundleSecret: string | undefined;
  fetchFn: typeof fetch;
  now: Date;
  resourceUrl: string;
  paymentSignatureHeader: string | null;
  xPaymentHeader: string | null;
}

export async function performCheck(input: CheckRequest): Promise<CheckOutcome> {
  const invalid = validateIgnoredFields(input.amountUsd, input.category);
  if (invalid) return invalid;
  if (input.target !== undefined && input.target !== null && typeof input.target !== "string") {
    return { type: "error", status: 400, body: { error: "invalid_target", message: "target must be a string." } };
  }
  const target = typeof input.target === "string" ? input.target : "";
  if (target.length > SCORE.maxTargetLength) {
    return { type: "error", status: 400, body: { error: "target_too_long", message: "target must be at most 2048 characters." } };
  }

  const identity = await resolveIdentity({
    store: input.store,
    ip: input.ip,
    apiKey: input.apiKey,
    bundleSecretHeader: input.bundleSecretHeader,
    bundleClientHeader: input.bundleClientHeader,
    configuredBundleSecret: input.bundleSecret,
  });
  if (!identity.ok) {
    return { type: "error", status: identity.status, body: { error: identity.error, message: identity.message } };
  }

  const parsed = parseTarget(target);
  const day = utcDay(input.now);
  const cached = await input.store.getCachedCheck(identity.subject, parsed.cacheKey);
  if (cached && input.now.getTime() - cached.checkedAtMs <= SCORE.idempotentWindowSeconds * 1000) {
    const body = JSON.parse(cached.responseJson) as CheckResult;
    body.signals = { ...body.signals, idempotent_replay: true };
    return { type: "ok", body };
  }

  const used = await input.store.getUsage(identity.subject, day);
  let billing: "free" | "x402" = "free";
  let paymentResponseHeader: string | undefined;
  if (used >= identity.limit) {
    const quota = quotaSnapshot(identity, used, input.now);
    const payTo = input.payTo?.trim();
    if (!payTo) {
      return { type: "payment", challenge: paymentNotConfigured(quota) };
    }
    const settled = await settlePayment({
      payTo,
      resourceUrl: input.resourceUrl,
      paymentSignatureHeader: input.paymentSignatureHeader,
      xPaymentHeader: input.xPaymentHeader,
      store: input.store,
      fetchFn: input.fetchFn,
      now: input.now,
    });
    if (!settled.ok) return { type: "payment", challenge: settled.challenge };
    billing = "x402";
    paymentResponseHeader = settled.responseHeader;
  } else {
    const next = await input.store.addUsage(identity.subject, day, 1);
    if (next > identity.limit) {
      await input.store.addUsage(identity.subject, day, -1);
      const payTo = input.payTo?.trim();
      const quota = quotaSnapshot(identity, identity.limit, input.now);
      if (!payTo) return { type: "payment", challenge: paymentNotConfigured(quota) };
      const settled = await settlePayment({
        payTo,
        resourceUrl: input.resourceUrl,
        paymentSignatureHeader: input.paymentSignatureHeader,
        xPaymentHeader: input.xPaymentHeader,
        store: input.store,
        fetchFn: input.fetchFn,
        now: input.now,
      });
      if (!settled.ok) return { type: "payment", challenge: settled.challenge };
      billing = "x402";
      paymentResponseHeader = settled.responseHeader;
    }
  }

  const age = await resolveAge(target, input);
  const result = scorePayee({ target, age, now: input.now });
  result.signals.billing = billing;
  const storedTarget = target.slice(0, 512);
  await input.store.putCachedCheck(identity.subject, parsed.cacheKey, input.now.getTime(), JSON.stringify(result));
  await input.store.insertHistory({
    checkedAtMs: input.now.getTime(),
    subject: identity.subject,
    target: storedTarget,
    cacheKey: parsed.cacheKey,
    score: result.score,
    verdict: result.verdict,
    policyVersion: POLICY_VERSION,
    billing,
  });
  return { type: "ok", body: result, paymentResponseHeader };
}

async function resolveAge(target: string, input: CheckRequest): Promise<AgeInput> {
  if (!needsDomainAge(target)) {
    const parsed = parseTarget(target);
    if (parsed.allowlisted) return { status: "skipped_allowlist" };
    return { status: "not_applicable" };
  }
  const parsed = parseTarget(target);
  const registrable = parsed.registrable;
  if (!registrable) return { status: "unknown", source: "unavailable" };
  const looked = await lookupDomainAge(registrable, input.store, input.fetchFn, input.now);
  if (looked.status === "known" && looked.days !== null) {
    return { status: "known", days: looked.days, source: looked.source === "cache" ? "cache" : "rdap" };
  }
  return { status: "unknown", source: looked.source === "cache" ? "cache" : "unavailable" };
}

export async function readQuota(input: {
  store: PaycheckStore;
  apiKey: string | null;
  bundleSecretHeader: string | null;
  bundleClientHeader: string | null;
  ip: string;
  payTo: string | undefined;
  bundleSecret: string | undefined;
  now: Date;
}): Promise<{ type: "ok"; body: QuotaBody } | ServiceFailure> {
  const identity = await resolveIdentity({
    store: input.store,
    ip: input.ip,
    apiKey: input.apiKey,
    bundleSecretHeader: input.bundleSecretHeader,
    bundleClientHeader: input.bundleClientHeader,
    configuredBundleSecret: input.bundleSecret,
  });
  if (!identity.ok) return { type: "error", status: identity.status, body: { error: identity.error, message: identity.message } };
  const used = await input.store.getUsage(identity.subject, utcDay(input.now));
  return { type: "ok", body: quotaSnapshot(identity, used, input.now) };
}

function quotaSnapshot(identity: Extract<Identity, { ok: true }>, used: number, now: Date): QuotaBody {
  return {
    subject_kind: identity.kind,
    limit: identity.limit,
    used,
    remaining: Math.max(0, identity.limit - used),
    resets_at: nextUtcMidnight(now),
    billed: false,
    policy_version: POLICY_VERSION,
  };
}

export async function mintApiKey(input: { store: PaycheckStore; ip: string; now: Date }): Promise<
  | { type: "ok"; status: 201; body: Record<string, unknown> }
  | ServiceFailure
> {
  const since = startOfUtcDay(input.now);
  const minted = await input.store.countKeysSince(input.ip, since);
  if (minted >= SCORE.keyMintsPerIpPerDay) {
    return {
      type: "error",
      status: 429,
      body: {
        error: "key_mint_limit",
        message: `At most ${SCORE.keyMintsPerIpPerDay} keys can be minted per IP per UTC day. Do not call get_api_key every turn.`,
        limit: SCORE.keyMintsPerIpPerDay,
        resets_at: nextUtcMidnight(input.now),
      },
    };
  }
  const apiKey = `pc_live_${randomHex(32)}`;
  const hash = await sha256Hex(apiKey);
  await input.store.insertKey({
    hash,
    prefix: apiKey.slice(0, 12),
    ownerIp: input.ip,
    createdAtMs: input.now.getTime(),
  });
  return {
    type: "ok",
    status: 201,
    body: {
      api_key: apiKey,
      token_type: "bearer",
      daily_limit: SCORE.keyDaily,
      prefix: apiKey.slice(0, 12),
      note: "Store this key now. PayCheck keeps only a SHA-256 hash. Do not call get_api_key every turn. The key raises the free check allowance to 1,000 per UTC day. It does not change merchant scores.",
    },
  };
}

function validateIgnoredFields(amountUsd: unknown, category: unknown): ServiceFailure | null {
  if (amountUsd !== undefined && amountUsd !== null) {
    if (typeof amountUsd !== "number" || !Number.isFinite(amountUsd) || amountUsd < 0) {
      return { type: "error", status: 400, body: { error: "invalid_amount_usd", message: "amount_usd must be a non-negative finite number. It is ignored by the scorer." } };
    }
  }
  if (category !== undefined && category !== null) {
    if (typeof category !== "string") {
      return { type: "error", status: 400, body: { error: "invalid_category", message: "category must be a string. It is ignored by the scorer." } };
    }
    if (category.length > 500) {
      return { type: "error", status: 400, body: { error: "category_too_long", message: "category must be at most 500 characters. It is ignored by the scorer." } };
    }
  }
  return null;
}

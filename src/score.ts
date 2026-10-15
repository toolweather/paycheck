import { parseTarget, type ParsedTarget } from "./parse";
import { DENYLIST_PATTERNS, SCORE } from "./policy";
import { POLICY_VERSION } from "./version";
import { clamp } from "./text";

export type Verdict = "trusted" | "unknown" | "suspicious" | "block";
export type RecommendedAction = "proceed" | "verify_out_of_band" | "require_human_review" | "do_not_pay";

export type AgeInput =
  | { status: "not_applicable" }
  | { status: "skipped_allowlist" }
  | { status: "unknown"; source: "rdap" | "cache" | "unavailable" }
  | { status: "known"; days: number; source: "rdap" | "cache" };

export interface CheckSignals {
  kind: "domain" | "wallet" | "invalid";
  normalized_target: string | null;
  host: string | null;
  scheme: string | null;
  port: number | null;
  allowlisted: boolean;
  denylisted: boolean;
  typosquat_of: string | null;
  impersonation_of: string | null;
  lookalike: boolean;
  hyphen_count: number;
  unsafe_shape: string | null;
  domain_age_days: number | null;
  domain_age_source: "rdap" | "cache" | "unavailable" | "skipped_allowlist" | "not_applicable";
  wallet_valid: boolean | null;
  burn_address: boolean;
  chain_analysis: "not_in_v1";
  embedded_wallet: boolean;
  hard_block: boolean;
  reason_codes: string[];
  category_ignored: true;
  amount_ignored: true;
  billing?: "free" | "x402";
  idempotent_replay?: boolean;
}

export interface CheckResult {
  score: number;
  verdict: Verdict;
  reasons: string[];
  recommended_action: RecommendedAction;
  signals: CheckSignals;
  checked_at: string;
  policy_version: typeof POLICY_VERSION;
}

const ACTION: Record<Verdict, RecommendedAction> = {
  trusted: "proceed",
  unknown: "verify_out_of_band",
  suspicious: "require_human_review",
  block: "do_not_pay",
};

const HAZARD_CAPS: Record<string, number> = {
  missing_target: SCORE.missingCap,
  target_too_long: SCORE.missingCap,
  unparsed: SCORE.missingCap,
  invalid_wallet: SCORE.invalidWalletCap,
  burn_address: SCORE.burnCap,
  non_https: SCORE.nonHttpsCap,
  raw_ip: SCORE.rawIpCap,
  local_or_private: SCORE.localCap,
  url_userinfo: SCORE.userinfoCap,
  unsupported_scheme: SCORE.unsupportedSchemeCap,
  bad_tld: SCORE.badTldCap,
};

const HAZARD_REASONS: Record<string, string> = {
  missing_target: "No payee target was provided.",
  target_too_long: "Target is longer than 2048 characters.",
  unparsed: "Target could not be parsed as a domain, https URL, or 0x wallet.",
  invalid_wallet: "Wallet is not 0x followed by 40 hexadecimal characters.",
  burn_address: "Wallet is a burn or zero address.",
  non_https: "URL is not https. PayCheck will not treat an insecure URL as payable.",
  raw_ip: "Host is a raw IP address, not a domain name.",
  local_or_private: "Host is localhost or a private / link-local address.",
  url_userinfo: "URL contains userinfo (user:pass@host), which is a phishing shape.",
  unsupported_scheme: "URL scheme is not https.",
  bad_tld: "Top-level domain is on the PayCheck bad-TLD list.",
};

/**
 * Deterministic scorer. Do not add free-text inputs.
 * category, purpose, and amount_usd must never reach this function.
 */
export function scorePayee(input: {
  target: string | null | undefined;
  age: AgeInput;
  now: Date;
}): CheckResult {
  const parsed = parseTarget(input.target);
  const reasons: string[] = [];
  const codes: string[] = [];
  const caps: number[] = [];
  let hard = false;
  let forceSuspicious = false;
  let score = 100;

  const block = (code: string, cap: number, reason: string) => {
    hard = true;
    caps.push(cap);
    if (!codes.includes(code)) {
      codes.push(code);
      reasons.push(reason);
    }
  };

  if (parsed.kind === "invalid" || parsed.hazards.includes("missing_target") || parsed.hazards.includes("target_too_long") || parsed.hazards.includes("unparsed") || parsed.hazards.includes("invalid_wallet")) {
    for (const hazard of parsed.hazards) {
      block(hazard, HAZARD_CAPS[hazard] ?? SCORE.missingCap, HAZARD_REASONS[hazard] ?? hazard);
    }
  } else if (parsed.kind === "wallet") {
    if (parsed.burnAddress) {
      block("burn_address", SCORE.burnCap, HAZARD_REASONS.burn_address!);
    } else {
      score -= SCORE.walletCautionPenalty;
      codes.push("wallet_unanalyzed");
      reasons.push(
        "Wallet address is well formed, but PayCheck v1 does not trace on-chain history, sanctions, or mixer exposure. Treat it as unverified.",
      );
    }
  } else {
    for (const hazard of parsed.hazards) {
      block(hazard, HAZARD_CAPS[hazard] ?? SCORE.badTldCap, HAZARD_REASONS[hazard] ?? hazard);
    }
    if (parsed.denylisted && parsed.denyCode && parsed.denyCode !== "bad_tld") {
      const pattern = DENYLIST_PATTERNS.find((p) => p.code === parsed.denyCode);
      block(
        parsed.denyCode,
        SCORE.denylistCap,
        pattern?.reason ?? "Host is on the PayCheck denylist of obvious scam domains.",
      );
    }
    if (parsed.typosquatOf) {
      block(
        "typosquat",
        SCORE.typosquatCap,
        `Registrable label "${parsed.sld}" is a typosquat of allowlisted brand "${parsed.typosquatOf}" (${parsed.typosquatRule}).`,
      );
    }

    if (!hard && parsed.allowlisted) {
      codes.push("allowlisted");
      reasons.push(`Host ${parsed.host} is on the PayCheck allowlist of known AI and developer APIs.`);
    }

    if (!parsed.allowlisted && !hard) {
      applyAge(input.age, (n) => {
        score -= n;
      }, codes, reasons, (code, cap, reason) => block(code, cap, reason));
    }

    if (!parsed.allowlisted && !hard && input.age.status !== "not_applicable") {
      codes.push("not_allowlisted");
      reasons.push("Host is not on the known-merchant allowlist, so the verdict cannot be trusted.");
    }

    if (parsed.ens) {
      score -= SCORE.ensPenalty;
      forceSuspicious = true;
      codes.push("ens_unresolved");
      reasons.push("ENS .eth names are not resolved in v1. Pass the 0x address to score the wallet.");
    }

    if (parsed.hyphenCount >= SCORE.hyphenMinCount && !parsed.allowlisted) {
      score -= SCORE.hyphenPenalty;
      forceSuspicious = true;
      codes.push("hyphen_heavy");
      reasons.push(`Hostname contains ${parsed.hyphenCount} hyphens.`);
    }

    if (parsed.lookalike && !parsed.typosquatOf) {
      score -= SCORE.lookalikePenalty;
      forceSuspicious = true;
      codes.push("lookalike");
      reasons.push("Hostname is an internationalized domain (punycode). PayCheck treats IDNs as lookalike risk.");
    }

    if (parsed.impersonationOf) {
      score -= SCORE.impersonationPenalty;
      forceSuspicious = true;
      codes.push("brand_impersonation");
      reasons.push(
        `Hostname imitates allowlisted brand "${parsed.impersonationOf}" but is not that brand's domain.`,
      );
    }

    if (parsed.scheme === "https" && parsed.port !== null && parsed.port !== 443) {
      score -= SCORE.unusualPortPenalty;
      forceSuspicious = true;
      codes.push("unusual_port");
      reasons.push(`HTTPS port ${parsed.port} is not 443. Allowlist trust does not apply off port 443.`);
    }

    if (parsed.embeddedWallet) {
      score -= SCORE.embeddedWalletPenalty;
      forceSuspicious = true;
      codes.push("embedded_wallet");
      reasons.push(
        "The URL contains an embedded 0x address. PayCheck scored the host, not that wallet, and will not return trusted. Pass the bare 0x address to score the payee.",
      );
    }
  }

  score = clamp(Math.round(score), 0, 100);
  let verdict: Verdict;
  const httpsDefaultPort = parsed.scheme === "https" && (parsed.port === null || parsed.port === 443);
  const trustedEligible = parsed.allowlisted && httpsDefaultPort && !forceSuspicious && !parsed.embeddedWallet && !hard;

  if (hard) {
    score = Math.min(score, ...caps);
    verdict = "block";
  } else if (trustedEligible) {
    score = Math.max(score, SCORE.allowlistFloor);
    verdict = "trusted";
  } else if (forceSuspicious || score < SCORE.unknownMin) {
    if (forceSuspicious) score = Math.min(score, SCORE.suspiciousCap);
    verdict = score >= SCORE.suspiciousMin ? "suspicious" : "block";
  } else {
    verdict = "unknown";
  }

  score = clamp(score, 0, 100);

  return {
    score,
    verdict,
    reasons,
    recommended_action: ACTION[verdict],
    signals: signalsFor(parsed, input.age, codes, hard),
    checked_at: input.now.toISOString(),
    policy_version: POLICY_VERSION,
  };
}

function applyAge(
  age: AgeInput,
  penalize: (n: number) => void,
  codes: string[],
  reasons: string[],
  block: (code: string, cap: number, reason: string) => void,
) {
  if (age.status === "not_applicable" || age.status === "skipped_allowlist") return;
  if (age.status === "unknown") {
    penalize(SCORE.ageUnknownPenalty);
    codes.push("domain_age_unknown");
    reasons.push("Domain age lookup did not return a registration date. PayCheck does not invent an age.");
    return;
  }
  const days = age.days;
  if (days < 2) {
    block("domain_age_under_2_days", SCORE.ageUnder2Cap, `Domain age is ${days} days, under 2 days.`);
    return;
  }
  if (days < 7) {
    penalize(SCORE.ageUnder7Penalty);
    codes.push("domain_age_under_7_days");
    reasons.push(`Domain age is ${days} days, under 7 days.`);
    return;
  }
  if (days < 30) {
    penalize(SCORE.ageUnder30Penalty);
    codes.push("domain_age_under_30_days");
    reasons.push(`Domain age is ${days} days, under 30 days.`);
    return;
  }
  if (days < 180) {
    penalize(SCORE.ageUnder180Penalty);
    codes.push("domain_age_under_180_days");
    reasons.push(`Domain age is ${days} days.`);
    return;
  }
  codes.push("domain_age_mature");
  reasons.push(`Domain age is ${days} days.`);
}

function ageSource(age: AgeInput): CheckSignals["domain_age_source"] {
  if (age.status === "not_applicable") return "not_applicable";
  if (age.status === "skipped_allowlist") return "skipped_allowlist";
  return age.source;
}

function signalsFor(parsed: ParsedTarget, age: AgeInput, codes: string[], hard: boolean): CheckSignals {
  return {
    kind: parsed.kind,
    normalized_target: parsed.normalized,
    host: parsed.host,
    scheme: parsed.scheme,
    port: parsed.port,
    allowlisted: parsed.allowlisted,
    denylisted: parsed.denylisted,
    typosquat_of: parsed.typosquatOf,
    impersonation_of: parsed.impersonationOf,
    lookalike: parsed.lookalike,
    hyphen_count: parsed.hyphenCount,
    unsafe_shape: parsed.hazards[0] ?? null,
    domain_age_days: age.status === "known" ? age.days : null,
    domain_age_source: ageSource(age),
    wallet_valid: parsed.walletValid,
    burn_address: parsed.burnAddress,
    chain_analysis: "not_in_v1",
    embedded_wallet: parsed.embeddedWallet,
    hard_block: hard,
    reason_codes: codes,
    category_ignored: true,
    amount_ignored: true,
  };
}

export function needsDomainAge(target: string | null | undefined): boolean {
  const parsed = parseTarget(target);
  if (parsed.kind !== "domain") return false;
  if (parsed.allowlisted || parsed.ens) return false;
  if (parsed.hazards.length > 0) return false;
  if (parsed.denylisted || parsed.typosquatOf) return false;
  return true;
}

import { POLICY_VERSION } from "./version";

/**
 * Scoring policy v1.
 * Start at 100 and subtract penalties. Hard blocks set a score cap.
 * Free-text fields (category, purpose, amount_usd) are not inputs.
 * A verdict of trusted is possible only for an allowlisted https host on port 443.
 */

export { POLICY_VERSION };

export const SCORE = {
  allowlistFloor: 92,
  suspiciousCap: 69,
  unknownMin: 70,
  suspiciousMin: 40,
  ageUnder2Cap: 20,
  ageUnder7Penalty: 55,
  ageUnder30Penalty: 35,
  ageUnder180Penalty: 8,
  ageUnknownPenalty: 12,
  hyphenPenalty: 22,
  hyphenMinCount: 3,
  impersonationPenalty: 45,
  lookalikePenalty: 40,
  unusualPortPenalty: 15,
  embeddedWalletPenalty: 15,
  ensPenalty: 30,
  walletCautionPenalty: 20,
  missingCap: 5,
  invalidWalletCap: 0,
  burnCap: 0,
  nonHttpsCap: 12,
  rawIpCap: 8,
  localCap: 5,
  userinfoCap: 10,
  unsupportedSchemeCap: 10,
  badTldCap: 15,
  denylistCap: 5,
  typosquatCap: 8,
  idempotentWindowSeconds: 60,
  anonDaily: 100,
  keyDaily: 1000,
  bundleHexDaily: 1000,
  bundleAnonDaily: 100,
  keyMintsPerIpPerDay: 10,
  domainAgeCacheDays: 7,
  domainAgeFailureCacheHours: 24,
  maxTargetLength: 2048,
  priceUsd: "0.001",
  amountAtomic: "1000",
} as const;

/** Known-good AI and developer API hosts. Subdomains inherit trust. */
export const ALLOWLIST_DOMAINS: readonly string[] = [
  "openai.com",
  "anthropic.com",
  "stripe.com",
  "github.com",
  "cloudflare.com",
  "vercel.com",
  "supabase.com",
  "google.com",
  "googleapis.com",
  "microsoft.com",
  "azure.com",
  "amazon.com",
  "nvidia.com",
  "huggingface.co",
  "replicate.com",
  "groq.com",
  "mistral.ai",
  "cohere.com",
  "together.ai",
  "fireworks.ai",
  "openrouter.ai",
  "deepseek.com",
  "x.ai",
  "perplexity.ai",
  "notion.com",
  "slack.com",
  "linear.app",
  "sentry.io",
  "twilio.com",
  "npmjs.com",
  "docker.com",
  "gitlab.com",
  "atlassian.com",
  "shopify.com",
  "paypal.com",
  "coinbase.com",
  "etherscan.io",
  "alchemy.com",
  "infura.io",
  "cursor.com",
];

/** Obvious scam hosts. These are synthetic phishing names, not a live feed. */
export const DENYLIST_DOMAINS: readonly string[] = [
  "metamask-support.com",
  "metamask-wallet.io",
  "wallet-connect-secure.com",
  "claim-airdrop.com",
  "free-usdc.com",
  "openai-login.com",
  "stripe-secure-pay.com",
  "github-verify-login.com",
  "coinbase-wallet-secure.com",
];

/** Matched against the registrable label and the full hostname, hyphens removed. */
export const DENYLIST_PATTERNS: readonly { code: string; re: RegExp; reason: string }[] = [
  {
    code: "airdrop_bait",
    re: /airdrop/,
    reason: "Hostname matches an airdrop-bait pattern.",
  },
  {
    code: "seed_phrase",
    re: /seedphrase/,
    reason: "Hostname matches a seed-phrase phishing pattern.",
  },
  {
    code: "wallet_connect_phish",
    re: /walletconnect/,
    reason: "Hostname matches a wallet-connect phishing pattern.",
  },
  {
    code: "free_crypto",
    re: /free(usdc|eth|nft)/,
    reason: "Hostname matches a free-crypto bait pattern.",
  },
  {
    code: "claim_crypto",
    re: /claim(usdc|eth|nft|airdrop|reward)/,
    reason: "Hostname matches a claim-crypto bait pattern.",
  },
];

/** Freenom leftovers and TLDs that are commonly shipped as phishing lures. */
export const BAD_TLDS: readonly string[] = ["tk", "ml", "ga", "cf", "gq", "zip", "mov"];

/**
 * Multi-label public suffixes. The label under the suffix is the tenant,
 * so customer sites on vercel.app or github.io are not one shared domain.
 */
export const PUBLIC_SUFFIXES: readonly string[] = [
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.jp",
  "com.br",
  "com.mx",
  "co.nz",
  "co.za",
  "com.sg",
  "com.hk",
  "co.in",
  "com.tr",
  "vercel.app",
  "pages.dev",
  "workers.dev",
  "github.io",
  "netlify.app",
  "fly.dev",
  "herokuapp.com",
  "azurewebsites.net",
  "onrender.com",
];

export const BURN_ADDRESSES: readonly string[] = [
  "0x0000000000000000000000000000000000000000",
  "0x000000000000000000000000000000000000dead",
  "0xffffffffffffffffffffffffffffffffffffffff",
];

export const X402 = {
  version: 2 as const,
  scheme: "exact",
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  assetSymbol: "USDC",
  assetName: "USD Coin",
  assetVersion: "2",
  facilitator: "https://facilitator.payai.network",
  maxTimeoutSeconds: 60,
  priceUsd: SCORE.priceUsd,
  amountAtomic: SCORE.amountAtomic,
} as const;

export const RDAP_BASE = "https://rdap.org/domain/";

const BRAND_MIN = 5;

/** Second-level labels used for typosquat and impersonation checks. */
export function allowlistBrands(): string[] {
  const brands = new Set<string>();
  for (const domain of ALLOWLIST_DOMAINS) {
    const label = domain.split(".")[0];
    if (label && label.length >= BRAND_MIN) brands.add(label);
  }
  return [...brands];
}

export function policyDocument() {
  return {
    policy_version: POLICY_VERSION,
    service: "PayCheck",
    suite: "toolweather",
    summary:
      "Start at 100 and subtract the penalties below. Hard blocks cap the score and force verdict block. Verdict trusted is allowed only for an allowlisted host served over https on port 443. Wallets are never trusted in v1.",
    determinism:
      "amount_usd, category, purpose, and any other free-text field are discarded. They are not scored and they are not stored. Repeating a check with different wording cannot change the verdict.",
    does_not:
      "PayCheck does not send payments, does not sign transactions, and does not hold wallet keys. PAY_TO only receives the optional x402 micropayment for an over-cap check.",
    verdicts: {
      trusted: "Allowlisted https host on port 443. recommended_action proceed.",
      unknown: "No hard block and score >= 70, but not on the allowlist. recommended_action verify_out_of_band.",
      suspicious: "Score 40–69, or a soft signal such as a young domain, heavy hyphenation, or brand impersonation. recommended_action require_human_review.",
      block: "Hard rule or score under 40. recommended_action do_not_pay.",
    },
    hard_rules: [
      "Missing target caps the score at 5 and blocks.",
      "Non-https schemes, raw IP hosts, localhost, and private addresses block.",
      "URL userinfo (user:pass@host) blocks.",
      "Denylist domains, scam-name patterns, and bad TLDs block.",
      "Typosquats of allowlist brands block: homoglyph or leetspeak fold equal to the brand, one insertion or deletion, an adjacent transposition, or a confusable single-character substitution.",
      "Domain age under 2 days blocks (cap 20). Age is never invented. A failed RDAP lookup is unknown, not zero.",
      "A brand-new or random domain is never trusted, even with a high score.",
      "0x wallets: invalid hex blocks, burn and zero addresses block, every other address is unknown. There is no chain analysis in v1.",
    ],
    penalties: {
      age_under_2_days: { cap: SCORE.ageUnder2Cap, verdict: "block" },
      age_under_7_days: { subtract: SCORE.ageUnder7Penalty, effect: "suspicious" },
      age_under_30_days: { subtract: SCORE.ageUnder30Penalty, effect: "suspicious" },
      age_under_180_days: { subtract: SCORE.ageUnder180Penalty, effect: "small" },
      age_180_days_or_more: { subtract: 0, effect: "no age penalty; still not trusted unless allowlisted" },
      age_unknown: { subtract: SCORE.ageUnknownPenalty, effect: "unknown, not trusted" },
      hyphen_count_at_least_3: { subtract: SCORE.hyphenPenalty, effect: "forces suspicious (score capped at 69)" },
      brand_impersonation: { subtract: SCORE.impersonationPenalty, effect: "forces suspicious" },
      unicode_or_punycode_lookalike: { subtract: SCORE.lookalikePenalty, effect: "forces suspicious; homoglyph of a brand blocks" },
      unusual_port: { subtract: SCORE.unusualPortPenalty, effect: "not trusted; forces suspicious" },
      embedded_wallet_in_url: { subtract: SCORE.embeddedWalletPenalty, effect: "host is scored, not the address; cannot be trusted" },
      ens_name: { subtract: SCORE.ensPenalty, effect: ".eth is not resolved in v1; forces suspicious" },
      wallet_unanalyzed: { subtract: SCORE.walletCautionPenalty, effect: "unknown" },
      allowlist_floor: SCORE.allowlistFloor,
    },
    caps: {
      missing_target: SCORE.missingCap,
      invalid_wallet: SCORE.invalidWalletCap,
      burn_address: SCORE.burnCap,
      non_https: SCORE.nonHttpsCap,
      raw_ip: SCORE.rawIpCap,
      local_or_private: SCORE.localCap,
      url_userinfo: SCORE.userinfoCap,
      unsupported_scheme: SCORE.unsupportedSchemeCap,
      bad_tld: SCORE.badTldCap,
      denylist: SCORE.denylistCap,
      typosquat: SCORE.typosquatCap,
    },
    allowlist: ALLOWLIST_DOMAINS,
    denylist_domains: DENYLIST_DOMAINS,
    denylist_patterns: DENYLIST_PATTERNS.map((p) => ({ code: p.code, reason: p.reason })),
    bad_tlds: BAD_TLDS,
    wallet: {
      chain_analysis: "not_in_v1",
      checksum: "EIP-55 is not validated in v1. Any 40 hex characters are accepted.",
      burn_addresses: BURN_ADDRESSES,
    },
    domain_age: {
      source: "RDAP via https://rdap.org (public, no API key)",
      cache_ttl_days: SCORE.domainAgeCacheDays,
      failure_cache_ttl_hours: SCORE.domainAgeFailureCacheHours,
      never_invent_age: true,
      allowlist_skips_lookup: true,
    },
    quota: {
      anonymous_per_utc_day: SCORE.anonDaily,
      free_key_per_utc_day: SCORE.keyDaily,
      bundle_hex_client_per_utc_day: SCORE.bundleHexDaily,
      bundle_anon_prefix_per_utc_day: SCORE.bundleAnonDaily,
      key_mints_per_ip_per_utc_day: SCORE.keyMintsPerIpPerDay,
      idempotent_window_seconds: SCORE.idempotentWindowSeconds,
      billed_operation: "check_merchant and POST /v1/check only",
      free_operations: ["get_quota", "get_api_key", "GET /v1/policy", "GET /health", "docs", "MCP discovery"],
    },
    x402: {
      price_usd: X402.priceUsd,
      amount_atomic: X402.amountAtomic,
      asset: X402.asset,
      asset_symbol: X402.assetSymbol,
      network: X402.network,
      scheme: X402.scheme,
      facilitator: X402.facilitator,
      pay_to: "Worker secret PAY_TO. Unset deployments return 402 payment_not_configured.",
    },
    bundle: {
      secret_header: "x-tw-bundle-secret",
      client_header: "x-tw-bundle-client",
      secret_env: "BUNDLE_PROXY_SECRET",
      hex_client: "16 or more hex characters → 1,000/day",
      anon_prefix: "client id anon or anon:… → 100/day",
      other_client: "any other id → 100/day",
    },
  };
}

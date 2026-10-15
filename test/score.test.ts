import { describe, expect, it } from "vitest";
import { ALLOWLIST_DOMAINS, SCORE } from "../src/policy";
import { parseTarget, registrableDomain } from "../src/parse";
import { scorePayee, type AgeInput } from "../src/score";
import { decodePunycode } from "../src/text";

const NOW = new Date("2026-10-15T12:00:00.000Z");
const unknownAge: AgeInput = { status: "unknown", source: "unavailable" };
const skipped: AgeInput = { status: "skipped_allowlist" };
const known = (days: number): AgeInput => ({ status: "known", days, source: "rdap" });

function score(target: string | null | undefined, age: AgeInput = unknownAge) {
  return scorePayee({ target, age, now: NOW });
}

describe("policy constants", () => {
  it("publishes policy version 1 and a 40-host allowlist", () => {
    expect(ALLOWLIST_DOMAINS).toHaveLength(40);
    expect(new Set(ALLOWLIST_DOMAINS).size).toBe(40);
    expect(ALLOWLIST_DOMAINS).toContain("openai.com");
    expect(ALLOWLIST_DOMAINS).toContain("stripe.com");
    expect(ALLOWLIST_DOMAINS).toContain("github.com");
  });

  it("decodes the punycode test vector for bücher", () => {
    expect(decodePunycode("bcher-kva")).toBe("bücher");
  });
});

describe("scorePayee", () => {
  it("trusts https://api.openai.com with a high score", () => {
    const result = score("https://api.openai.com", skipped);
    expect(result.verdict).toBe("trusted");
    expect(result.score).toBeGreaterThanOrEqual(92);
    expect(result.recommended_action).toBe("proceed");
    expect(result.policy_version).toBe("1");
    expect(result.signals.allowlisted).toBe(true);
    expect(result.signals.chain_analysis).toBe("not_in_v1");
    expect(result.signals.domain_age_source).toBe("skipped_allowlist");
    expect(score("https://api.openai.com", known(0)).verdict).toBe("trusted");
  });

  it("trusts a bare allowlisted domain as https", () => {
    const result = score("stripe.com", skipped);
    expect(result.verdict).toBe("trusted");
    expect(result.signals.scheme).toBe("https");
  });

  it("blocks http://1.2.3.4", () => {
    const result = score("http://1.2.3.4");
    expect(result.verdict).toBe("block");
    expect(result.score).toBeLessThanOrEqual(15);
    expect(result.score).toBe(Math.min(SCORE.nonHttpsCap, SCORE.rawIpCap));
    expect(result.recommended_action).toBe("do_not_pay");
    expect(result.signals.reason_codes).toEqual(expect.arrayContaining(["non_https", "raw_ip"]));
  });

  it("blocks localhost, private IPs, and userinfo even on an allowlisted host", () => {
    expect(score("https://localhost/pay").verdict).toBe("block");
    expect(score("https://10.1.2.3").verdict).toBe("block");
    expect(score("http://192.168.1.20").verdict).toBe("block");
    expect(score("https://user:pass@api.openai.com/v1").verdict).toBe("block");
    expect(score("http://api.openai.com").verdict).toBe("block");
  });

  it("does not trust a young domain", () => {
    const result = score("https://brand-new-startup.io", known(3));
    expect(result.verdict).toBe("suspicious");
    expect(result.verdict).not.toBe("trusted");
    expect(result.score).toBe(100 - SCORE.ageUnder7Penalty);
    expect(result.signals.domain_age_days).toBe(3);
  });

  it("blocks domains younger than 2 days", () => {
    const result = score("https://born-yesterday.io", known(1));
    expect(result.verdict).toBe("block");
    expect(result.score).toBe(SCORE.ageUnder2Cap);
  });

  it("marks a mature unknown domain unknown, not trusted", () => {
    const result = score("https://quiet-ledger.example", known(400));
    expect(result.verdict).toBe("unknown");
    expect(result.score).toBe(100);
    expect(result.recommended_action).toBe("verify_out_of_band");
  });

  it("treats a failed age lookup as unknown and still not trusted", () => {
    const result = score("https://example.com", unknownAge);
    expect(result.verdict).toBe("unknown");
    expect(result.score).toBe(100 - SCORE.ageUnknownPenalty);
    expect(result.signals.domain_age_days).toBeNull();
    expect(result.reasons.join(" ")).toMatch(/does not invent/i);
  });

  it("treats a hyphen-heavy new-looking host as suspicious, not trusted", () => {
    const result = score("https://qz7k-pay-now-claim.biz", unknownAge);
    expect(["suspicious", "unknown", "block"]).toContain(result.verdict);
    expect(result.verdict).not.toBe("trusted");
    expect(result.signals.hyphen_count).toBeGreaterThanOrEqual(3);
  });

  it("blocks denylist hits, bad TLDs, and typosquats", () => {
    expect(score("https://openai-login.com", known(2000)).verdict).toBe("block");
    expect(score("https://invoice.zip", known(2000)).verdict).toBe("block");
    expect(score("https://openal.com", known(2000)).verdict).toBe("block");
    expect(score("https://paypa1.com", known(2000)).verdict).toBe("block");
    expect(score("https://stripee.com", known(2000)).signals.typosquat_of).toBe("stripe");
  });

  it("does not block an unrelated one-letter difference", () => {
    const result = score("https://black.com", known(400));
    expect(result.signals.typosquat_of).toBeNull();
    expect(result.verdict).not.toBe("block");
  });

  it("flags brand impersonation without calling it trusted", () => {
    const result = score("https://stripe-pay.com", known(400));
    expect(result.signals.impersonation_of).toBe("stripe");
    expect(result.verdict).toBe("suspicious");
  });

  it("blocks a missing target and invalid or burn wallets", () => {
    expect(score(null).verdict).toBe("block");
    expect(score("  ").score).toBeLessThanOrEqual(SCORE.missingCap);
    expect(score("0x1234").verdict).toBe("block");
    expect(score("0x0000000000000000000000000000000000000000").verdict).toBe("block");
    expect(score("0x000000000000000000000000000000000000dEaD").signals.burn_address).toBe(true);
  });

  it("scores a well-formed wallet as unknown, with no chain analysis", () => {
    const result = score("0x52908400098527886E0F7030069857D2E4169EE7");
    expect(result.verdict).toBe("unknown");
    expect(result.score).toBe(100 - SCORE.walletCautionPenalty);
    expect(result.signals.chain_analysis).toBe("not_in_v1");
    expect(result.signals.wallet_valid).toBe(true);
  });

  it("is deterministic for the same target and age", () => {
    const a = score("https://quiet-ledger.example", known(40));
    const b = score("https://quiet-ledger.example", known(40));
    expect(a).toEqual(b);
  });

  it("does not trust an allowlisted host when the URL embeds a wallet", () => {
    const result = score("https://etherscan.io/address/0x52908400098527886E0F7030069857D2E4169EE7", skipped);
    expect(result.verdict).not.toBe("trusted");
    expect(result.signals.embedded_wallet).toBe(true);
  });

  it("parses registrable domains under public suffixes", () => {
    expect(registrableDomain("shop.foo.vercel.app")).toBe("foo.vercel.app");
    expect(registrableDomain("api.openai.com")).toBe("openai.com");
    expect(registrableDomain("paypal.co.uk")).toBe("paypal.co.uk");
    expect(parseTarget("https://api.openai.com").allowlisted).toBe(true);
  });
});

import {
  ALLOWLIST_DOMAINS,
  BAD_TLDS,
  BURN_ADDRESSES,
  DENYLIST_DOMAINS,
  DENYLIST_PATTERNS,
  PUBLIC_SUFFIXES,
  allowlistBrands,
} from "./policy";
import { decodeHostname, skeleton, typosquatRule } from "./text";

export interface ParsedTarget {
  kind: "domain" | "wallet" | "invalid";
  normalized: string | null;
  host: string | null;
  displayHost: string | null;
  registrable: string | null;
  sld: string | null;
  scheme: string | null;
  port: number | null;
  allowlisted: boolean;
  denylisted: boolean;
  denyCode: string | null;
  typosquatOf: string | null;
  typosquatRule: string | null;
  impersonationOf: string | null;
  lookalike: boolean;
  hyphenCount: number;
  /** URL-shape problems. More than one can apply (http + raw IP). */
  hazards: string[];
  embeddedWallet: boolean;
  ens: boolean;
  walletValid: boolean | null;
  burnAddress: boolean;
  cacheKey: string;
}

const ALLOW = new Set(ALLOWLIST_DOMAINS);
const DENY = new Set(DENYLIST_DOMAINS);
const BAD = new Set(BAD_TLDS);
const SUFFIX = new Set(PUBLIC_SUFFIXES);
const BURN = new Set(BURN_ADDRESSES);

export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const last2 = labels.slice(-2).join(".");
  if (SUFFIX.has(last2)) return labels.slice(-3).join(".");
  return last2;
}

function isIpv4(host: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  return host.split(".").every((part) => {
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

function isPrivateIpv4(host: string): boolean {
  const [a, b] = host.split(".").map((p) => Number(p));
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b !== undefined && b >= 64 && b <= 127) return true;
  return false;
}

function isLocalName(host: string): boolean {
  return (
    host === "localhost" ||
    host === "localhost.localdomain" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".home") ||
    host.endsWith(".lan")
  );
}

function blank(cacheKey: string, extra: Partial<ParsedTarget> = {}): ParsedTarget {
  return {
    kind: "invalid",
    normalized: null,
    host: null,
    displayHost: null,
    registrable: null,
    sld: null,
    scheme: null,
    port: null,
    allowlisted: false,
    denylisted: false,
    denyCode: null,
    typosquatOf: null,
    typosquatRule: null,
    impersonationOf: null,
    lookalike: false,
    hyphenCount: 0,
    hazards: ["missing_target"],
    embeddedWallet: false,
    ens: false,
    walletValid: null,
    burnAddress: false,
    cacheKey,
    ...extra,
  };
}

export function parseTarget(raw: string | null | undefined): ParsedTarget {
  if (raw === null || raw === undefined || raw.trim() === "") return blank("invalid:missing");
  const trimmed = raw.trim();
  if (trimmed.length > 2048) {
    return blank("invalid:too_long", { hazards: ["target_too_long"] });
  }

  if (/^0x[0-9a-fA-F]{40}$/i.test(trimmed)) {
    const address = trimmed.toLowerCase();
    const burn = BURN.has(address);
    return blank(`wallet:${address}`, {
      kind: "wallet",
      normalized: address,
      hazards: burn ? ["burn_address"] : [],
      walletValid: true,
      burnAddress: burn,
      cacheKey: `wallet:${address}`,
    });
  }

  if (/^0x/i.test(trimmed)) {
    return blank(`invalid:wallet`, {
      hazards: ["invalid_wallet"],
      walletValid: false,
      cacheKey: `invalid:wallet:${skeleton(trimmed).slice(0, 64)}`,
    });
  }

  const schemeExplicit = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);
  let url: URL;
  try {
    url = new URL(schemeExplicit ? trimmed : `https://${trimmed}`);
  } catch {
    return blank("invalid:unparsed", { hazards: ["unparsed"] });
  }

  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host) {
    return blank("invalid:nohost", { scheme, hazards: ["unsupported_scheme"] });
  }

  const displayHost = decodeHostname(host);
  const port = url.port ? Number(url.port) : null;
  const hazards: string[] = [];
  if (scheme !== "http" && scheme !== "https") hazards.push("unsupported_scheme");
  if (scheme === "http") hazards.push("non_https");
  if (url.username || url.password) hazards.push("url_userinfo");
  if (isLocalName(host) || host === "::1" || host === "0:0:0:0:0:0:0:1") hazards.push("local_or_private");
  else if (isIpv4(host) && isPrivateIpv4(host)) hazards.push("local_or_private");
  else if (isIpv4(host) || (host.includes(":") && !host.includes("."))) hazards.push("raw_ip");
  else if (host.includes(":")) hazards.push("raw_ip");

  const tld = host.split(".").at(-1) ?? "";
  const registrable = isIpv4(host) || host.includes(":") ? host : registrableDomain(host);
  const sld = registrable.split(".")[0] ?? null;
  const hostOnAllowlist =
    ALLOW.has(host) || ALLOW.has(registrable) || ALLOWLIST_DOMAINS.some((domain) => host.endsWith(`.${domain}`));

  let denylisted = DENY.has(host) || DENY.has(registrable);
  let denyCode: string | null = denylisted ? "denylist_domain" : null;
  if (BAD.has(tld)) {
    denylisted = true;
    denyCode = denyCode ?? "bad_tld";
    hazards.push("bad_tld");
  }

  const foldedHost = skeleton(displayHost);
  const foldedSld = sld ? skeleton(decodeHostname(sld)) : "";
  if (!denylisted) {
    const hay = `${foldedHost}${foldedSld}`;
    for (const pattern of DENYLIST_PATTERNS) {
      if (pattern.re.test(hay)) {
        denylisted = true;
        denyCode = pattern.code;
        break;
      }
    }
  }

  let typosquatOf: string | null = null;
  let rule: string | null = null;
  let impersonationOf: string | null = null;
  if (!hostOnAllowlist && sld && !isIpv4(host) && !host.includes(":")) {
    const rawSld = decodeHostname(sld).toLowerCase();
    const candidate = skeleton(rawSld);
    for (const brand of allowlistBrands()) {
      if (candidate === brand && rawSld !== brand) {
        typosquatOf = brand;
        rule = "homoglyph";
        break;
      }
      const found = typosquatRule(candidate, brand);
      if (found) {
        typosquatOf = brand;
        rule = found;
        break;
      }
    }
    if (!typosquatOf) {
      for (const brand of allowlistBrands()) {
        for (const label of displayHost.split(".")) {
          const rawLabel = label.toLowerCase();
          const sk = skeleton(label);
          if (rawLabel === brand || (sk === brand && rawLabel !== brand)) {
            impersonationOf = brand;
            break;
          }
          if (!sk.includes(brand) || sk === brand) continue;
          if (sk.startsWith(brand) || sk.endsWith(brand)) {
            impersonationOf = brand;
            break;
          }
        }
        if (impersonationOf) break;
      }
    }
  }

  const allowlisted = hostOnAllowlist && hazards.length === 0 && !denylisted && !typosquatOf;
  const embeddedWallet = /0x[a-fA-F0-9]{40}/.test(`${url.pathname}${url.search}`);
  const ens = host === "eth" || host.endsWith(".eth");
  const lookalike = host.split(".").some((label) => label.startsWith("xn--"));
  const hyphenCount = (host.match(/-/g) ?? []).length;
  const cacheKey = `host:${scheme}:${host}:${port ?? ""}:${embeddedWallet ? "w" : "n"}`;

  return {
    kind: "domain",
    normalized: `${scheme}://${host}${port ? `:${port}` : ""}`,
    host,
    displayHost,
    registrable,
    sld,
    scheme,
    port,
    allowlisted,
    denylisted,
    denyCode,
    typosquatOf,
    typosquatRule: rule,
    impersonationOf,
    lookalike,
    hyphenCount,
    hazards,
    embeddedWallet,
    ens,
    walletValid: null,
    burnAddress: false,
    cacheKey,
  };
}

/** RFC 3492 punycode decoder for a single label (no xn-- prefix). */
export function decodePunycode(input: string): string {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = "-";

  function adapt(delta: number, numPoints: number, firstTime: boolean): number {
    let d = firstTime ? Math.floor(delta / damp) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > Math.floor(((base - tMin) * tMax) / 2)) {
      d = Math.floor(d / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * d) / (d + skew));
  }

  const output: number[] = [];
  let n = initialN;
  let i = 0;
  let bias = initialBias;
  let basic = input.lastIndexOf(delimiter);
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  let index = basic > 0 ? basic + 1 : 0;
  while (index < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (index >= input.length) throw new Error("punycode overflow");
      const c = input.charCodeAt(index++);
      let digit: number;
      if (c >= 48 && c <= 57) digit = c - 22;
      else if (c >= 65 && c <= 90) digit = c - 65;
      else if (c >= 97 && c <= 122) digit = c - 97;
      else throw new Error("punycode digit");
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

export function decodeHostname(host: string): string {
  return host
    .split(".")
    .map((label) => {
      if (!label.toLowerCase().startsWith("xn--")) return label;
      try {
        return decodePunycode(label.slice(4).toLowerCase());
      } catch {
        return label;
      }
    })
    .join(".");
}

const CONFUSABLES: Record<string, string> = {
  а: "a",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  х: "x",
  у: "y",
  і: "i",
  ї: "i",
  ј: "j",
  ѕ: "s",
  һ: "h",
  ɡ: "g",
  ο: "o",
  ν: "v",
  τ: "t",
  α: "a",
  ε: "e",
  ι: "i",
  κ: "k",
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "8": "b",
  "9": "g",
  "@": "a",
  $: "s",
};

/** Fold homoglyphs, leetspeak, and hyphens so openai and 0pen-ai compare equal. */
export function skeleton(value: string): string {
  const folded = value.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase();
  let out = "";
  for (const ch of folded) {
    if (ch === "-" || ch === "_" || ch === ".") continue;
    out += CONFUSABLES[ch] ?? ch;
  }
  return out;
}

export function visualFold(value: string): string {
  return skeleton(value).replace(/rn/g, "m").replace(/vv/g, "w");
}

const CONFUSABLE_GROUPS = ["il1|", "o0", "a@", "e3", "s5$", "t7+", "b8", "g9q"];

export function confusableChars(a: string, b: string): boolean {
  if (a === b) return true;
  return CONFUSABLE_GROUPS.some((group) => group.includes(a) && group.includes(b));
}

const KEYBOARD_NEIGHBORS: Record<string, string> = {
  q: "wa",
  w: "qeas",
  e: "wrds",
  r: "etdf",
  t: "ryfg",
  y: "tugh",
  u: "yihj",
  i: "uokj",
  o: "iplk",
  p: "ol",
  a: "qwsz",
  s: "weadzx",
  d: "ersfxc",
  f: "rtdgcv",
  g: "tyfhvb",
  h: "yugjbn",
  j: "uikhnm",
  k: "ioljm",
  l: "opk",
  z: "asx",
  x: "zsdc",
  c: "xdfv",
  v: "cfgb",
  b: "vghn",
  n: "bhjm",
  m: "njk",
};

export function keyboardAdjacent(a: string, b: string): boolean {
  return (KEYBOARD_NEIGHBORS[a] ?? "").includes(b);
}

/**
 * Conservative typosquat test.
 * True for homoglyph equality, one insertion or deletion, an adjacent swap,
 * or a single substitution that is confusable or a keyboard neighbor.
 * A random one-letter change such as black/slack is not a typosquat.
 */
export function typosquatRule(candidate: string, brand: string): string | null {
  if (!candidate || !brand || candidate === brand) return null;
  if (candidate.length < 5 || brand.length < 5) return null;
  if (visualFold(candidate) === visualFold(brand) || visualFold(candidate) === brand || candidate === visualFold(brand)) {
    return "homoglyph";
  }
  if (Math.abs(candidate.length - brand.length) > 1) return null;

  if (candidate.length === brand.length) {
    const diffs: number[] = [];
    for (let i = 0; i < candidate.length; i++) {
      if (candidate[i] !== brand[i]) diffs.push(i);
    }
    if (
      diffs.length === 2 &&
      diffs[1] === diffs[0]! + 1 &&
      candidate[diffs[0]!] === brand[diffs[1]!] &&
      candidate[diffs[1]!] === brand[diffs[0]!]
    ) {
      return "transposition";
    }
    if (diffs.length === 1) {
      const ca = candidate[diffs[0]!]!;
      const cb = brand[diffs[0]!]!;
      if (confusableChars(ca, cb) || keyboardAdjacent(ca, cb)) return "substitution";
    }
    return null;
  }

  const [shorter, longer] = candidate.length < brand.length ? [candidate, brand] : [brand, candidate];
  for (let i = 0; i < longer.length; i++) {
    if (shorter === longer.slice(0, i) + longer.slice(i + 1)) return "insertion";
  }
  return null;
}

export function utcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export function startOfUtcDay(date: Date): number {
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

export function nextUtcMidnight(date: Date): string {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() + 1)).toISOString();
}

export function ageInDays(registeredAt: string, now: Date): number | null {
  const registered = Date.parse(registeredAt);
  if (Number.isNaN(registered)) return null;
  const diff = now.getTime() - registered;
  if (diff < 0) return 0;
  return Math.floor(diff / 86_400_000);
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function safeEqual(a: string, b: string): boolean {
  const ae = new TextEncoder().encode(a);
  const be = new TextEncoder().encode(b);
  if (ae.length !== be.length) return false;
  let diff = 0;
  for (let i = 0; i < ae.length; i++) diff |= ae[i]! ^ be[i]!;
  return diff === 0;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64ToString(value: string): string {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

export function jsonBase64(value: unknown): string {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(value)));
}

export function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

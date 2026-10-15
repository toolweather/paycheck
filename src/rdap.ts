import { RDAP_BASE, SCORE } from "./policy";
import type { PaycheckStore } from "./store";
import { ageInDays } from "./text";

export interface AgeLookup {
  status: "unknown" | "known";
  days: number | null;
  source: "rdap" | "cache" | "unavailable";
}

const DAY_MS = 86_400_000;

export async function lookupDomainAge(
  registrable: string,
  store: PaycheckStore,
  fetchFn: typeof fetch,
  now: Date,
): Promise<AgeLookup> {
  const cached = await store.getDomainAge(registrable);
  if (cached) {
    const ageMs = now.getTime() - cached.fetchedAtMs;
    const ttl = cached.source === "rdap" && cached.registeredAt ? SCORE.domainAgeCacheDays * DAY_MS : SCORE.domainAgeFailureCacheHours * 3_600_000;
    if (ageMs >= 0 && ageMs < ttl) {
      if (cached.registeredAt) {
        const days = ageInDays(cached.registeredAt, now);
        if (days !== null) return { status: "known", days, source: "cache" };
      }
      return { status: "unknown", days: null, source: "cache" };
    }
  }

  try {
    const response = await fetchFn(`${RDAP_BASE}${encodeURIComponent(registrable)}`, {
      headers: {
        accept: "application/rdap+json, application/json",
        "user-agent": "PayCheck/1.0 (merchant trust check)",
      },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      await store.putDomainAge({
        host: registrable,
        registeredAt: null,
        source: "unavailable",
        fetchedAtMs: now.getTime(),
      });
      return { status: "unknown", days: null, source: "unavailable" };
    }
    const body: unknown = await response.json();
    const registeredAt = registrationDate(body);
    if (!registeredAt || ageInDays(registeredAt, now) === null) {
      await store.putDomainAge({
        host: registrable,
        registeredAt: null,
        source: "unavailable",
        fetchedAtMs: now.getTime(),
      });
      return { status: "unknown", days: null, source: "unavailable" };
    }
    await store.putDomainAge({
      host: registrable,
      registeredAt,
      source: "rdap",
      fetchedAtMs: now.getTime(),
    });
    return { status: "known", days: ageInDays(registeredAt, now), source: "rdap" };
  } catch {
    await store.putDomainAge({
      host: registrable,
      registeredAt: null,
      source: "unavailable",
      fetchedAtMs: now.getTime(),
    });
    return { status: "unknown", days: null, source: "unavailable" };
  }
}

function registrationDate(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const events = (body as { events?: unknown }).events;
  if (!Array.isArray(events)) return null;
  for (const event of events) {
    if (!event || typeof event !== "object") continue;
    const action = String((event as { eventAction?: unknown }).eventAction ?? "").toLowerCase();
    const date = (event as { eventDate?: unknown }).eventDate;
    if ((action === "registration" || action === "registered") && typeof date === "string") return date;
  }
  return null;
}

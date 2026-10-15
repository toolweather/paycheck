export interface DomainAgeRow {
  host: string;
  registeredAt: string | null;
  source: "rdap" | "unavailable";
  fetchedAtMs: number;
}

export interface CacheRow {
  responseJson: string;
  checkedAtMs: number;
}

export interface HistoryRow {
  checkedAtMs: number;
  subject: string;
  target: string;
  cacheKey: string;
  score: number;
  verdict: string;
  policyVersion: string;
  billing: string;
}

export interface KeyRow {
  hash: string;
  prefix: string;
  ownerIp: string;
  createdAtMs: number;
}

export interface PaycheckStore {
  getDomainAge(host: string): Promise<DomainAgeRow | null>;
  putDomainAge(row: DomainAgeRow): Promise<void>;
  getUsage(subject: string, day: string): Promise<number>;
  addUsage(subject: string, day: string, delta: number): Promise<number>;
  getCachedCheck(subject: string, cacheKey: string): Promise<CacheRow | null>;
  putCachedCheck(subject: string, cacheKey: string, checkedAtMs: number, responseJson: string): Promise<void>;
  insertHistory(row: HistoryRow): Promise<void>;
  insertKey(row: KeyRow): Promise<void>;
  countKeysSince(ownerIp: string, sinceMs: number): Promise<number>;
  hasKeyHash(hash: string): Promise<boolean>;
  hasNonce(nonce: string): Promise<boolean>;
  putNonce(nonce: string, payer: string, settledAtMs: number, txHash: string): Promise<void>;
}

export class MemoryStore implements PaycheckStore {
  ages = new Map<string, DomainAgeRow>();
  usage = new Map<string, number>();
  cache = new Map<string, CacheRow>();
  history: HistoryRow[] = [];
  keys: KeyRow[] = [];
  nonces = new Map<string, { payer: string; settledAtMs: number; txHash: string }>();

  async getDomainAge(host: string): Promise<DomainAgeRow | null> {
    return this.ages.get(host) ?? null;
  }
  async putDomainAge(row: DomainAgeRow): Promise<void> {
    this.ages.set(row.host, row);
  }
  async getUsage(subject: string, day: string): Promise<number> {
    return this.usage.get(`${subject}|${day}`) ?? 0;
  }
  async addUsage(subject: string, day: string, delta: number): Promise<number> {
    const key = `${subject}|${day}`;
    const next = (this.usage.get(key) ?? 0) + delta;
    this.usage.set(key, next);
    return next;
  }
  async getCachedCheck(subject: string, cacheKey: string): Promise<CacheRow | null> {
    return this.cache.get(`${subject}|${cacheKey}`) ?? null;
  }
  async putCachedCheck(subject: string, cacheKey: string, checkedAtMs: number, responseJson: string): Promise<void> {
    this.cache.set(`${subject}|${cacheKey}`, { checkedAtMs, responseJson });
  }
  async insertHistory(row: HistoryRow): Promise<void> {
    this.history.push(row);
  }
  async insertKey(row: KeyRow): Promise<void> {
    this.keys.push(row);
  }
  async countKeysSince(ownerIp: string, sinceMs: number): Promise<number> {
    return this.keys.filter((k) => k.ownerIp === ownerIp && k.createdAtMs >= sinceMs).length;
  }
  async hasKeyHash(hash: string): Promise<boolean> {
    return this.keys.some((k) => k.hash === hash);
  }
  async hasNonce(nonce: string): Promise<boolean> {
    return this.nonces.has(nonce.toLowerCase());
  }
  async putNonce(nonce: string, payer: string, settledAtMs: number, txHash: string): Promise<void> {
    this.nonces.set(nonce.toLowerCase(), { payer, settledAtMs, txHash });
  }
}

interface Prepared {
  bind(...values: unknown[]): Prepared;
  first<T>(): Promise<T | null>;
  run(): Promise<unknown>;
  all<T>(): Promise<{ results: T[] }>;
}

interface D1Like {
  prepare(sql: string): Prepared;
}

export class D1Store implements PaycheckStore {
  constructor(private readonly db: D1Like) {}

  async getDomainAge(host: string): Promise<DomainAgeRow | null> {
    const row = await this.db
      .prepare("SELECT host, registered_at, source, fetched_at_ms FROM domain_age WHERE host = ?")
      .bind(host)
      .first<{ host: string; registered_at: string | null; source: string; fetched_at_ms: number }>();
    if (!row) return null;
    return {
      host: row.host,
      registeredAt: row.registered_at,
      source: row.source === "rdap" ? "rdap" : "unavailable",
      fetchedAtMs: row.fetched_at_ms,
    };
  }

  async putDomainAge(row: DomainAgeRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO domain_age (host, registered_at, source, fetched_at_ms)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(host) DO UPDATE SET
           registered_at = excluded.registered_at,
           source = excluded.source,
           fetched_at_ms = excluded.fetched_at_ms`,
      )
      .bind(row.host, row.registeredAt, row.source, row.fetchedAtMs)
      .run();
  }

  async getUsage(subject: string, day: string): Promise<number> {
    const row = await this.db
      .prepare("SELECT checks FROM usage_daily WHERE subject = ? AND day = ?")
      .bind(subject, day)
      .first<{ checks: number }>();
    return row?.checks ?? 0;
  }

  async addUsage(subject: string, day: string, delta: number): Promise<number> {
    await this.db
      .prepare(
        `INSERT INTO usage_daily (subject, day, checks) VALUES (?, ?, ?)
         ON CONFLICT(subject, day) DO UPDATE SET checks = checks + ?`,
      )
      .bind(subject, day, delta, delta)
      .run();
    return this.getUsage(subject, day);
  }

  async getCachedCheck(subject: string, cacheKey: string): Promise<CacheRow | null> {
    const row = await this.db
      .prepare("SELECT response_json, checked_at_ms FROM check_cache WHERE subject = ? AND cache_key = ?")
      .bind(subject, cacheKey)
      .first<{ response_json: string; checked_at_ms: number }>();
    if (!row) return null;
    return { responseJson: row.response_json, checkedAtMs: row.checked_at_ms };
  }

  async putCachedCheck(subject: string, cacheKey: string, checkedAtMs: number, responseJson: string): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO check_cache (subject, cache_key, checked_at_ms, response_json)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(subject, cache_key) DO UPDATE SET
           checked_at_ms = excluded.checked_at_ms,
           response_json = excluded.response_json`,
      )
      .bind(subject, cacheKey, checkedAtMs, responseJson)
      .run();
  }

  async insertHistory(row: HistoryRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO check_history
         (checked_at_ms, subject, target, cache_key, score, verdict, policy_version, billing)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(row.checkedAtMs, row.subject, row.target, row.cacheKey, row.score, row.verdict, row.policyVersion, row.billing)
      .run();
  }

  async insertKey(row: KeyRow): Promise<void> {
    await this.db
      .prepare("INSERT INTO api_keys (key_hash, key_prefix, owner_ip, created_at_ms) VALUES (?, ?, ?, ?)")
      .bind(row.hash, row.prefix, row.ownerIp, row.createdAtMs)
      .run();
  }

  async countKeysSince(ownerIp: string, sinceMs: number): Promise<number> {
    const row = await this.db
      .prepare("SELECT COUNT(*) AS n FROM api_keys WHERE owner_ip = ? AND created_at_ms >= ?")
      .bind(ownerIp, sinceMs)
      .first<{ n: number }>();
    return row?.n ?? 0;
  }

  async hasKeyHash(hash: string): Promise<boolean> {
    const row = await this.db.prepare("SELECT 1 AS ok FROM api_keys WHERE key_hash = ?").bind(hash).first<{ ok: number }>();
    return Boolean(row);
  }

  async hasNonce(nonce: string): Promise<boolean> {
    const row = await this.db
      .prepare("SELECT 1 AS ok FROM payment_nonces WHERE nonce = ?")
      .bind(nonce.toLowerCase())
      .first<{ ok: number }>();
    return Boolean(row);
  }

  async putNonce(nonce: string, payer: string, settledAtMs: number, txHash: string): Promise<void> {
    await this.db
      .prepare("INSERT INTO payment_nonces (nonce, payer, settled_at_ms, tx_hash) VALUES (?, ?, ?, ?)")
      .bind(nonce.toLowerCase(), payer, settledAtMs, txHash)
      .run();
  }
}

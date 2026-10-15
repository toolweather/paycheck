-- PayCheck v1. Free-tier counters, domain-age cache, check history, key hashes.
-- API keys are stored as SHA-256 hashes. The plaintext pc_live_… value is shown once.

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash TEXT PRIMARY KEY,
  key_prefix TEXT NOT NULL,
  owner_ip TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_ip ON api_keys (owner_ip, created_at_ms);

CREATE TABLE IF NOT EXISTS usage_daily (
  subject TEXT NOT NULL,
  day TEXT NOT NULL,
  checks INTEGER NOT NULL,
  PRIMARY KEY (subject, day)
);

CREATE TABLE IF NOT EXISTS domain_age (
  host TEXT PRIMARY KEY,
  registered_at TEXT,
  source TEXT NOT NULL,
  fetched_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS check_cache (
  subject TEXT NOT NULL,
  cache_key TEXT NOT NULL,
  checked_at_ms INTEGER NOT NULL,
  response_json TEXT NOT NULL,
  PRIMARY KEY (subject, cache_key)
);

CREATE TABLE IF NOT EXISTS check_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  checked_at_ms INTEGER NOT NULL,
  subject TEXT NOT NULL,
  target TEXT NOT NULL,
  cache_key TEXT NOT NULL,
  score INTEGER NOT NULL,
  verdict TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  billing TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_checked ON check_history (checked_at_ms);

CREATE TABLE IF NOT EXISTS payment_nonces (
  nonce TEXT PRIMARY KEY,
  payer TEXT,
  settled_at_ms INTEGER NOT NULL,
  tx_hash TEXT
);

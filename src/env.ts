export interface Env {
  DB: D1Database;
  ASSETS?: Fetcher;
  PAY_TO?: string;
  BUNDLE_PROXY_SECRET?: string;
}

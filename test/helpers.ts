import { createApp } from "../src/http";
import type { Env } from "../src/env";
import { MemoryStore } from "../src/store";

export function rdapFetch(registeredAt: string | null, calls?: { n: number }): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("rdap.org")) {
      if (calls) calls.n += 1;
      if (!registeredAt) return new Response("missing", { status: 404 });
      return new Response(
        JSON.stringify({ events: [{ eventAction: "registration", eventDate: registeredAt }] }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.includes("facilitator.payai.network")) {
      const body = {
        isValid: true,
        success: true,
        payer: "0x2222222222222222222222222222222222222222",
        transaction: "0xabc123",
        network: "eip155:8453",
      };
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("no", { status: 404 });
  }) as typeof fetch;
}

export function testApp(opts?: {
  payTo?: string;
  bundleSecret?: string;
  fetchFn?: typeof fetch;
  now?: Date;
}) {
  const store = new MemoryStore();
  const env = {
    DB: {} as Env["DB"],
    ASSETS: undefined,
    PAY_TO: opts?.payTo ?? "",
    BUNDLE_PROXY_SECRET: opts?.bundleSecret ?? "",
  } as Env;
  const app = createApp({
    resolveStore: () => store,
    fetchFn: opts?.fetchFn ?? rdapFetch(null),
    now: () => opts?.now ?? new Date("2026-10-15T12:00:00.000Z"),
  });
  return { app, env, store };
}

export function postCheck(
  app: ReturnType<typeof testApp>["app"],
  env: Env,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
) {
  return app.request("http://paycheck.test/v1/check", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.10", ...headers },
    body: JSON.stringify(body),
  }, env);
}

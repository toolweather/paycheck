import { Hono } from "hono";
import { llmsFull, llmsTxt, mcpDiscovery, openApiDocument, x402Discovery } from "./docs";
import type { Env } from "./env";
import { clientIp, readApiKey } from "./identity";
import { acceptsMcp, dispatchMcp, unsupportedProtocol } from "./mcp";
import { policyDocument } from "./policy";
import { mintApiKey, performCheck, readQuota, type CheckRequest } from "./service";
import { D1Store, type PaycheckStore } from "./store";
import { POLICY_VERSION, SERVICE_NAME, VERSION } from "./version";

export interface AppOptions {
  resolveStore?: (env: Env) => PaycheckStore;
  fetchFn?: typeof fetch;
  now?: () => Date;
}

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
  "access-control-allow-headers":
    "content-type, accept, authorization, x-api-key, mcp-protocol-version, mcp-session-id, payment-signature, x-payment, x-tw-bundle-secret, x-tw-bundle-client",
  "access-control-expose-headers": "payment-required, payment-response, mcp-protocol-version",
};

function blank(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function headerOrNull(c: { req: { header: (name: string) => string | undefined } }, name: string): string | null {
  const value = c.req.header(name);
  return value === undefined ? null : value;
}

export function createApp(options: AppOptions = {}) {
  const app = new Hono<{ Bindings: Env; Variables: { store: PaycheckStore } }>();
  const fetchFn = options.fetchFn ?? fetch;
  const nowFn = options.now ?? (() => new Date());

  app.use("*", async (c, next) => {
    await next();
    for (const [key, value] of Object.entries(CORS)) c.header(key, value);
  });

  app.options("*", (c) => c.body(null, 204));

  app.use("*", async (c, next) => {
    const store = options.resolveStore ? options.resolveStore(c.env) : new D1Store(c.env.DB);
    c.set("store", store);
    await next();
  });

  app.get("/health", (c) =>
    c.json({
      ok: true,
      service: SERVICE_NAME.toLowerCase(),
      version: VERSION,
      policy_version: POLICY_VERSION,
    }),
  );

  app.get("/v1/policy", (c) => c.json(policyDocument()));
  app.get("/openapi.json", (c) => c.json(openApiDocument(new URL(c.req.url).origin)));
  app.get("/llms.txt", (c) => c.text(llmsTxt(new URL(c.req.url).origin)));
  app.get("/llms-full.txt", (c) => c.text(llmsFull(new URL(c.req.url).origin)));
  app.get("/.well-known/mcp", (c) => c.json(mcpDiscovery(new URL(c.req.url).origin)));
  app.get("/.well-known/mcp.json", (c) => c.json(mcpDiscovery(new URL(c.req.url).origin)));
  app.get("/.well-known/x402", (c) => c.json(x402Discovery(Boolean(blank(c.env.PAY_TO)))));

  app.get("/v1/quota", async (c) => {
    const url = new URL(c.req.url);
    const result = await readQuota({
      store: c.get("store"),
      apiKey: readApiKey(c.req.raw.headers, url.searchParams.get("api_key")),
      bundleSecretHeader: headerOrNull(c, "x-tw-bundle-secret"),
      bundleClientHeader: headerOrNull(c, "x-tw-bundle-client"),
      ip: clientIp(c.req.raw.headers),
      payTo: blank(c.env.PAY_TO),
      bundleSecret: blank(c.env.BUNDLE_PROXY_SECRET),
      now: nowFn(),
    });
    if (result.type === "error") return c.json(result.body, result.status as 400);
    return c.json(result.body);
  });

  app.post("/v1/keys", async (c) => {
    const minted = await mintApiKey({
      store: c.get("store"),
      ip: clientIp(c.req.raw.headers),
      now: nowFn(),
    });
    if (minted.type === "error") return c.json(minted.body, minted.status as 429);
    return c.json(minted.body, 201);
  });

  app.post("/v1/check", async (c) => {
    const body = await readJson(c);
    if (!body.ok) return c.json(body.body, 400);
    const record = body.value;
    const outcome = await performCheck(checkRequest(c, record, fetchFn, nowFn));
    return sendOutcome(c, outcome);
  });

  app.post("/mcp", async (c) => {
    if (!acceptsMcp(c.req.header("accept") ?? null)) {
      return c.json({ error: "not_acceptable", message: "Accept must include application/json or text/event-stream." }, 406);
    }
    const body = await readJson(c);
    if (!body.ok) return c.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
    const method = body.value && typeof body.value.method === "string" ? body.value.method : "";
    if (method !== "initialize" && unsupportedProtocol(c.req.header("mcp-protocol-version") ?? null)) {
      return c.json({ error: "unsupported_protocol_version", supported: ["2025-06-18", "2025-03-26"] }, 400);
    }
    const dispatched = await dispatchMcp(body.value, {
      check: checkRequest(c, {}, fetchFn, nowFn),
    });
    if (dispatched.type === "none") return c.body(null, 202);
    if (dispatched.type === "http") {
      const response = c.json(dispatched.body, dispatched.status as 200);
      for (const [key, value] of Object.entries(dispatched.headers ?? {})) response.headers.set(key, value);
      return response;
    }
    return c.json(dispatched.body);
  });

  app.get("/mcp", (c) => c.json({ error: "method_not_allowed", message: "This stateless MCP endpoint accepts POST." }, 405));
  app.delete("/mcp", (c) => c.json({ error: "method_not_allowed", message: "PayCheck MCP is stateless and has no session to delete." }, 405));

  app.all("*", async (c) => {
    if (c.env.ASSETS && c.req.method === "GET") {
      return c.env.ASSETS.fetch(c.req.raw);
    }
    return c.json({ error: "not_found" }, 404);
  });

  app.onError((err, c) => {
    console.error(err instanceof Error ? err.message : "internal_error");
    return c.json({ error: "internal_error" }, 500);
  });

  return app;
}

function checkRequest(
  c: {
    req: { url: string; raw: Request; header: (name: string) => string | undefined };
    env: Env;
    get: (key: "store") => PaycheckStore;
  },
  record: Record<string, unknown>,
  fetchFn: typeof fetch,
  nowFn: () => Date,
): CheckRequest {
  return {
    store: c.get("store"),
    target: record.target,
    amountUsd: record.amount_usd,
    category: record.category,
    apiKey: readApiKey(c.req.raw.headers, record.api_key),
    bundleSecretHeader: headerOrNull(c, "x-tw-bundle-secret"),
    bundleClientHeader: headerOrNull(c, "x-tw-bundle-client"),
    ip: clientIp(c.req.raw.headers),
    payTo: blank(c.env.PAY_TO),
    bundleSecret: blank(c.env.BUNDLE_PROXY_SECRET),
    fetchFn,
    now: nowFn(),
    resourceUrl: new URL(c.req.url).toString(),
    paymentSignatureHeader: headerOrNull(c, "payment-signature"),
    xPaymentHeader: headerOrNull(c, "x-payment"),
  };
}

async function readJson(
  c: { req: { json: () => Promise<unknown> } },
): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; body: Record<string, unknown> }> {
  try {
    const value = await c.req.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { ok: false, body: { error: "invalid_json", message: "Body must be a JSON object." } };
    }
    return { ok: true, value: value as Record<string, unknown> };
  } catch {
    return { ok: false, body: { error: "invalid_json", message: "Body must be JSON." } };
  }
}

function sendOutcome(
  c: { json: (body: unknown, status?: number) => Response },
  outcome: Awaited<ReturnType<typeof performCheck>>,
): Response {
  if (outcome.type === "error") return c.json(outcome.body, outcome.status);
  if (outcome.type === "payment") {
    const response = c.json(outcome.challenge.body, 402);
    for (const [key, value] of Object.entries(outcome.challenge.headers)) response.headers.set(key, value);
    return response;
  }
  const response = c.json(outcome.body, 200);
  if (outcome.paymentResponseHeader) response.headers.set("PAYMENT-RESPONSE", outcome.paymentResponseHeader);
  return response;
}

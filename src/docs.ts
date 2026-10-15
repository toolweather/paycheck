import { policyDocument, X402 } from "./policy";
import { TOOLS } from "./tools";
import { SERVICE_NAME, VERSION } from "./version";

export function openApiDocument(origin: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: SERVICE_NAME,
      version: VERSION,
      summary: "Deterministic payee trust scores for agents. Does not send payments or hold wallet keys.",
      description:
        "PayCheck is part of the Toolweather suite. POST /v1/check scores a domain, https URL, or 0x wallet. Anonymous callers get 100 checks per UTC day. A free pc_live_ key gets 1,000. Over-cap checks cost $0.001 USDC on Base via x402. Category, purpose, and amount do not change the score.",
      license: { name: "MIT" },
    },
    servers: [{ url: origin }],
    paths: {
      "/health": { get: { operationId: "health", summary: "Liveness", responses: { "200": { description: "ok" } } } },
      "/v1/policy": {
        get: { operationId: "policy", summary: "Scoring policy v1", responses: { "200": { description: "Policy document" } } },
      },
      "/v1/quota": {
        get: {
          operationId: "quota",
          summary: "Remaining free checks today. Not billed.",
          parameters: [
            { name: "api_key", in: "query", required: false, schema: { type: "string" } },
            { name: "X-API-Key", in: "header", required: false, schema: { type: "string" } },
          ],
          responses: { "200": { description: "Quota" }, "401": { description: "Invalid key or bundle secret" } },
        },
      },
      "/v1/keys": {
        post: {
          operationId: "mintKey",
          summary: "Mint a free pc_live_ key. Not billed. Limited to 10 per IP per UTC day.",
          responses: { "201": { description: "Key minted" }, "429": { description: "Mint limit" } },
        },
      },
      "/v1/check": {
        post: {
          operationId: "check",
          summary: "Score one payee. Free under the daily cap, otherwise x402.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["target"],
                  properties: {
                    target: { type: "string" },
                    amount_usd: { type: "number", minimum: 0 },
                    category: { type: "string" },
                    api_key: { type: "string" },
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Score, verdict, reasons, recommended_action, signals, checked_at" },
            "402": { description: "Over free quota. payment_not_configured, or x402 payment required." },
          },
        },
      },
      "/mcp": {
        post: {
          operationId: "mcp",
          summary: "MCP streamable HTTP (protocol 2025-06-18 and 2025-03-26).",
          responses: { "200": { description: "JSON-RPC" }, "202": { description: "Notification accepted" } },
        },
      },
    },
  };
}

export function llmsTxt(origin: string): string {
  return `# PayCheck

> Deterministic trust score for a payee (domain, https URL, or 0x wallet) before an agent sends money. Part of the Toolweather suite. PayCheck does not send payments and does not hold wallet keys.

## When to use

Call PayCheck once per payee, immediately before a payment. Do not reword the purpose to fish for a better verdict. amount_usd and category are ignored.

## Endpoints

- [Policy v1](${origin}/v1/policy): scoring rules, allowlist, denylist, quota, x402 price
- [OpenAPI](${origin}/openapi.json): REST contract
- [MCP discovery](${origin}/.well-known/mcp.json): streamable HTTP tools
- [x402 discovery](${origin}/.well-known/x402): Base USDC overage price
- MCP: ${origin}/mcp (protocols 2025-06-18 and 2025-03-26)
- Check: POST ${origin}/v1/check
- Quota: GET ${origin}/v1/quota (free)
- Key: POST ${origin}/v1/keys (free, pc_live_…)

## Tools

${TOOLS.map((tool) => `- ${tool.name}: ${tool.title}`).join("\n")}

## Free tier

- Anonymous: 100 checks / UTC day
- Free key or bundle hex client: 1,000 checks / UTC day
- Bundle anon: client: 100 checks / UTC day
- Over-cap check: $0.001 USDC on Base (eip155:8453) via x402
- get_quota, get_api_key, docs, and discovery are not billed

## Verdicts

trusted, unknown, suspicious, block. Trusted only for the published allowlist over https on port 443. Wallets are never trusted in v1 (no chain analysis).
`;
}

export function llmsFull(origin: string): string {
  const policy = policyDocument();
  return `${llmsTxt(origin)}

## Scoring summary

${policy.summary}

${policy.determinism}

${policy.does_not}

### Hard rules

${policy.hard_rules.map((rule) => `- ${rule}`).join("\n")}

### Allowlist

${policy.allowlist.map((host) => `- ${host}`).join("\n")}

## Tool descriptions

${TOOLS.map((tool) => `### ${tool.name}\n\n${tool.description}\n`).join("\n")}

## x402

- Price: ${X402.priceUsd} USDC (${X402.amountAtomic} atomic units)
- Asset: ${X402.asset}
- Network: ${X402.network}
- Scheme: ${X402.scheme}
- Facilitator: ${X402.facilitator}
- If PAY_TO is unset, over-cap responses use error payment_not_configured and no charge is attempted.

## Suite

PayCheck sits beside Toolweather MCP health, Upstream, and SpendGate. SpendGate is for spend limits. PayCheck is only the payee trust check. The Toolweather bundle can front this API later with x-tw-bundle-secret and x-tw-bundle-client.
`;
}

export function mcpDiscovery(origin: string) {
  return {
    name: SERVICE_NAME,
    version: VERSION,
    description: "Deterministic payee trust scores before an agent sends money. Does not send payments or hold keys.",
    protocol_versions: ["2025-06-18", "2025-03-26"],
    transport: "streamable-http",
    endpoint: `${origin}/mcp`,
    tools: TOOLS.map((tool) => tool.name),
    suite: "toolweather",
    docs: `${origin}/llms.txt`,
    policy: `${origin}/v1/policy`,
    openapi: `${origin}/openapi.json`,
  };
}

export function x402Discovery(payToConfigured: boolean) {
  return {
    x402Version: X402.version,
    facilitator: X402.facilitator,
    scheme: X402.scheme,
    network: X402.network,
    asset: X402.asset,
    asset_symbol: X402.assetSymbol,
    price_usd: X402.priceUsd,
    amount_atomic: X402.amountAtomic,
    pay_to_configured: payToConfigured,
    billed_routes: ["POST /v1/check", "tools/call check_merchant"],
    free_routes: [
      "GET /v1/quota",
      "POST /v1/keys",
      "GET /v1/policy",
      "GET /health",
      "tools/call get_quota",
      "tools/call get_api_key",
      "GET /llms.txt",
      "GET /.well-known/mcp",
    ],
    over_cap_without_pay_to: "402 payment_not_configured",
  };
}

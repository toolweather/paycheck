import { mintApiKey, performCheck, readQuota, type CheckRequest } from "./service";
import { TOOLS, toolByName } from "./tools";
import { SERVICE_NAME, VERSION } from "./version";

export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26"] as const;

const INSTRUCTIONS = [
  "PayCheck scores whether a domain, https URL, or 0x wallet is safe to pay before you send money.",
  "It does not send payments and it does not hold wallet keys.",
  "Call check_merchant once per payee. Call get_api_key only when you need a free pc_live_ key, not every turn.",
  "Call get_quota to see remaining free checks. Scores are deterministic: rewording purpose, category, or amount does not change the verdict.",
  "policy_version is 1. A domain is trusted only when it is on the published allowlist.",
].join(" ");

export interface McpDeps {
  check: CheckRequest;
}

export type McpDispatch =
  | { type: "none" }
  | { type: "rpc"; body: unknown }
  | { type: "http"; status: number; body: unknown; headers?: Record<string, string> };

export function negotiateProtocol(requested: unknown): string {
  if (typeof requested === "string" && (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)) {
    return requested;
  }
  return "2025-06-18";
}

export function unsupportedProtocol(header: string | null | undefined): boolean {
  if (!header) return false;
  return !(SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(header);
}

export async function dispatchMcp(message: unknown, deps: McpDeps): Promise<McpDispatch> {
  if (Array.isArray(message)) {
    return { type: "rpc", body: rpcError(null, -32600, "JSON-RPC batches are not supported.") };
  }
  if (!message || typeof message !== "object") {
    return { type: "rpc", body: rpcError(null, -32600, "Invalid JSON-RPC request.") };
  }
  const msg = message as { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return { type: "rpc", body: rpcError(msg.id ?? null, -32600, "Invalid JSON-RPC request.") };
  }
  const id = msg.id;
  const isNotification = id === undefined;

  if (msg.method === "notifications/initialized" || msg.method === "notifications/cancelled") {
    return { type: "none" };
  }
  if (msg.method.startsWith("notifications/")) return { type: "none" };

  if (msg.method === "initialize") {
    const params = (msg.params ?? {}) as { protocolVersion?: unknown; clientInfo?: unknown };
    return {
      type: "rpc",
      body: {
        jsonrpc: "2.0",
        id: id ?? null,
        result: {
          protocolVersion: negotiateProtocol(params.protocolVersion),
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: SERVICE_NAME, version: VERSION },
          instructions: INSTRUCTIONS,
        },
      },
    };
  }

  if (msg.method === "ping") {
    return { type: "rpc", body: { jsonrpc: "2.0", id: id ?? null, result: {} } };
  }

  if (msg.method === "tools/list") {
    return {
      type: "rpc",
      body: {
        jsonrpc: "2.0",
        id: id ?? null,
        result: {
          tools: TOOLS.map((tool) => ({
            name: tool.name,
            title: tool.title,
            description: tool.description,
            inputSchema: tool.inputSchema,
            annotations: tool.annotations,
          })),
        },
      },
    };
  }

  if (msg.method === "tools/call") {
    if (isNotification) return { type: "none" };
    const params = (msg.params ?? {}) as { name?: unknown; arguments?: unknown };
    if (typeof params.name !== "string") {
      return { type: "rpc", body: rpcError(id, -32602, "tools/call requires a tool name.") };
    }
    const tool = toolByName(params.name);
    if (!tool) return { type: "rpc", body: rpcError(id, -32602, `Unknown tool: ${params.name}`) };
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    if (args && typeof args !== "object") {
      return { type: "rpc", body: rpcError(id, -32602, "Tool arguments must be an object.") };
    }
    return callTool(id, tool.name, args, deps);
  }

  if (isNotification) return { type: "none" };
  return { type: "rpc", body: rpcError(id, -32601, `Method not found: ${msg.method}`) };
}

async function callTool(id: unknown, name: string, args: Record<string, unknown>, deps: McpDeps): Promise<McpDispatch> {
  if (name === "get_quota") {
    const quota = await readQuota({
      store: deps.check.store,
      apiKey: typeof args.api_key === "string" ? args.api_key : deps.check.apiKey,
      bundleSecretHeader: deps.check.bundleSecretHeader,
      bundleClientHeader: deps.check.bundleClientHeader,
      ip: deps.check.ip,
      payTo: deps.check.payTo,
      bundleSecret: deps.check.bundleSecret,
      now: deps.check.now,
    });
    if (quota.type === "error") {
      return { type: "http", status: quota.status, body: quota.body };
    }
    return { type: "rpc", body: toolResult(id, quota.body, false) };
  }

  if (name === "get_api_key") {
    const minted = await mintApiKey({ store: deps.check.store, ip: deps.check.ip, now: deps.check.now });
    if (minted.type === "error") return { type: "rpc", body: toolResult(id, minted.body, true) };
    return { type: "rpc", body: toolResult(id, minted.body, false) };
  }

  const outcome = await performCheck({
    ...deps.check,
    target: args.target,
    amountUsd: args.amount_usd,
    category: args.category,
    apiKey: typeof args.api_key === "string" ? args.api_key : deps.check.apiKey,
  });
  if (outcome.type === "error") return { type: "http", status: outcome.status, body: outcome.body };
  if (outcome.type === "payment") {
    return {
      type: "http",
      status: 402,
      body: outcome.challenge.body,
      headers: outcome.challenge.headers,
    };
  }
  const headers = outcome.paymentResponseHeader ? { "PAYMENT-RESPONSE": outcome.paymentResponseHeader } : undefined;
  return { type: "http", status: 200, body: toolResult(id, outcome.body, false), headers };
}

function toolResult(id: unknown, payload: unknown, isError: boolean) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
      structuredContent: payload,
      isError,
    },
  };
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export function acceptsMcp(accept: string | null): boolean {
  if (!accept || accept.trim() === "" || accept.includes("*/*")) return true;
  return accept.includes("application/json") || accept.includes("text/event-stream");
}

import { MemoryStore } from "./store";
import { dispatchMcp, type McpDeps } from "./mcp";

interface StdioProcess {
  stdin: {
    on(event: "data", cb: (chunk: Uint8Array | string) => void): void;
    on(event: "end", cb: () => void): void;
    resume(): void;
  };
  stdout: { write(chunk: string): boolean };
  stderr: { write(chunk: string): boolean };
  env: Record<string, string | undefined>;
}

function getProcess(): StdioProcess {
  return (globalThis as unknown as { process: StdioProcess }).process;
}

const MAX_BUFFER = 1_048_576;

/** One JSON-RPC object plus a newline. Glama's mcp-proxy reads this, not Content-Length frames. */
export function encodeNdjson(message: unknown): string {
  return `${JSON.stringify(message)}\n`;
}

/**
 * Accept newline-delimited JSON-RPC and LSP-style Content-Length frames.
 * Incomplete input stays in `rest` until the next chunk.
 */
export function takeStdioMessages(buffer: string): { messages: unknown[]; rest: string } {
  const messages: unknown[] = [];
  let rest = buffer;
  while (rest.length > 0) {
    if (/^content-length:/i.test(rest)) {
      const match = /\r?\n\r?\n/.exec(rest);
      if (!match || match.index === undefined) break;
      const header = rest.slice(0, match.index);
      const lengthMatch = /content-length:\s*(\d+)/i.exec(header);
      const bodyStart = match.index + match[0].length;
      if (!lengthMatch) {
        rest = rest.slice(bodyStart);
        continue;
      }
      const length = Number(lengthMatch[1]);
      const decoded = sliceUtf8(rest.slice(bodyStart), length);
      if (!decoded) break;
      rest = decoded.tail;
      try {
        messages.push(JSON.parse(decoded.head));
      } catch {
        // Drop a framed body that is not JSON and keep reading.
      }
      continue;
    }

    const nl = rest.indexOf("\n");
    if (nl === -1) break;
    const line = rest.slice(0, nl).replace(/\r$/, "").trim();
    rest = rest.slice(nl + 1);
    if (!line) continue;
    try {
      messages.push(JSON.parse(line));
    } catch {
      // A non-JSON banner on the stream is not a JSON-RPC message.
    }
  }
  return { messages, rest };
}

function sliceUtf8(value: string, byteLength: number): { head: string; tail: string } | null {
  if (!Number.isFinite(byteLength) || byteLength < 0) return { head: "", tail: value };
  const bytes = new TextEncoder().encode(value);
  if (bytes.length < byteLength) return null;
  const decoder = new TextDecoder();
  return {
    head: decoder.decode(bytes.slice(0, byteLength)),
    tail: decoder.decode(bytes.slice(byteLength)),
  };
}

function stdioBody(message: unknown, result: { type: "rpc" | "http"; body: unknown; status?: number }): unknown {
  if (result.type === "rpc") return result.body;
  if (result.body && typeof result.body === "object" && "jsonrpc" in result.body) return result.body;
  const id = message && typeof message === "object" && "id" in message ? (message as { id?: unknown }).id ?? null : null;
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: JSON.stringify(result.body, null, 2) }],
      structuredContent: result.body,
      isError: (result.status ?? 500) >= 400,
    },
  };
}

async function main() {
  const proc = getProcess();
  const store = new MemoryStore();
  const decoder = new TextDecoder();
  proc.stderr.write("PayCheck MCP stdio listening\n");
  let buffer = "";
  let chain: Promise<void> = Promise.resolve();
  proc.stdin.resume();
  proc.stdin.on("data", (chunk) => {
    buffer += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
    if (buffer.length > MAX_BUFFER) {
      buffer = "";
      proc.stdout.write(encodeNdjson({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Message too large" } }));
      return;
    }
    const taken = takeStdioMessages(buffer);
    buffer = taken.rest;
    for (const message of taken.messages) {
      const deps: McpDeps = {
        check: {
          store,
          target: undefined,
          amountUsd: undefined,
          category: undefined,
          apiKey: null,
          bundleSecretHeader: null,
          bundleClientHeader: null,
          ip: "stdio",
          payTo: proc.env.PAY_TO,
          bundleSecret: proc.env.BUNDLE_PROXY_SECRET,
          fetchFn: fetch,
          now: new Date(),
          resourceUrl: "stdio://paycheck/check",
          paymentSignatureHeader: null,
          xPaymentHeader: null,
        },
      };
      chain = chain
        .then(async () => {
          const result = await dispatchMcp(message, deps);
          if (result.type === "none") return;
          proc.stdout.write(encodeNdjson(stdioBody(message, result)));
        })
        .catch((error: unknown) => {
          proc.stderr.write(`${error instanceof Error ? error.message : "stdio error"}\n`);
        });
    }
  });
  proc.stdin.on("end", () => {
    proc.stderr.write("PayCheck MCP stdio closed\n");
  });
}

const entry = (globalThis as { process?: { argv?: string[] } }).process?.argv?.[1] ?? "";
const isDirect = entry.endsWith(`${"/"}stdio.js`) || entry.endsWith(`${"/"}stdio.ts`) || entry.endsWith("\\stdio.js");

if (isDirect) void main();

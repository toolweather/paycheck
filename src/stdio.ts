import { MemoryStore } from "./store";
import { dispatchMcp, type McpDeps } from "./mcp";

interface StdioProcess {
  stdin: {
    on(event: "data", cb: (chunk: Uint8Array | string) => void): void;
    on(event: "end", cb: () => void): void;
    resume(): void;
  };
  stdout: { write(chunk: Uint8Array): boolean };
  stderr: { write(chunk: string): boolean };
  env: Record<string, string | undefined>;
}

function getProcess(): StdioProcess {
  return (globalThis as unknown as { process: StdioProcess }).process;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function encodeFrame(message: unknown): Uint8Array {
  const json = encoder.encode(JSON.stringify(message));
  const header = encoder.encode(`Content-Length: ${json.byteLength}\r\n\r\n`);
  const out = new Uint8Array(header.byteLength + json.byteLength);
  out.set(header, 0);
  out.set(json, header.byteLength);
  return out;
}

export function pushFrames(buffer: Uint8Array, chunk: Uint8Array): { messages: unknown[]; rest: Uint8Array } {
  const combined = new Uint8Array(buffer.length + chunk.length);
  combined.set(buffer, 0);
  combined.set(chunk, buffer.length);
  const messages: unknown[] = [];
  let rest = combined;
  while (rest.length > 0) {
    const text = decoder.decode(rest);
    const split = text.indexOf("\r\n\r\n");
    if (split < 0) break;
    const header = text.slice(0, split);
    const match = /Content-Length:\s*(\d+)/i.exec(header);
    if (!match) break;
    const length = Number(match[1]);
    const headerBytes = encoder.encode(header + "\r\n\r\n").length;
    if (rest.length < headerBytes + length) break;
    const body = rest.slice(headerBytes, headerBytes + length);
    messages.push(JSON.parse(decoder.decode(body)));
    rest = rest.slice(headerBytes + length);
  }
  return { messages, rest };
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
  proc.stderr.write("PayCheck MCP stdio listening\n");
  let buffer: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  proc.stdin.resume();
  proc.stdin.on("data", (chunk) => {
    const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
    const pushed = pushFrames(buffer, bytes);
    buffer = pushed.rest;
    for (const message of pushed.messages) {
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
      void dispatchMcp(message, deps)
        .then((result) => {
          if (result.type === "none") return;
          proc.stdout.write(encodeFrame(stdioBody(message, result)));
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

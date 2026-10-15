import { MemoryStore } from "./store";
import { dispatchMcp, type McpDeps } from "./mcp";

const MAX_BUFFER = 1_048_576;

export interface StdioProcess {
  stdin: {
    on(event: "data", cb: (chunk: Uint8Array | string) => void): void;
    on(event: "end", cb: () => void): void;
    resume(): void;
    setEncoding(encoding: "utf8"): void;
  };
  stdout: { write(chunk: string): boolean };
  stderr: { write(chunk: string): boolean };
  env: Record<string, string | undefined>;
  exit(code: number): void;
}

function getProcess(): StdioProcess {
  return (globalThis as unknown as { process: StdioProcess }).process;
}

const decoder = new TextDecoder();

/**
 * Glama's mcp-proxy speaks newline-delimited JSON-RPC, same as SpendGate.
 * Stdin also accepts LSP Content-Length frames. Responses are one JSON
 * object per line on stdout. Diagnostic banners stay on stderr.
 */
export function encodeLine(message: unknown): string {
  return `${JSON.stringify(message)}\n`;
}

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
      // A wrapper may write a non-JSON banner. Skip it.
    }
  }
  return { messages, rest };
}

function sliceUtf8(value: string, byteLength: number): { head: string; tail: string } | null {
  if (!Number.isFinite(byteLength) || byteLength < 0) return { head: "", tail: value };
  const bytes = new TextEncoder().encode(value);
  if (bytes.length < byteLength) return null;
  const utf8 = new TextDecoder();
  return {
    head: utf8.decode(bytes.slice(0, byteLength)),
    tail: utf8.decode(bytes.slice(byteLength)),
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

function depsFor(proc: StdioProcess, store: MemoryStore): McpDeps {
  return {
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
}

export function startStdioServer(proc: StdioProcess = getProcess()): void {
  const store = new MemoryStore();
  proc.stderr.write("PayCheck MCP stdio listening\n");
  let buffer = "";
  let chain: Promise<void> = Promise.resolve();

  const write = (body: unknown) => {
    proc.stdout.write(encodeLine(body));
  };

  const enqueue = (message: unknown) => {
    chain = chain
      .then(async () => {
        const result = await dispatchMcp(message, depsFor(proc, store));
        if (result.type === "none") return;
        write(stdioBody(message, result));
      })
      .catch((error: unknown) => {
        proc.stderr.write(`${error instanceof Error ? error.message : "stdio error"}\n`);
      });
  };

  proc.stdin.setEncoding("utf8");
  proc.stdin.resume();
  proc.stdin.on("data", (chunk) => {
    buffer += typeof chunk === "string" ? chunk : decoder.decode(chunk);
    if (buffer.length > MAX_BUFFER) {
      buffer = "";
      write({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Message too large" } });
      return;
    }
    const taken = takeStdioMessages(buffer);
    buffer = taken.rest;
    for (const message of taken.messages) enqueue(message);
  });
  proc.stdin.on("end", () => {
    void chain.then(() => {
      proc.stderr.write("PayCheck MCP stdio closed\n");
      proc.exit(0);
    });
  });
}

function runningAsCli(): boolean {
  const entry = String((globalThis as { process?: { argv?: string[] } }).process?.argv?.[1] ?? "").replace(/\\/g, "/");
  return /(?:^|\/)stdio\.(?:js|ts)$/.test(entry);
}

if (runningAsCli()) startStdioServer();

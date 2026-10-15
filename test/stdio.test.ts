import { describe, expect, it } from "vitest";
import { encodeLine, startStdioServer, takeStdioMessages, type StdioProcess } from "../src/stdio";

describe("stdio framing", () => {
  it("round-trips a JSON-RPC message as newline-delimited JSON", () => {
    const message = { jsonrpc: "2.0", id: 1, method: "tools/list" };
    const line = encodeLine(message);
    expect(line.endsWith("\n")).toBe(true);
    expect(line.includes("Content-Length")).toBe(false);
    const parsed = takeStdioMessages(line);
    expect(parsed.messages).toEqual([message]);
    expect(parsed.rest).toBe("");
  });

  it("reads newline JSON and Content-Length frames", () => {
    const ping = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });
    const framed = `Content-Length: ${new TextEncoder().encode(ping).length}\r\n\r\n${ping}`;
    const mixed = `not json\n${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n${framed}`;
    const taken = takeStdioMessages(mixed);
    expect(taken.rest).toBe("");
    expect(taken.messages).toEqual([
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 1, method: "ping" },
    ]);
  });

  it("waits for a partial NDJSON line and a partial Content-Length body", () => {
    const partialLine = takeStdioMessages('{"jsonrpc":"2.0","id":3,"method":"pi');
    expect(partialLine.messages).toEqual([]);
    const finishedLine = takeStdioMessages(`${partialLine.rest}ng"}\n`);
    expect(finishedLine.messages).toEqual([{ jsonrpc: "2.0", id: 3, method: "ping" }]);

    const ping = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" });
    const framed = `Content-Length: ${new TextEncoder().encode(ping).length}\r\n\r\n${ping}`;
    const partialFrame = takeStdioMessages(framed.slice(0, 20));
    expect(partialFrame.messages).toEqual([]);
    const finishedFrame = takeStdioMessages(partialFrame.rest + framed.slice(20));
    expect(finishedFrame.messages).toEqual([{ jsonrpc: "2.0", id: 2, method: "ping" }]);
    expect(finishedFrame.rest).toBe("");
  });

  it("answers initialize and tools/list over mixed NDJSON and Content-Length input", async () => {
    const io = fakeStdio();
    startStdioServer(io.proc);
    const toolsList = { jsonrpc: "2.0", id: 2, method: "tools/list" };
    const framedList = `Content-Length: ${new TextEncoder().encode(JSON.stringify(toolsList)).length}\r\n\r\n${JSON.stringify(toolsList)}`;
    io.push(
      encodeLine({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "glama", version: "0" } },
      }),
    );
    io.push(encodeLine({ jsonrpc: "2.0", method: "notifications/initialized" }));
    io.push(framedList);
    io.end();
    await io.exited;

    const lines = io.stdout.map((line) => JSON.parse(line) as { id?: number; result?: { tools?: { name: string }[] } });
    expect(io.stdout.every((line) => line.endsWith("\n") && !line.includes("Content-Length"))).toBe(true);
    expect(io.stderr.join("")).toContain("PayCheck MCP stdio listening");
    expect(io.stderr.join("")).not.toContain("Content-Length");
    expect(lines.map((line) => line.id)).toEqual([1, 2]);
    expect(lines[1]?.result?.tools?.map((tool) => tool.name)).toEqual(["check_merchant", "get_quota", "get_api_key"]);
  });
});

function fakeStdio(): {
  proc: StdioProcess;
  push(chunk: string): void;
  end(): void;
  stdout: string[];
  stderr: string[];
  exited: Promise<void>;
} {
  const dataHandlers: Array<(chunk: Uint8Array | string) => void> = [];
  const endHandlers: Array<() => void> = [];
  const stdout: string[] = [];
  const stderr: string[] = [];
  let resolveExit: () => void = () => {};
  const exited = new Promise<void>((resolve) => {
    resolveExit = resolve;
  });
  const proc: StdioProcess = {
    stdin: {
      on(event, cb) {
        if (event === "data") dataHandlers.push(cb as (chunk: Uint8Array | string) => void);
        else endHandlers.push(cb);
      },
      resume() {},
      setEncoding() {},
    },
    stdout: {
      write(chunk) {
        stdout.push(chunk);
        return true;
      },
    },
    stderr: {
      write(chunk) {
        stderr.push(chunk);
        return true;
      },
    },
    env: {},
    exit() {
      resolveExit();
    },
  };
  return {
    proc,
    push(chunk) {
      for (const handler of dataHandlers) handler(chunk);
    },
    end() {
      for (const handler of endHandlers) handler();
    },
    stdout,
    stderr,
    exited,
  };
}
